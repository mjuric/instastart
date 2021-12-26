# FIXME:
#  * Do we need to block/unblock signals in signal handlers?
#  * Sane default for systems w/o XDG_RUNTIME_DIR (macOS)
#  * Proper logging
#  * Tests
#
import socket, os, sys, pickle, tty, fcntl, termios, select, signal, inspect, hashlib
from contextlib import contextmanager

# Helpful constants
STDIN  = 0
STDOUT = 1
STDERR = 2

# These get set in their respective processes. They really shouldn't be
# touched by user code (an internal implementation detail)
_worker = None
_server = None

def _debug_write_pid(name):
    # debugging/profiling aid: write out our PID into a file in
    # $INSTA_PID_DIR directory
    import instastart
    instastart._name = name
    if "INSTA_PID_DIR" in os.environ:
        with open(os.path.join(os.environ["INSTA_PID_DIR"], f"{name}.pid"), "w") as fp:
            print(os.getpid(), file=fp)

def _construct_socket_name():
    # construct a UNIX socket path reasonably unique to this program
    # invocation. This is where the server will listen for client
    # connections.

    # the name of the file at the top of the call stack (should be our __main__)
    pth = inspect.stack()[-1].filename
    py = sys.executable
    env = "PYTHONPATH=" + os.environ.get("PYTHONPATH",'')

    # compute the md5 of the elements that affect the execution environment,
    # to get something unique.
    state=f"{pth}-{py}-{env}"
    md5 = hashlib.md5(state.encode('utf-8')).hexdigest()

    # take the __main__'s filename, w/o the extension
    fn = pth.split('/')[-1].split('.')[0]

    # FIXME: handle the case where XDG_RUNTIME_DIR isn't defined
    return os.path.join(os.environ['XDG_RUNTIME_DIR'], f"{fn}.{md5}.socket")

def _setproctitle(title):
    # change our process' title (as viewed in utilities like ps or top)
    try:
        import setproctitle
        setproctitle.setproctitle(title)
    except ImportError: #pragma: no cover
        pass

class TimestampedOutput:
    out = None
    name = ""

    def __init__(self, out, name):
        self.out = out
        self.name = name
        self._at_line_start = True

    def set_name(self, name):
        self.name = name

    def write(self, text):
        import datetime
        # add timestamps to beginnings of lines
#        ts = f'{datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %Z")} '
        ts = f'{datetime.datetime.now().strftime("%b %d %H:%M:%S.%f")} '
        if self.name:
            ts = ts + f'{self.name}[{os.getpid()}] '

        if self._at_line_start:
            text = ts + text
        lineend = text.endswith('\n')
        text = text.replace('\n', "\n" + ts)
        if lineend:
            text = text[:-len(ts)]
        self._at_line_start = lineend

        self.out.write(text)

    def __getattr__(self, name):
        return getattr(self. out, name)

def debug(*argv, **kwargs):
    # our own fast-ish logging routines (importing logging seems to add
    # ~15msec to runtime, tested on macOS/MBA)
    kwargs['file'] = sys.stderr
    return print(*argv, **kwargs)

#############################################################################
#   Pty management 
#############################################################################

def _getwinsize(fd):
    # Return the terminal window size struct for file descriptor fd
    # the contents are a struct w. "HHHH" signature, mapping to
    # (rows, cols, ws_xpixel, ws_ypixel), but we don't bother
    # to unpack as this will be bed back to _setwinsize.
    return fcntl.ioctl(fd, termios.TIOCGWINSZ ,"\000"*8)

def _setwinsize(fd, winsz):
    # Set window size of tty with file descriptor fd
    # winsz is a struct with "HHHH" signature, as returned by _getwinsize
    return fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)

#############################################################################
#   Low-level socket communication
#############################################################################

def _read_object(fp):
    """ Read a pickled object from file fp """
    return pickle.load(fp)

def _write_object(fp, obj):
    """ Write an object to file fp, using pickle """
    return pickle.dump(obj, fp, -1)

def _writen(fd, data):
    """Write all the data to a descriptor."""
    while data:
        n = os.write(fd, data)
        data = data[n:]

def _readn(fd, n):
    """Read n bytes from a file descriptor."""
    s = os.read(fd, n)
    while len(s) < n:
        s += os.read(fd, len(s) - n)
    return s

#############################################################################
#   Server
#############################################################################

class Server:
    _readypipe = None   # the pipe that .start() uses to signal the server is ready
    socket_path = None  # path to the UNIX socket we listen on

    def __init__(self, socket_path, log_path) -> None:
        self.socket_path = socket_path
        self.log_path = log_path

    def fork_and_wait_for_server(self):
        # For this process and wait until the server is ready to accept
        # connections, This is called by _connect_or_serve() to instantiate
        # the server (as a child process) before the parent continues to act
        # as a client.

        _r, _w = os.pipe()  # this is how the server will tell us it's ready
        pid = os.fork()
        if pid == 0:
            # child (== server)
            _debug_write_pid("server")

            os.close(_r)
            name = sys.argv[0].split('/')[-1]
            _setproctitle(f"[instastart: {name}]")

            # start a new session, to protect the child from SIGHUPs, etc. we
            # don't double-fork as the daemon never really does anything
            # funny with the tty.
            os.setsid()

            # redirect the server output to a log file (/dev/null, by
            # default). Note that the sentry will inherit these.
            fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            os.dup2(fd, 1)
            os.dup2(fd, 2)
            os.close(fd)
            # We don't close stdin, but redirect it to /dev/null. If we
            # closed it, a subsequent os.open() or os.pipe() may allocate
            # fd=0 to some random file/pipe, thus wreaking havoc. (learned
            # the hard way!)
            fd = os.open(os.devnull, os.O_RDONLY)
            os.dup2(fd, 0)
            os.close(fd)
            # customize stdout/stderr to prepend timestamps
            sys.stdout = TimestampedOutput(sys.stdout, "server")
            sys.stderr = TimestampedOutput(sys.stderr, "server")

            # now fall through until we hit start() somewhere in __main__
            self._readypipe = _w
        else:
            # parent -- we'll wait for the server to become available, then
            # connect to it.
            os.close(_w)
            while True:
                msg = os.read(_r, 1)
                # debug(msg)
                if len(msg):
                    break
            os.close(_r)
            # print(f"Signal received!")
        return pid

    def _serve(self, timeout):
        # this is invoked by start(), at a point where user's one-time
        # (heavy) initialization has completed. We'll pause execution,
        # daemonize, and start waiting for incoming connections to fork off
        # children (workers) to continue doing the work.

        # safely set up a socket on which to listen for connections.
        # avoid the race condition where two clients are launched
        # at the same time, and try to create the same socket.
        pid = os.getpid()
        spath = f"{self.socket_path}.{pid}"
        if os.path.exists(spath):
            os.unlink(spath)

        # debug(f"Opening socket at {socket_path=} with {timeout=}...", end='')
        child_pid = 0
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                os.fchmod(sock.fileno(), 0o700)		# security: only allow the user to do anything w. the socket
                sock.bind(spath)
                sock.listen()
                os.rename(spath, self.socket_path)
                # debug(' done.')

                # add a SIGCHLD handler so we reap the sentries as soon as
                # they exit, avoiding accumulation of zombies. We don't
                # double fork (reparenting children to init) for performance:
                # for a large process (100GB+ of preloaded data in RAM) the
                # fork itself takes awhile.
                def _reap_children(signum, frame):
                    # debug("Reaping sentry")
                    pid = -1
                    while pid != 0:
                        try:
                            pid, exitstatus = os.waitpid(-1, os.WNOHANG)
                        except ChildProcessError:
                            pid = exitstatus = 0
                        # debug(f"waitpid returned {pid=} {exitstatus=}")

                signal.signal(signal.SIGCHLD, _reap_children)

                if self._readypipe is not None:
                    # debug('signaling on readypipe')
                    # signal to the reader the server is ready to accept connections
                    os.write(self._readypipe, b"x")
                    os.close(self._readypipe)
                    self._readypipe = None
                    # debug('done')

                # Await for client connections (or server commands)
                while True:
                    try:
                        conn, _ = sock.accept()
                    except socket.timeout:
                        debug("Server timeout. Exiting")
                        sys.exit(0)
                    debug(f"Connection accepted")

                    # make our life easier & create a file-like object
                    fp = conn.makefile(mode='rwb', buffering=0)

                    cmd = _read_object(fp)
                    debug(f"{cmd=}")
                    if cmd == "stop":
                        # exit the listen loop
                        debug("Server received a command to exit. Exiting")
                        sys.exit(0)
                    elif cmd == "run":
                        # Fork a child process to do the work.
                        child_pid = os.fork()
                        if child_pid == 0:
                            _debug_write_pid("sentry")
                            sys.stdout.set_name("sentry")
                            sys.stderr.set_name("sentry")
                            # Child process -- this is where the work gets done
                            sock.close()
                            return Worker(conn, fp)
                        else:
                            conn.close()
        finally:
            if child_pid != 0:
                # server process exiting. clean up the socket file(s).
                if os.path.exists(spath):
                    os.unlink(spath)
                if os.path.exists(self.socket_path):
                    os.unlink(self.socket_path)

        # This function will continue _only_ in the spawned child process,
        # and execute the main program.
        assert False, "This function should only return in a worker process!" # pragma: no cover

    def start(self, timeout):
        # run the server. Returns only in the forked worker process.
        # print("Spinning up the server... {_w=}")
        return self._serve(timeout=timeout)

#############################################################################
#
#   Worker
#
#############################################################################

class Worker:
    _is_worker = False      # set to True in the worker process (false in sentry)

    def __init__(self, conn, fp):
        try:
            self._spawn(conn, fp)
        finally:
            # make sure the sentry never returns, even if
            # we've received an exception or something similar
            if not self._is_worker:
                sys.exit(0)
                #raise Exception("Making some noise")

    def done(self, exitcode=0):
        # signal the client we've finished and that it can safely pretend
        # this process has exited.
        assert self._is_worker, "This function can only be called from within the worker process"

        # Flush the output back to the client and redirect all
        # open STD* file descriptors to /dev/null.
        for stream in [ sys.stdout, sys.stderr ]:
            if not stream.closed:
                stream.flush()
                fd = os.open(os.devnull, os.O_WRONLY)
                os.dup2(fd, stream.fileno())
                os.close(fd)

        if not sys.stdin.closed:
            fd = os.open(os.devnull, os.O_RDONLY)
            os.dup2(fd, 0)
            os.close(fd)

        # FIXME: HACK: This is a hack, introducing a race condition w. the
        # sentry process (example: if the client is sent a SIGTSTP just as
        # we're writing the "exited" message, the two may overlapp as the
        # writes to the socket aren't guaranteed to be atomic). Possible
        # solutions: a) only the sentry should ever be talking to _client_fp; we
        # should have a pipe back to the sentry instead, message the sentry
        # and have the sentry message the client, b) switch the socket to use
        # datagrams.
        with os.fdopen(self.wrk_w, "wb", buffering=0) as fp:
            _write_object(fp, ("exited", exitcode))
        # note: as a side-effect, the above also closes the wrk_w fd

    def _spawn(self, conn, fp):
        # Fork the sentry and worker processes to execute the payload.
        #
        # The sentry is forked first, which then forks the worker. The sentry
        # plays the role of the shell -- controls the tty session, monitors
        # worker signals and communicates the exit status to the client.
        # See docs/implementation.md for details.
        #
        # Returns only in the worker process.
        os.setsid()

        r, w = os.pipe()            # block the worker while sentry does the setup
        wrk_r, wrk_w = os.pipe()    # worker -> sentry messaging (for done())

        # get our client's id string; used by _setproctitle to make it
        # easy to identify which processes are related to a given client
        rs = RunSpec.receive(conn, fp)

        # make the pty our controlling terminal, if there is one
        if rs.master is not None:
            fcntl.ioctl(rs.slave, termios.TIOCSCTTY)

        # fork the worker process
        pid = os.fork()
        if pid == 0:
            _debug_write_pid("worker")
            sys.stdout.set_name("worker")
            sys.stderr.set_name("worker")
            self._is_worker = True

            conn.close()
            os.close(w)
            os.close(wrk_r)
            if rs.master is not None:
                os.close(rs.master)
                os.close(rs.slave)
            self.wrk_w = wrk_w      # so done() can use it to message the sentry

            # set up and run
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            rs.apply()
            _setproctitle(f"[{' '.join(sys.argv)} :: worker/{rs.client_pid}]")

            # wait until the sentry sets us up before continuing
            if os.read(r, 1) != b"x":
                raise Exception("[worker] sentry closed the pipe w/o starting us.") # pragma: no cover
            os.close(r)

            # return to __main__ to run the payload
            return
        else:
            os.close(rs.fds[0])
            os.close(rs.fds[1])
            os.close(rs.fds[2])
            os.close(r)
            os.close(wrk_w)

            # change name to denote we're the sentry
            _setproctitle(f"[{' '.join(sys.argv)} :: sentry/{rs.client_pid}]")

            # receive SIGCHLD signals via a file descriptor. this way we can
            # select() both on conn and child messages in _sentry_loop()
            sig_r, sig_w = os.pipe()
            os.set_blocking(sig_w, False)
            signal.set_wakeup_fd(sig_w, warn_on_full_buffer=False)
            signal.signal(signal.SIGCHLD, lambda signum, frame: None)  # have to set a dummy handler, otherwise sig_w isn't woken up

            os.setpgid(pid, pid)        # start a new process group for the child
            if rs.master is not None:
                os.tcsetpgrp(rs.slave, pid)                # make the child's the foreground process group (so it receives tty input+signals)
                os.close(rs.slave)

            _write_object(fp, pid)      # send the child's PID back to the client

            os.write(w, b"x")           # unblock the child, close the pipe
            os.close(w)

            try:
                self._sentry_loop(fp, sig_r, wrk_r, pid)
            finally:
                conn.close()
                os.close(sig_r)
                os.close(sig_w)
                # FIXME: this should really be os._exit(), otherwise
                # except/finally branches may be triggered in the user's
                # code. Keeping sys.exit() for now as coverage.py needs to
                # run atexit handlers.
                sys.exit(0)

        assert False, "We should never exit this function" #pragma: no cover

    def _sentry_loop(self, client_fp, sig_r, wrk_r, pid):
        # We monitor for three things here:
        # * client_fp, the socket to the client. If it's down, the
        #   client has exited and we make sure the worker exits as well.
        # * wrk_r, the pipe from the worker. If the worker sends us an
        #   "exited" message, we pass it to the client then make sure
        #   the worker exits.
        # * sig_r, the SIGCHLD messages. We pass these on to the client.
        #
        client_fd = client_fp.fileno() # client control conection
        fds = [ client_fd, sig_r, wrk_r ]
        done = False # did the worker "exit" via a call to done()
        while fds:
            rfds, _, _ = foo = select.select(fds, [], [])

            if client_fd in rfds:
                # The client has died. If the worker isn't already marked as
                # done, kill it with a SIGKILL.
                try:
                    data = os.read(client_fd, 1024*1024)
                except OSError:
                    data = b''
                assert data == b''

                fds.remove(client_fd)

                if not done:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)

            if wrk_r in rfds:
                # worker process exit, or a user-initiated exit (via done()).
                try:
                    with os.fdopen(os.dup(wrk_r), "rb", buffering=0) as wrk_fp:
                        (cmd, exitstatus) = _read_object(wrk_fp)
                except EOFError:
                    cmd = "closed"

                if cmd == "closed":
                    # the worker process has exited & closed the pipe
                    fds.remove(wrk_r)
                elif cmd == "exited":
                    # the worker process has called done(). Message the
                    # client but remain looping here until the worker
                    # actually terminates.
                    debug(f"SENTRY: DONE reading {cmd=} {exitstatus=}")
                    assert cmd == "exited"

                    _write_object(client_fp, ("exited", exitstatus))
                    done = True
                else: #pragma: no cover
                    assert False, f"Unknown command {cmd=}"

            if sig_r in rfds:
                # empty the buffer (we only use this for signaling on the child)
                os.read(sig_r, 1024*1024)

                # wait for child status
                _, status = os.waitpid(pid, os.WUNTRACED | os.WCONTINUED)
                if done:
                    break

                if os.WIFSTOPPED(status):
                    # let the controller know we've stopped
                    _write_object(client_fp, ("stopped", 0))
                elif os.WIFEXITED(status):
                    # we've exited. return the status back to the controller
                    _write_object(client_fp, ("exited", os.WEXITSTATUS(status)))
                    break
                elif os.WIFSIGNALED(status):
                    # we've exited. return the status back to the controller
                    _write_object(client_fp, ("signaled", os.WTERMSIG(status)))
                    break
                elif os.WIFCONTINUED(status):
                    # we've been continued after being stopped
                    # TODO: should we make sure the remote_pid is signaled to CONT?
                    pass
                else:
                    assert False, f"weird {status=}" #pragma: no cover

#############################################################################
#
#   Client
#
#############################################################################

class Terminal:
    master = None       # pty master
    input = None        # set to 0 if STDIN is connected to a tty
    tty = None          # the client's controlling tty
    termios = None      # the client's tty termios attributes

    @staticmethod
    def construct():
        self = Terminal()
        slave = None

        # see if we're connected to a tty
        fd = next((fd for fd in [STDIN, STDOUT, STDERR] if os.isatty(fd)), None)
        if fd == 0:
            self.input = 0

        if fd is not None:
            self.tty = fd

            # open and set up a pty
            self.master, slave = os.openpty()

            # copy tty properties & window size
            self.termios = termios.tcgetattr(self.tty)
            termios.tcsetattr(self.master, termios.TCSAFLUSH, self.termios)
            _setwinsize(self.master, _getwinsize(self.tty))

            # set up the SIGWINCH handler which copies terminal window changes
            # to the pty
            def _sigwinch_handler(signum, frame):
                _setwinsize(self.master, _getwinsize(self.tty))
            signal.signal(signal.SIGWINCH, _sigwinch_handler)

        return self, slave

    def __del__(self):
        if self.master is not None:
            os.close(self.master)

    def __bool__(self):
        return self.master is not None

    def setraw(self):
        if self.input is not None:
            tty.setraw(self.input)

    def reset(self):
        if self.input is not None:
            termios.tcsetattr(self.input, tty.TCSAFLUSH, self.termios)

class RunSpec:
    # specification of a worker run. Things like argv, cwd, environ, and file
    # descriptors.
    def __init__(self):
        pass

    @staticmethod
    def construct(master, slave):
        # constructs the run specification from the current process. This is
        # usually how this class is meant to be constructed, from the client.
        self = RunSpec()

        # the process environment
        self.argv = sys.argv
        self.cwd = os.getcwd()
        self.client_pid = os.getpid()
        self.environ = os.environ.copy()

        # Pass STDIN/OUT/ERR directly if not a tty, or replace them by the pty
        # slave if they are.
        self.fds = [ fd if not os.isatty(fd) else slave for fd in [STDIN, STDOUT, STDERR] ]
        self.master = master
        self.slave = slave

        return self

    def write(self, conn, fp):
        _write_object(fp, self)
        fds = self.fds if self.master is None else self.fds + [ self.master, self.slave ]
        socket.send_fds(conn, [ b'm' ], fds)

    @staticmethod
    def receive(conn, fp):
        # called by the sentry to set up the worker process & connection
        self = _read_object(fp)
        _, self.fds, _, _ = socket.recv_fds(conn, 10, maxfds=5)
        if self.master is not None:
            self.master = self.fds[3]
            self.slave = self.fds[4]
            self.fds = self.fds[:3]
        return self

    def apply(self):
        # apply the run specification to the current process
        sys.argv = self.argv
        os.chdir(self.cwd)
        os.environ.clear()
        os.environ.update(self.environ)

        # duplicate self.fds to STDIN/OUT/ERR
        for src, dst in zip(self.fds, [STDIN, STDOUT, STDERR]):
            os.dup2(src, dst)
            os.close(src)

        return self

def _run_coverage_py_atexit(): #pragma: no cover
    # a hack to find coverage.py atexit function, and call
    # it explicitly before a program terminates.
    class Capture:
        def __init__(self):
            self.captured = []
        def __eq__(self, other):
            self.captured.append(other)
            return False

    # fantastic hack from https://stackoverflow.com/a/63029332
    c = Capture()
    import atexit
    atexit.unregister(c)
    for fun in c.captured:
        print(fun)
        print(fun.__module__)

    for fun in c.captured:
        if fun.__module__.startswith("coverage"):
            _atexit = fun
            break
    else:
        return

    # call coverage.py's atexit
    _atexit()

    return None

class Client:
    socket_path = None   # path to the UNIX socket we connect to

    def __init__(self, socket_path) -> None:
        self.socket_path = socket_path

    def _communicate_loop(self, master_fd, stdin_fd, control_fp, termios_attr, remote_pid):
        """Copy and control loop
        Copies
                pty master -> standard output   (master_read)
                standard input -> pty master    (stdin_read)
        and also listens for control messages from the child
        on control_fd/fp.
        """
        control_fd = control_fp.fileno()
        fds = [ control_fd ]
        if master_fd is not None: fds.append(master_fd)
        if stdin_fd is not None: fds.append(stdin_fd)
        
        # debug(f"{fds=} {master_fd=} {tty_fd=}")
        while fds:
            rfds, _wfds, _xfds = select.select(fds, [], [])
            # import time; debug(f"{rfds=} {time.time()=}")

            # received output
            if master_fd in rfds:
                # Some OSes signal EOF by returning an empty byte string,
                # some (incl. Linux) throw OSErrors. EOF can happen if
                # the client closes all pty file descriptors.
                try:
                    data = os.read(master_fd, 1024*1024)
                except OSError:
                    data = b""
#                debug(f"CLIENT: read output {data=}")
                if not data:  # Reached EOF.
                    # debug("CLIENT: zero read on master_fd")
                    fds.remove(master_fd)
                else:
                    os.write(stdin_fd, data)

            # received input
            if stdin_fd in rfds:
                data = os.read(stdin_fd, 1024*1024)
#                debug(f"CLIENT: read input {data=}")
                if not data:
                    fds.remove(stdin_fd)
                else:
                    _writen(master_fd, data)

            # received a control message
            if control_fd in rfds:
                # a control message from the worker. they've
                # paused, exited, etc.
                event, data = _read_object(control_fp)
                # debug(f"CLIENT: received {event=}")
                if event == "stopped":
                    if stdin_fd is not None:
                        # it's possible we've been backrounded by the time we got here,
                        # so ignore SIGTTOU while mode-setting. This can happen if someone sent
                        # us (the client) an explicit SIGTSTP.
                        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                        termios.tcsetattr(stdin_fd, tty.TCSAFLUSH, termios_attr)	# restore tty
                        signal.signal(signal.SIGTTOU, signal.SIG_DFL)
                        # debug("CLIENT: Putting us to sleep")
                        # os.kill(os.getpid(), signal.SIGSTOP)			# put ourselves to sleep
                    os.kill(0, signal.SIGSTOP)			# put ourselves to sleep

                    # this is where we sleep....
                    # ... and continue when we're awoken by SIGCONT (e.g., 'fg' in the shell)

                    if stdin_fd is not None:
     	                # debug("CLIENT: Awake again")
                        tty.setraw(stdin_fd)					# turn the STDIN raw again

                        # set terminal size (in case it changed while we slept)
                        s = fcntl.ioctl(stdin_fd, termios.TIOCGWINSZ, '\0'*8)
                        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, s)

                    # FIXME: we should message the sentry to do this (pid race condition!)
                    os.killpg(os.getpgid(remote_pid), signal.SIGCONT)	# wake up the worker process
                elif event == "exited":
                    # FIXME: there are two subtle problems here, which are
                    # (hopefully) academic in real-world scenarios.
                    # 1) if the worker writes out more data its stdout/err
                    #    than we can read in a single os.read(), and then
                    #    exits with done(), we may exit here before we've
                    #    copied everything over from master_fd. We defend
                    #    agains this by using a sizable buffer (~1M) on
                    #    os.read (see above), which is hopefully larger than
                    #    any kernel-level buffer. We can't just wait and
                    #    continue to read until stdout/err are closed, as
                    #    these may be kept open by any children the worker
                    #    has spawned (e.g., imagine a poorly written daemon
                    #    that doesn't close the std* streams).
                    # 2) if the worker's code spawns a child, which inherits
                    #    the stdout/err file descriptors, then exits w. the
                    #    child running & writing to stdout/err, those writes
                    #    will stop being copied over to the client's tty.
                    #    This sort of thing is usually a bug w. the user's
                    #    code, but the difference in running w. vs. w/o
                    #    instastart is displeasing.
                    #
                    # A possible fix may be to fork a background process at
                    # here before exiting, which would continue this loop
                    # until both master_fd and/or tty_fd are closed.

                    return data # data is the exitstatus
                elif event == "signaled":
                    signum = data  # data is the signal that terminated the worker
                    if stdin_fd is not None:
                        termios.tcsetattr(stdin_fd, tty.TCSAFLUSH, termios_attr)	# restore tty back from the raw mode
                    # then restore its default handler and commit a copycat suicide
                    signal.signal(signum, signal.SIG_DFL)
                    _run_coverage_py_atexit()
                    os.kill(os.getpid(), signum) #pragma: no cover
                else: #pragma: no cover
                    assert 0, "unknown control event {event}"

    def _communicate(self, fp, term, remote_pid):
        # raw mode control
        try:
            # switch our input to raw mode, so everything is passed on to the
            # worker
            term.setraw()

            # Now enter the communication forwarding loop
            return self._communicate_loop(term.master, term.input, fp, term.termios, remote_pid)
        finally:
            # restore our console
            term.reset()

    def _setup_signal_passthrough(self, remote_pid):
        def _handle_ISIG(signum, frame):
            # just pass on the signal to the remote process
            #
            # if the remote process handles the signal by suspending
            # or terminating itself, we'll be told about it via
            # the control socket (and can do the same).
            #
            # FIXME: this signaling should be done through the control socket (pid race contitions!)
            # debug(f"_handle_ISIG: {signum=}")
            os.killpg(os.getpgid(remote_pid), signum)

        # forward all signals that make sense to forward
        fwd_signals = set(signal.Signals) - {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD, signal.SIGWINCH}
        for signum in fwd_signals:
            signal.signal(signum, _handle_ISIG)

    def connect(self):
        # try connecting to the UNIX socket. If successful, pass it our command
        # line (argv).  If connection is not successful, start the server.

        # try connecting
        try:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.connect(self.socket_path)
        except (FileNotFoundError, ConnectionRefusedError):
            # connection failed; return None
            return None

        fp = server.makefile(mode='rwb', buffering=0)

        cmd = os.environ.get("INSTA_CMD", None)
        if cmd is not None:
            _write_object(fp, cmd)
            sys.exit(0)

        # this is a command run
        _write_object(fp, "run")

        # the pty and runspec
        term, slave = Terminal.construct()
        rs = RunSpec.construct(term.master, slave)
        rs.write(server, fp)
        if slave is not None:
            os.close(slave)

        # get the worker PID
        remote_pid = _read_object(fp)

        # pass any signals we receive back to the worker
        self._setup_signal_passthrough(remote_pid)

        # communicate through the pipe until the worker or client end
        return self._communicate(fp, term, remote_pid)

#############################################################################
#
#   Public API
#
#############################################################################

def start():
    if not _disabled:
        timeout = float(os.environ.get("INSTA_TIMEOUT", "10"))

        global _worker
        _worker = _server.start(timeout=timeout)

        return _worker

def done(exitcode=0):
    # signal the client we've finished and that it can safely pretend
    # this process has exited.
    #
    # May only be called from the worker (i.e., after start() has been called).
    if not _disabled:
        _worker.done(exitcode)

@contextmanager
def serve(autodone=True):
    # Convenience function to wrap a block of code in a context manager
    start()
    
    # return to execute the user's code
    yield

    # This is intentionally vulnerable to exceptions; if an exception occurs
    # in the user's code, we don't want to terminate the connection to the
    # client early. Instead, we want to let any output the worker will throw
    # out (tracebacks, etc.) be streamed back to the client.
    if autodone:
        done()

def _connect_or_serve():
    _debug_write_pid("client")

    # try connecting on our socket; if fail, spawn a new server
    socket_path = _construct_socket_name()
    client = Client(socket_path)

    # try connecting
    ret = client.connect()
    if ret is not None:
        sys.exit(ret)

    # fork the server. This will return pid or 0, depending on if it's
    # child or parent
    server = Server(socket_path, os.environ.get("INSTA_LOG", os.devnull))
    if server.fork_and_wait_for_server() != 0:
        # parent (== client)

        # try connecting again
        ret = client.connect()
        if ret is not None:
            # print("Napping for the debugger")
            # import time
            # time.sleep(400)
            sys.exit(ret)
        else:
            raise Exception("Uh-oh... Failed to connect to instastart background process!")
    else:
        # this will fall through, running all code that
        # should be prewarmed until it's paused in start()
        return server

_disabled = os.environ.get("INSTA_DISABLE", "no")
if _disabled == "yes":
    _disabled = True
elif _disabled == "no":
    _disabled = False
else:
    raise Exception(f'$INSTA_DISABLE environmental variable must be either "yes" or "no" (current: INSTA_DISABLE={_disabled})')

if not _disabled:
    _server = _connect_or_serve()

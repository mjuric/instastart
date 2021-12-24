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
    except ImportError:
        pass

# for debugging -- flip this to True to keep STDERR connected to the console
_keep_stderr = False

def debug(*argv, **kwargs):
    # our own fast-ish logging routines (importing logging seems to add
    # ~15msec to runtime, tested on macOS/MBA)
    if _keep_stderr:
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

            # close whatever we've had open for stdin/out/err, and redirect
            # the server output to a log file (/dev/null, by default).
            # Note: https://docs.python.org/3/faq/library.html#why-doesn-t-closing-sys-stdout-stdin-stderr-really-close-it
            os.close(0)
            os.close(1)
            if not _keep_stderr:
                os.close(2)
            fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            os.dup2(fd, 1)
            if not _keep_stderr:
                os.dup2(fd, 2)
            os.close(fd)

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

    def _spawn(self, conn, fp):
        # Fork the sentry and worker processes to execute the payload.
        #
        # The sentry is forked first, which then forks the worker. The sentry
        # plays the role of the shell -- controls the tty session, monitors
        # worker signals and communicates the exit status to the client.
        # See docs/implementation.md for details.
        #
        # Returns only in the worker process.

        # load the run specification, and apply it to our process
        pipe = Pipe.receive(conn, fp)
    
        os.setsid()
        if pipe.tty is not None:
            # make us the session leader, and make the tty our 
            # controlling terminal
            fcntl.ioctl(pipe.tty, termios.TIOCSCTTY)

        # receive SIGCHLD signals via a file descriptor. this way we can
        # select() both on conn and child messages in _sentry_loop()
        sig_r, sig_w = os.pipe()
        os.set_blocking(sig_w, False)
        signal.set_wakeup_fd(sig_w, warn_on_full_buffer=False)
        signal.signal(signal.SIGCHLD, lambda signum, frame: None)  # have to set a dummy handler, otherwise sig_w isn't woken up

        # the sentry will set up the child's process group and terminal.
        # while that's going on, the child should wait and not start
        # executeing the payload. We do this by having the child wait to
        # receive a message via a pipe.
        r, w = os.pipe()
        wrk_r, wrk_w = os.pipe()    # return messages from the worker (for done())

        # fork the worker process
        pid = os.fork()
        if pid == 0:
            _debug_write_pid("worker")
            self._is_worker = True
            _setproctitle(f"[{' '.join(sys.argv)} :: worker/{pipe.pid}]")

            os.close(sig_r)         # signal handling pipes
            os.close(sig_w)
            os.close(w)             # we'll only be reading
            conn.close()            # we won't be directly communicating to the client
            os.close(wrk_r)
            self.wrk_w = wrk_w      # so done() can use it to message the sentry

            # wait until the sentry sets us up
            if os.read(r, 1) != b"x":
                raise Exception("[worker] sentry closed the pipe w/o starting us.") # pragma: no cover
            os.close(r)

            # return to __main__ to run the payload
            return
        else:
            # change name to denote we're the sentry
            _setproctitle(f"[{' '.join(sys.argv)} :: sentry/{pipe.pid}]")

            os.close(r)                 # we'll only be writing
            os.close(wrk_w)

            os.setpgid(pid, pid)        # start a new process group for the child
            if pipe.tty is not None:
                os.tcsetpgrp(pipe.tty, pid)	# make the child's the foreground process group (so it receives tty input+signals)

            _write_object(fp, pid)      # send the child's PID back to the client

            os.write(w, b"x")           # unblock the child, close the pipe
            os.close(w)

            try:
                self._sentry_loop(fp, sig_r, wrk_r, pid)
            finally:
                conn.close()
                os.close(sig_r)
                os.close(sig_w)
                os.close(wrk_r)
                # FIXME: this should really be os._exit(), otherwise
                # except/finally branches may be triggered in the user's
                # code. Keeping sys.exit() for now as coverage.py needs to
                # run atexit handlers.
                sys.exit(0)

        assert False, "We should never exit this function" #pragma: no cover

    def _sentry_loop(self, fp, sig_r, wrk_r, pid):
        # Await for signals or messages about the worker, as well as whether
        # client is alive.
        confd = fp.fileno() # client control conection
        wrk_fp = os.fdopen(wrk_r, "rb", buffering=0) # worker pipe for done()
        fds = [ confd, sig_r, wrk_r ]
        exited = False # did the worker "exit" via a call to done()
        while fds:
            # debug(f"about to select {fds=}")
            rfds, _, _ = foo = select.select(fds, [], [])
            # debug(f"{foo=}")
            # debug(f"{confd=} {sig_r=} {wrk_r=}")

            if confd in rfds:
                # this should only happen if the connection has been closed.
                # Either the client has died w/o being able to shutdown
                # cleanly (in which case we'll terminate the worker)
                # OR the client has exited because the worker exited via
                # done(). Either way, we'll stick around to reap the worker.

                # debug("SENTRY: confd selected")
                try:
                    data = os.read(confd, 1024*1024)
                except OSError:
                    data = b''
                assert data == b''

                #debug(f"SENTRY: confd connection closed, {exited=} {data=}")
                if not exited:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                
                fds.remove(confd)

            if wrk_r in rfds:
                # user-initiated exit (i.e., the user called done())
                # emulate an exit here.
                debug("SENTRY: about to read")
                try:
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

                    _write_object(fp, ("exited", exitstatus))
                    exited = True
                else: #pragma: no cover
                    assert False, f"Unknown command {cmd=}"

            if sig_r in rfds:
#            if True:
                # empty the buffer (we only use this for signaling on the child)
                dummy = os.read(sig_r, 1024*1024)
                debug(f"{len(dummy)=}")

                debug(f"SENTRY[{os.getpid()}]: waitpid on {pid=}")
                _, status = os.waitpid(pid, os.WUNTRACED | os.WCONTINUED)
                debug(f"SENTRY: WAITPID finished")
                if exited:
                    debug(f"Breaking out of the loop")
                    break
                # debug(f"SENTRY: waitpid returned {status=}")
                # debug(f"SENTRY: {os.WIFSTOPPED(status)=} {os.WIFEXITED(status)=} {os.WIFSIGNALED(status)=} {os.WIFCONTINUED(status)=}")
                if os.WIFSTOPPED(status):
                    # let the controller know we've stopped
                    _write_object(fp, ("stopped", 0))
                elif os.WIFEXITED(status):
                    # we've exited. return the status back to the controller
                    _write_object(fp, ("exited", os.WEXITSTATUS(status)))
                    break
                elif os.WIFSIGNALED(status):
                    # we've exited. return the status back to the controller
                    _write_object(fp, ("signaled", os.WTERMSIG(status)))
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

class Pipe:
    tty = None  # out tty (Client: real tty; Worker: the slave_fd of the pty)
    pty = None  # Used only on the Client, the pty we've set up for the Worker
    termios = None # original termios attributes of the Client's tty

    # specification of a worker run. Things like argv, cwd, environ, and file
    # descriptors.
    def __init__(self):
        pass

    @staticmethod
    def construct():
        # constructs the run specification from the current process. This is
        # usually how this class is meant to be constructed, from the client.
        self = Pipe()

        # the process environment
        self.argv = sys.argv
        self.cwd = os.getcwd()
        self.environ = os.environ.copy()
        self.pid = os.getpid()

        # STDIN/OUT/ERR file descriptiors
        self.fds = []
        for fd in [STDIN, STDOUT, STDERR]:
            if not os.isatty(fd):
                # pipe -- we can duplicate this directly, for zero overhead
                # reads/writes
                self.fds.append(fd)
            else:
                # tty -- as the remote process is not part of this session,
                # it won't be able to directly write to our tty fd. Instead,
                # we'll open a pty, pass on a slave end, and the client will
                # manually shuttle data tty <-> pty.
                if self.pty is None:
                    # set up a pty made to look like our tty
                    self.pty = os.openpty()
                    # copy tty properties & window size
                    self.tty = os.open(os.ttyname(fd), os.O_RDWR)
                    self.termios = termios.tcgetattr(self.tty)
                    termios.tcsetattr(self.pty[1], termios.TCSAFLUSH, self.termios)
                    _setwinsize(self.pty[1], _getwinsize(self.tty))
                self.fds.append(self.pty[1])

        return self

    # def __del__(self):
    #     # close the pty
    #     if getattr(self, "pty", None):
    #         os.close(self.pty[0])
    #         os.close(self.pty[1])
    #         os.close(self.tty)

    def write(self, conn, fp):
        _write_object(fp, self)

        # pass on the master_fd as well, if we have a pty
        fds = self.fds[:]
        if self.pty:
            fds.append(self.pty[0])

        socket.send_fds(conn, [ b'm' ], fds)

    @staticmethod
    def receive(conn, fp):
        # called by the sentry to set up the worker process & connection
        self = _read_object(fp)
        _, fds, _, _ = socket.recv_fds(conn, 10, maxfds=4)

        # pty/tty variables
        if len(fds) == 4:      # means we have a pty
            for fd in fds:     # one of the fds is our tty; pull it out
                if os.isatty(fd):
                    self.tty = fd
                    break
            self.pty = (fds[3], self.tty)   # fds[3] is the master_fd; we need to keep it 
                                            # open on the Sentry so we don't
                                            # get SIGHUP-ed if the Client
                                            # exits before us, closing
                                            # master_fd.
        self.fds = fds[:3]

        # apply the run specification to the current process
        sys.argv = self.argv
        os.chdir(self.cwd)
        os.environ.clear()
        os.environ.update(self.environ)

        # File descriptors for STDIN/OUT/ERR
        if not _keep_stderr:
            fdnums = [STDIN, STDOUT, STDERR]
        else:
            fdnums = [STDIN, STDOUT]
        for src, dst in zip(self.fds, fdnums):
            os.dup2(src, dst)

        return self

class Client:
    socket_path = None   # path to the UNIX socket we connect to

    def __init__(self, socket_path) -> None:
        self.socket_path = socket_path

    def _communicate_loop(self, master_fd, tty_fd, control_fp, termios_attr, remote_pid):
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
        if tty_fd is not None: fds.append(tty_fd)
        
        # debug(f"{fds=} {master_fd=} {tty_fd=}")
        while fds:
            rfds, _wfds, _xfds = select.select(fds, [], [])
            # import time; debug(f"{rfds=} {time.time()=}")

            # received output
            if master_fd in rfds:
                # Some OSes signal EOF by returning an empty byte string,
                # some throw OSErrors.
                try:
                    data = os.read(master_fd, 1024*1024)
                except OSError:
                    data = b""
                if not data:  # Reached EOF.
                    # debug("CLIENT: zero read on master_fd")
                    fds.remove(master_fd)
                else:
                    os.write(tty_fd, data)

            # received input
            if tty_fd in rfds:
                data = os.read(tty_fd, 1024*1024)
                if not data:
                    fds.remove(tty_fd)
                else:
                    _writen(master_fd, data)

            # received a control message
            if control_fd in rfds:
                # a control message from the worker. they've
                # paused, exited, etc.
                event, data = _read_object(control_fp)
                # debug(f"CLIENT: received {event=}")
                if event == "stopped":
                    if tty_fd is not None:
                        # it's possible we've been backrounded by the time we got here,
                        # so ignore SIGTTOU while mode-setting. This can happen if someone sent
                        # us (the client) an explicit SIGTSTP.
                        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                        termios.tcsetattr(tty_fd, tty.TCSAFLUSH, termios_attr)	# restore tty
                        signal.signal(signal.SIGTTOU, signal.SIG_DFL)
                        # debug("CLIENT: Putting us to sleep")
                        # os.kill(os.getpid(), signal.SIGSTOP)			# put ourselves to sleep
                    os.kill(0, signal.SIGSTOP)			# put ourselves to sleep

                    # this is where we sleep....
                    # ... and continue when we're awoken by SIGCONT (e.g., 'fg' in the shell)

                    if tty_fd is not None:
     	                # debug("CLIENT: Awake again")
                        tty.setraw(tty_fd)					# turn the STDIN raw again

                        # set terminal size (in case it changed while we slept)
                        s = fcntl.ioctl(tty_fd, termios.TIOCGWINSZ, '\0'*8)
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
                    if tty_fd is not None:
                        termios.tcsetattr(tty_fd, tty.TCSAFLUSH, termios_attr)	# restore tty back from the raw mode
                    # then restore its default handler and commit a copycat suicide
                    signal.signal(signum, signal.SIG_DFL)
                    os.kill(os.getpid(), signum)
                else:
                    assert 0, "unknown control event {event}"

    def _communicate(self, fp, pipe, remote_pid):
        # raw mode control
        try:
            # switch our input to raw mode, so everything is passed on to the
            # worker
            if pipe.tty is not None:
                tty.setraw(pipe.tty)
                master_fd = pipe.pty[0]
            else:
                master_fd = None

            # Now enter the communication forwarding loop
            return self._communicate_loop(master_fd, pipe.tty, fp, pipe.termios, remote_pid)
        finally:
            # restore our console
            if pipe.tty is not None:
                termios.tcsetattr(pipe.tty, tty.TCSAFLUSH, pipe.termios)

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
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.socket_path)
        except (FileNotFoundError, ConnectionRefusedError):
            # connection failed; return None
            return None

        fp = client.makefile(mode='rwb', buffering=0)

        cmd = os.environ.get("INSTA_CMD", None)
        if cmd is not None:
            _write_object(fp, cmd)
            sys.exit(0)

        # this is a command run
        _write_object(fp, "run")

        # set up a run spec and request to launch the worker
        pipe = Pipe.construct()
        if pipe.pty:
            # set up the SIGWINCH handler which copies terminal window changes
            # to the pty
            signal.signal(
                signal.SIGWINCH,
                lambda signum, frame: _setwinsize(pipe.pty[1], _getwinsize(pipe.tty))
            )
        pipe.write(client, fp)

        # get the child PID
        remote_pid = _read_object(fp)

        # pass any signals we receive back to the worker
        self._setup_signal_passthrough(remote_pid)

        # communicate through the pipe until the worker or client end
        return self._communicate(fp, pipe, remote_pid)

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
#            print("Napping for the debugger")
#            import time
#            time.sleep(400)
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

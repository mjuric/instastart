# FIXME:
#  * Do we need to block/unblock signals in signal handlers?
#  * Sane default for systems w/o XDG_RUNTIME_DIR (macOS)
#  * Proper logging
#  * Tests
#
import socket, os, sys, marshal, tty, fcntl, termios, select, signal

# construct our unique socket name
def _construct_socket_name():
    import inspect, hashlib

    # the name of the file at the top of the call stack (should be our main file)
    pth = inspect.stack()[-1].filename
    py = sys.executable
    env = "PYTHONPATH=" + os.environ.get("PYTHONPATH",'')

    state=f"{pth}-{py}-{env}"

    # compute the md5 of the elements that affect the execution environment,
    # to get something unique.
    # FIXME: this should also incorporate environ, current python interpreted
    md5 = hashlib.md5(state.encode('utf-8')).hexdigest()

    # take the filename, w/o the extension
    fn = pth.split('/')[-1].split('.')[0]

    return os.path.join(os.environ['XDG_RUNTIME_DIR'], f"{fn}.{md5}.socket")

socket_path = _construct_socket_name()

# Helpful constants
STDIN  = 0
STDOUT = 1
STDERR = 2

# our own fast-ish logging routines
# (importing logging seems to add ~15msec to runtime, tested on macOS/MBA)
#
def debug(*argv, **kwargs):
    kwargs['file'] = sys.stderr
    return print(*argv, **kwargs)

#############################################################################
#
#   Pty management routines
#
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
#
#   Child spawner
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

        # Flush the output back to the client
        if not sys.stdout.closed: sys.stdout.flush()
        if not sys.stderr.closed: sys.stderr.flush()

        # FIXME: HACK: This is a _HUGE_ hack, introducing a race condition w. the sentry process.
        #              only the sentry should ever be talking to _client_fp; we should
        #              have a pipe back to the sentry instead.
        _write_object(self._client_fp, ("exited", exitcode))

    def _spawn(self, conn, fp):
        # Fork the sentry and worker processes to execute the payload.
        #
        # The sentry is forked first, which then forks the worker. The sentry
        # plays the role of the shell -- controls the tty session, monitors
        # worker signals and communicates the exit status to the client.
        # See docs/implementation.md for details.
        #
        # Returns only in the worker process.

        # receive the command line
        sys.argv = _read_object(fp)
        
        # receive the cwd (and change to it)
        cwd = _read_object(fp)
        os.chdir(cwd)

        # receive the environment
        env = _read_object(fp)
        os.environ.clear()
        os.environ.update(env)

        # File descriptors that we should directly duplicate (w. dup2)
        fdidx = _read_object(fp) # a list of one or more of [STDIN, STDOUT, STDERR]
    #    debug(f"{fdidx=}")
        if len(fdidx):
            _, fds, _, _ = socket.recv_fds(conn, 10, maxfds=len(fdidx))
        else:
            fds = []
    #    debug(f"{fds=}")
        for a, b in zip(fds, fdidx):
    #        debug(f"_spawn: duplicating fd {a} to {b}")
            os.dup2(a, b)

        # receive the client PID (FIXME: we don't really use this)
        remote_pid = _read_object(fp)

        havetty = len(fdidx) != 3
        if havetty:
            # Open a new PTY and send it back to our controller process
            master_fd, slave_fd = os.openpty()

            # send back the master_fd, wait for master to set it up and
            # acknowledge.
            socket.send_fds(conn, [ b'm' ], [master_fd])
            ok = _read_object(fp)
            assert ok == "OK"
            os.close(master_fd) # master_fd is with the client now, so we can close it

            # make us the session leader, and make slave_fd our 
            # controlling terminal and dup it to stdin/out/err
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY)

            # duplicate what's needed
            if STDERR not in fdidx: os.dup2(slave_fd, STDERR); #debug(f"{(slave_fd, STDERR)=}")
            if STDIN  not in fdidx: os.dup2(slave_fd, STDIN); #debug(f"{(slave_fd, STDIN)=}")
            if STDOUT not in fdidx: os.dup2(slave_fd, STDOUT); #debug(f"{(slave_fd, STDOUT)=}")

        # the parent will set up the child's process group and terminal.
        # while that's going on, the child should wait and not execute
        # the payload. We do this by having the child wait to receive
        # a message via a pipe.
        r, w = os.pipe()
        
        # now fork the payload process
        pid = os.fork()
        if pid == 0:
            self._is_worker = True

            os.close(w)             # we'll only be reading
            conn.close()            # we won't be directly communicating to the client
            if havetty:
                os.close(slave_fd)  # this has now been duplicated to STD* stream
            self._client_fp = fp    # FIXME: massive hack, for communicating the done() msg to the client

            # wait until the parent sets us up
            while not len(os.read(r, 1)):
                pass
            os.close(r)

            # return to __main__ to run the payload
            return
        else:
            # change name to denote we're the sentry
            #import setproctitle
            #setproctitle.setproctitle(f"{' '.join(sys.argv)} [sentry for {pid=}]")

            os.close(r)			# we'll only be writing
            
            os.setpgid(pid, pid)		# start a new process group for the child
            if havetty:
                os.tcsetpgrp(slave_fd, pid)	# make the child's the foreground process group (so it receives tty input+signals)

            _write_object(fp, pid)		# send the child's PID back to the client

            os.write(w, b"x")		# unblock the child, close the pipe
            os.close(w)

            # Loop here calling waitpid(-1, 0, WUNTRACED) to handle
            # the child's SIGSTOP (by SIGSTOP-ing the remote_pid) and death (just exit)
            # Really good explanation: https://stackoverflow.com/a/34845669
            # FIXME: We should handle the case where remote_pid is killed, by
            #        periodically timing out and checking if conn is still open...
            #        Or, we could move all this into a SIGCHLD handler, and
            #        constantly listen on conn?
            #        Actually, we should do this: https://docs.python.org/3/library/signal.html#signal.set_wakeup_fd
            while True:
    #            debug(f"SENTRY: waitpid on {pid=}")
                _, status = os.waitpid(pid, os.WUNTRACED | os.WCONTINUED)
    #            debug(f"SENTRY: waitpid returned {status=}")
    #            debug(f"SENTRY: {os.WIFSTOPPED(status)=} {os.WIFEXITED(status)=} {os.WIFSIGNALED(status)=} {os.WIFCONTINUED(status)=}")
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
                    assert 0, f"weird {status=}"

            # the child has exited; clean up and leave
            if havetty: os.close(slave_fd)
            conn.close()

            # the sentry must never return
            sys.exit(0)

        # 
        assert False, "We should never exit this function"

#############################################################################
#
#   Control socket communication routines
#
#############################################################################

def _read_object(fp):
    """ Read a marshaled object from file fp """
    return marshal.load(fp)

def _write_object(fp, obj):
    """ Write an object to file fp, using marshal """
    return marshal.dump(obj, fp)

def _writen(fd, data):
    """Write all the data to a descriptor."""
    while data:
        n = os.write(fd, data)
        data = data[n:]

def _copy(master_fd, tty_fd, control_fp, termios_attr, remote_pid):
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
    import time
#    debug(f"{fds=} {master_fd=} {tty_fd=}")
    while fds:
        rfds, _wfds, _xfds = select.select(fds, [], [])
#        debug(f"{rfds=} {time.time()=}")

        # received output
        if master_fd in rfds:
            # Some OSes signal EOF by returning an empty byte string,
            # some throw OSErrors.
            try:
                data = os.read(master_fd, 1024)
            except OSError:
                data = b""
            if not data:  # Reached EOF.
#                debug("CLIENT: zero read on master_fd")
                fds.remove(master_fd)
            else:
                os.write(tty_fd, data)

        # received input
        if tty_fd in rfds:
            data = os.read(tty_fd, 1024)
            if not data:
                fds.remove(tty_fd)
            else:
                _writen(master_fd, data)

        # received a control message
        if control_fd in rfds:
            # a control message from the worker. they've
            # paused, exited, etc.
            event, data = _read_object(control_fp)
#            debug(f"CLIENT: received {event=}")
            if event == "stopped":
                if tty_fd is not None:
                    # it's possible we've been backrounded by the time we got here,
                    # so ignore SIGTTOU while mode-setting. This can happen if someone sent
                    # us (the client) an explicit SIGTSTP.
                    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                    termios.tcsetattr(tty_fd, tty.TCSAFLUSH, termios_attr)	# restore tty
                    signal.signal(signal.SIGTTOU, signal.SIG_DFL)
#                    debug("CLIENT: Putting us to sleep")
#                    os.kill(os.getpid(), signal.SIGSTOP)			# put ourselves to sleep
                os.kill(0, signal.SIGSTOP)			# put ourselves to sleep

                # this is where we sleep....
                # ... and continue when we're awoken by SIGCONT (e.g., 'fg' in the shell)

                if tty_fd is not None:
# 	             debug("CLIENT: Awake again")
                    tty.setraw(tty_fd)					# turn the STDIN raw again

                    # set terminal size (in case it changed while we slept)
                    s = fcntl.ioctl(tty_fd, termios.TIOCGWINSZ, '\0'*8)
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, s)

                # FIXME: we should message the nanny to do this (pid race condition!)
                os.killpg(os.getpgid(remote_pid), signal.SIGCONT)	# wake up the worker process
            elif event == "exited":
                return data # data is the exitstatus
            elif event == "signaled":
#                return -1
                signum = data  # data is the signal that terminated the worker
                if tty_fd is not None:
                    termios.tcsetattr(tty_fd, tty.TCSAFLUSH, termios_attr)	# restore tty back from the raw mode
                # then restore its default handler and commit a copycat suicide
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)
            else:
                assert 0, "unknown control event {event}"

#
# Handling broken pipe-related errors:
#   https://bugs.python.org/issue11380,#msg153320
#

# we need to catch & pass on:
# INTR, QUIT, SUSP, or DSUSP ==> SIGINT, SIGQUIT, SIGTSTP, SIGTERM
# and then we need SIGCONT for recovery
# See: https://www.gnu.org/software/libc/manual/html_node/Signal-Characters.html
# See: https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html

def _setup_signal_passthrough(remote_pid):
    def _handle_ISIG(signum, frame):
        # just pass on the signal to the remote process
        #
        # if the remote process handles the signal by suspending
        # or terminating itself, we'll be told about it via
        # the control socket (and can do the same).
        #
        # FIXME: this signaling should be done through the control socket (pid race contitions!)
#        debug(f"_handle_ISIG: {signum=}")
        os.killpg(os.getpgid(remote_pid), signum)

    # forward all signals that make sense to forward
    fwd_signals = set(signal.Signals) - {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD, signal.SIGWINCH}
    for signum in fwd_signals:
        signal.signal(signum, _handle_ISIG)

#
# Really useful explanation of how SIGTSTP SIGSTOP CTRL-Z work:
#   https://news.ycombinator.com/item?id=8773740
#
def _connect(timeout=None):
    # try connecting to the UNIX socket. If successful, pass it our command
    # line (argv).  If connection is not successful, start the server.
#    if not os.path.exists(socket_path):
#        return _server(preload, payload, timeout)

    # try connecting
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(socket_path)
    except (FileNotFoundError, ConnectionRefusedError):
        # connection failed; return None
        return None

    fp = client.makefile(mode='rwb', buffering=0)

    cmd = os.environ.get("INSTA_CMD", None)
    if cmd is not None:
        debug(f"Messaging the server {cmd=}")
        _write_object(fp, cmd)
        sys.exit(0)

    # tell the server we want to run a command
    _write_object(fp, "run")

    # send our command line
    _write_object(fp, sys.argv)

    # send cwd
    _write_object(fp, os.getcwd())

    # send environment
    _write_object(fp, os.environ.copy())

    # find which one of our STD* descriptors point to the tty.
    # send non-tty file descriptors directly to the worker. These will
    # be dup2-ed, rather than manually copied to in the _copy loop.
    pipes = filter(lambda fd: not os.isatty(fd), [STDIN, STDOUT, STDERR])
    pipes, tty_fd = [], None
    for fd in [STDIN, STDOUT, STDERR]:
        if not os.isatty(fd):
            pipes.append(fd)
        elif tty_fd is None:
            ttyname = os.ttyname(fd)
#            debug(f"{ttyname=}")
            tty_fd = os.open(ttyname, os.O_RDWR)

#    debug(f"Non-tty {pipes=}")
#    debug(f"{tty_fd=}")
    _write_object(fp, pipes)
    if len(pipes):
        socket.send_fds(client, [ b'm' ], pipes)

    # send our PID (FIXME: is this necessary?)
    _write_object(fp, os.getpid())

    if tty_fd is not None:
        # we'll need a pty. the server will create it for us, and we
        # need to receive and set it up.
        _, (master_fd,), _, _ = socket.recv_fds(client, 10, maxfds=1)
        termios_attr = termios.tcgetattr(tty_fd)
        termios.tcsetattr(master_fd, termios.TCSAFLUSH, termios_attr)
        _setwinsize(master_fd, _getwinsize(tty_fd))
        _write_object(fp, "OK")

        # set up the SIGWINCH handler which copies terminal window changes
        # to the pty
        signal.signal(
            signal.SIGWINCH,
            lambda signum, frame: _setwinsize(master_fd, _getwinsize(tty_fd))
        )
    else:
        # no tty, pipes all the way
        master_fd = termios_attr = None

    # get the child PID
    remote_pid = _read_object(fp)

    # pass any signals we receive back to the worker
    _setup_signal_passthrough(remote_pid)

    # Now enter the control loop
    try:
        # switch our input to raw mode
        # See here for _very_ useful info about raw mode:
        #   https://stackoverflow.com/questions/51509348/python-tty-setraw-ctrl-c-doesnt-work-getch
        if tty_fd is not None:
            tty.setraw(tty_fd)

        # Now enter the communication forwarding loop
        exitcode = _copy(master_fd, tty_fd, fp, termios_attr, remote_pid)
    finally:
        # restore our console
        if tty_fd is not None:
            termios.tcsetattr(tty_fd, tty.TCSAFLUSH, termios_attr)

    return exitcode

from contextlib import contextmanager
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

def _unlink_socket():
    # atexit handler registered by _server
    if os.path.exists(socket_path):
        os.unlink(socket_path)

class Server:
    # the pipe that .start() uses to signal the server is ready
    _readypipe = None

    def fork_and_wait_for_server(self):
        _r, _w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(_r)
            import setproctitle
            name = sys.argv[0].split('/')[-1]
            setproctitle.setproctitle(f"[instastart: {name}]")

            # child -- this is what will become the server. Just fall through
            # the code, to be caught in start(). This will launch the
            # server, setting up its socket, etc., and signaling we're ready by
            # writing to _r pipe.

            # start a new session, to protect the child from SIGHUPs, etc.
            # we don't double-fork as the daemon never really does anything
            # funny with the tty (TODO: should we still double-fork, just in case?)
            os.setsid()

            # now fall through until we hit start() somewhere in __main__
            self._readypipe = _w
            pass
        else:
            os.close(_w)
            # parent -- we'll wait for the server to become available, then connect to it.
    #        print(f"Awaiting a signal at {socket_path=}")
            while True:
                msg = os.read(_r, 1)
    #            debug(msg)
                if len(msg):
                    break
            os.close(_r)
    #        print(f"Signal received!")
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
        spath = f"{socket_path}.{pid}"
        if os.path.exists(spath):
            os.unlink(spath)

        # make sure we clean up if anything goes wrong
        import atexit
        atexit.register(_unlink_socket)

    #    debug(f"Opening socket at {socket_path=} with {timeout=}...", end='')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            os.fchmod(sock.fileno(), 0o700)		# security: only allow the user to do anything w. the socket
            sock.bind(spath)
            sock.listen()
            os.rename(spath, socket_path)
    #        debug(' done.')

            if self._readypipe is not None:
    #            debug('signaling on readypipe')
                # signal to the reader the server is ready to accept connections
                os.write(self._readypipe, b"x")
                os.close(self._readypipe)
                self._readypipe = None
    #            debug('done')

            # Await for client connections (or server commands)
            while True:
                try:
                    conn, _ = sock.accept()
                except socket.timeout:
                    debug("Server timeout. Exiting")
                    sys.exit(0)
    #            debug(f"Connection accepted")

                # make our life easier & create a file-like object
                fp = conn.makefile(mode='rwb', buffering=0)

                cmd = _read_object(fp)
    #            debug(f"{cmd=}")
                if cmd == "stop":
                    # exit the listen loop
                    debug("Server received a command to exit. Exiting")
                    sys.exit(0)
                elif cmd == "run":
                    # Fork a child process to do the work.
                    pid = os.fork()
                    if pid == 0:
                        # Child process -- this is where the work gets done
                        atexit.unregister(_unlink_socket)
                        sock.close()
                        return Worker(conn, fp)
                    else:
                        conn.close()

        # This function will continue _only_ in the spawned child process,
        # and execute the main program.
        assert False, "This function should only return in a worker process!"

    def start(self, timeout):
        # run the server. Returns only in the forked worker process.
    #    print("Spinning up the server... {_w=}")
        return self._serve(timeout=timeout)

def start():
    timeout = os.environ.get("INSTA_TIMEOUT", 10)

    global worker
    worker = server.start(timeout=timeout)

    return worker

def done(exitcode=0):
    # signal the client we've finished and that it can safely pretend
    # this process has exited.
    #
    # May only be called from the worker (i.e., after start() has been called).
    worker.done(exitcode)

def _connect_or_serve():
    # try connecting on our socket; if fail, spawn a new server

    # try connecting
    ret = _connect()
    if ret is not None:
        sys.exit(ret)

    # fork the server. This will return pid or 0, depending on if it's
    # child or parent
    server = Server()
    if server.fork_and_wait_for_server() != 0:
        # parent (== client)

        # try connecting again
        ret = _connect()
        if ret is not None:
            sys.exit(ret)
        else:
            raise Exception("Uh-oh... Failed to connect to instastart background process!")
    else:
        # this will fall through the code until, running all code that
        # should be prewarmed until it's paused in start()
        return server

server = _connect_or_serve()

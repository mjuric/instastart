#
# A small echo server designed to test out pty and signal forwarding
#

import sys, os
if '--instastart' not in sys.argv:
    os.environ["INSTA_DISABLE"] = "yes"

from instastart.auto import serve
import os, time, sys, errno, signal, struct, fcntl, termios

# unbuffered read of a line from stdin
def getline():
    line = []
    while True:
        c = os.read(0, 1)
        line.append(c)
        if c in [b"", b"\n"]:
            break
    return b"".join(line)

def xprint(*args, **kwargs):
    kwargs["flush"] = True
    print(*args, **kwargs)

streams = dict(stdin=0, stdout=1, stderr=2)

def cmd_info():
    xprint(f"{os.getpid()=}")
    xprint(f"{os.isatty(0)=}")
    xprint(f"{os.isatty(1)=}")
    xprint(f"{os.isatty(2)=}")

    # see if we have a controlling terminal
    try:
        ctty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        xprint(f"controlling tty: {os.ttyname(ctty)}")

        fg = os.tcgetpgrp(ctty) == os.getpgrp()
        xprint(f"The process is in the {'foreground' if fg else 'background'}")

        os.close(ctty)
    except OSError as e:
        if e.errno != errno.ENXIO:
            raise
        xprint(f"No controlling tty")

def cmd_help():
    import inspect
    prefix = "cmd_"
    xprint("available commands:")
    for name in dir(sys.modules["__main__"]):
        if not name.startswith(prefix):
            continue

        func = getattr(sys.modules["__main__"], name)
        if not callable(func):
            continue

        # cmd
        cmd = [ name[len(prefix):] ]
        for argname, p in inspect.signature(func).parameters.items():
            if p.default != inspect._empty:
                s = f"[{argname}={p.default}]"
            else:
                s = f"<{argname}>"
            cmd.append(s)
        cmd = ' '.join(cmd)

        # docstring
        d = func.__doc__
        if d is None:
            xprint(f"  {cmd:30s}")
        else:
            xprint(f"  {cmd:30s}: {d}")

def cmd_close(*what):
    if not what:
        what = list(streams.keys())

    names = []
    fds = []
    for name in what:
        fd = stream_to_fd(name)
        if fd is None:
            xprint(f"error: {name=} unknown. must be one of {list(streams.keys())} or an integer fd.")
            continue
        else:
            fds.append(fd)

        if str(fd) != name:
            names.append(f"{fd}({name})")
        else:
            names.append(fd)
    names = ', '.join(names)
    xprint(f"closing fds {names}.")

    for fd in fds:
        os.close(fd)

def stream_to_fd(name_or_fd):
    destfd = streams.get(name_or_fd, None)
    try:
        if destfd is None:
            destfd = int(name_or_fd)
            if destfd < 0:
                raise ValueError()
        return destfd
    except ValueError:
        return None

def cmd_open(dest, source, mode="rw"):
    intmode = dict(
        r  = os.O_RDONLY,
        w  = os.O_WRONLY,
        rw = os.O_RDWR
    ).get(mode, None)
    if intmode is None:
        xprint(f"error: {mode=} unknown.")

    destfd = stream_to_fd(dest)
    if destfd is None:
        xprint(f"error: {dest=} unknown. must be one of {list(streams.keys())} or an integer fd.")

    xprint(f"opening {source} as {dest} with {mode=} | {destfd=} {intmode=}")

    fd = os.open(source, intmode)
    if fd != destfd: # this can happen by chance
        os.dup2(fd, destfd)
        os.close(fd)

def cmd_stop():
    xprint("sending SIGSTOP to my process group.")
    os.killpg(0, signal.SIGSTOP)

def cmd_sleep(seconds):
    seconds = float(seconds)
    xprint(f"sleeping for {seconds} seconds.")
    time.sleep(seconds)

def cmd_child(seconds, silent=False):
    seconds = int(seconds)
    silent = bool(silent)
    pid = os.fork()
    if pid == 0:
        if not silent:
            xprint(f"started pid={os.getpid()}, for {seconds}s: ", end='')
            for _ in range(seconds):
                time.sleep(1)
                xprint(f"#", end='')
            xprint()
        else:
            time.sleep(seconds)
        sys.exit(0)

def _on_signal(signum, frame):
    # convert to name
    sig = next((sig.name for sig in signal.Signals if sig == signum), f"signal {signum}")
    xprint(f"\ncaught {sig}", end='')

    if signum == signal.SIGCHLD:
        os.wait()
    if signum == signal.SIGWINCH:
        s = struct.pack('HHHH', 0, 0, 0, 0)
        t = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, s)
        xprint(": window size =", struct.unpack('HHHH', t), end='')
    if signum == signal.SIGHUP:
        xprint(". exiting.")
        sys.exit()

    xprint("\n> ", end='')

def main(notty=False):
    if notty:
        if os.fork() == 0:
            os.setsid()
        else:
            os.wait()
            sys.exit()

    cmd_info()

    # catchable_sigs = set(signal.Signals) - {signal.SIGKILL, signal.SIGSTOP}
    # for sig in catchable_sigs:
    #     signal.signal(sig, _on_signal)  # Substitute handler of choice for `print`

    while True:
        os.write(1, b"> ")
        try:
            data = getline()
        except OSError as e:
            # should only happen if 'close stdin' or 'close std' were invoked
            xprint("\nOSError: " + str(e))
            sys.exit(-1)
        text = data.decode('utf-8')

        if text == "":
            # end of input; exit
            xprint("Done, exiting.")
            break
        else:
            s = text.rstrip().split()
            if len(s):
                cmd, *args = s
                func = getattr(sys.modules["__main__"], f"cmd_{cmd}", None)
                if func is not None and not callable(func):
                    func = None
            else:
                func = None

            if func is not None:
                func(*args)
            else:
                xprint(data)

if __name__ == "__main__":
    with serve():
        if '--instastart' in sys.argv:
            sys.argv.remove('--instastart')

        notty = len(sys.argv) == 2 and sys.argv[1] == 'notty'
        main(notty=notty)

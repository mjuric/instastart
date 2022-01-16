import os

# The name of this process, for logging ("tty", "worker", "server", "sentry",
# "client"). Set by _fork(name).
_name = None

class TimestampedOutputFile:
    out = None

    def __init__(self, out):
        self.out = out
        self._at_line_start = True

    def write(self, text):
        import datetime
        # add timestamps to beginnings of lines
        ts = f'{datetime.datetime.now().strftime("%b %d %H:%M:%S.%f")} {_name:>6s}[{os.getpid()}] '

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

def set_name(name):
    global _name
    _name = name

def _setup_logging(name="client", logfile=None):
    set_name(name)

    # log file must be inheritable across forks
    if logfile is None:
        logfile = os.environ.get("INSTA_LOG", os.devnull)
    fp = open(logfile, "a")
    os.set_inheritable(fp.fileno(), True)

    global _logfile
    _logfile = TimestampedOutputFile(fp)

def debug(*argv, **kwargs):
    # our own fast-ish logging routines (importing logging seems to add
    # ~15msec to runtime, tested on macOS/MBA)
    kwargs['file'] = _logfile
    kwargs['flush'] = True
    return print(*argv, **kwargs)


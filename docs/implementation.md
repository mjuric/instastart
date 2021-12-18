## Implementation

Two core ideas are at the center of this package:

  1. An observation that the slow startup time of many Python codes is
     due to costly, one-time, unchanging, initialization -- specifically
     imports of large modules.  If there was a way to do this
     initialization just once, then (quickly) copy the state of the
     initialized interpreter for subsequent runs, we'd dramatically cut
     down on the total startup time.

  2. The fact that UNIX systems provide a way to do something like the
     above, using the fork(2) system call (e.g., see the man page at
     https://man7.org/linux/man-pages/man2/fork.2.html).  fork() allows
     one to duplicate (aka "fork") a running process (program).  If we
     could find a clever way to pause a Python program after it's
     finished the (costly) initialization, and then fork() from that
     state the next time it's invoked, we could achieve our goal of
     cutting down the startup times.

This techique is sometimes known as "pre-warming". An ideal
implementation would be one where a pre-warmed server process awaits in
the background.  When a new invocation is launched, it forks the
pre-warmed server and replaces itself w.  the forked child process (while
maintaining the process ID -- the pid, etc.).  This way the result would
seem nearly 100% identical to non-prewarmed runs, from the point of view
of the shell and other programs.  It would also work if one could
"reparent" the server's child to the subsequent invocation (and bind it
to its own terminal).  Alas, neither of those options are allowed on
typical UNIX systems (and for good reasons).

So we have to take a different tack: have the new invocation (which we'll
-- call the "client") act as a /transparent proxy/ shutling input,
output, and signals between the user and the "worker", the process forked
from the server that does the actual work.  This is what instastart does. 
Below we discuss how.

## Gory details

Figure 1. A diagram of a typical execution (first run):

```
  <<client>>
      |
      | ---> contact server on UNIX socket...fail (doesn't exist)
      |
      | -----------> fork <<server>>
      |                       |
      | ---> "cmd=run" -----> |
      |                       | ---> fork <<sentry>>
      |                       :               | (alloc pty)
      | ---> argv + cwd + environ + fds ----> |
      |                       :               |  ---> fork <<worker>>
      |                       :               :                |
      | ------------- stdin/signals/pty control -------------> |
      | <------------------- stdout/stderr ------------------- |
      |                       :               :
      | <--------- waitpid() results -------- |
                              :
                              o exit after idle timeout
```

Terminology:

* server: the pre-warmed process that stick around in the background,
          ready to fork a child to do the work
* worker: the process doing the actual, useful, work. I.e., the thing
          that would be done w/o instastart.
* sentry: the process that watches over the worker, receives and
          forwards the notifications that the worker has stopped or
          has exited. A session leader for the worker's pty.
          Plays the role of a quasi-shell process for the worker.
* client: the process the user launches, which has the server fork a
          child doing the real work and proxies keyboard/signals back to
          the child

The sequence begins by the user launching a client on the command line. 
Usually the very first thing the client does it import
instastart.auto, i.e.:
```
import instastart.auto
```
This module contains the code that makes the client attempt to connect to
the server via a named UNIX socket stored on a well-known path (usually
in $XDG_RUNTIME_DIR).  The name of the socket is unique to the
combination of the path of the executable script, the python interpreter,
and the contents of PYTHONPATH.  If no such socket exists, or if the
connection is unsuccessful, instastart.auto forks a server process.

This server process then returns from the import statement, and continues
running the client's code, presumably some heavy imports and one-time
computations.  It does so until it reaches an invocation of
instastart.auto.start(). Typically:
```
import instastart.auto

   ... heavy imports, dask.distributed, vaex, astropy etc ...

if __name__ == "__main__":
      instastart.auto.start()
      ... code to run ...
```
This function serves as a barrier -- at this point, the server binds to
the named UNIX socket and begins listening for connections, effectivelly
pausing execution.  The big idea is that a subsequent client connection
will cause the server to fork a worker and simply return from
instastart.auto.start(), continuing to run (from the users' code
perspective) as if nothing happened.  Through the magic of fork() and
UNIX' copy-on-write semantics, this can be done many times -- each time
effectivelly skipping all the costly initialization and starting to run
from the line where we invoked instastart.auto.start() (thus the name of
that function).  I.e., we've effectivelly "pre-warmed" Python VM w.  plus
our modules of interest.  The implementation details are a bit more
complicated, as discussed next.

With the server now forked and awaiting connections, the client can
connect to it and request to continue running (possibly in a different
directory, or w.  different cmd args, or environment; more below).  The
server reacts by first forking a sentry process.  This process will serve
as a quasi-shell for the actual worker process (to be forked next, by the
sentry).  It is also necessary to receive signals about worker's state as
well as manage it's pseudo-terminal (pty).  Once the sentry is forked,
the client sends it the specifics of how to continue running -- at least
the argv, cwd, and environ.  These will be modified once the worker is
forked to match the client's environment (i.e., to make the worker's
internal state as close to what it would look like if it was launched
under in the client's location/environment).

If any of the client's stdin/out/err are not connected to the terminal
(i.e., I/O was redirected to a file or piped), the client sends those
file descriptors over as well.  They will be dup2-ed directly to the
worker's stdin/out/err (see below), making for truly zero-overhead IO. 
If at least one of the client's stdin/out/err are connected to a tty, we
need to make the worker believe it's connected to the (analogous)
terminal (otherwise fancy progress bars and other UI elements -- curses,
mouse control, etc -- won't work).  To do so, the sentry allocates a pty
& becomes its session leader.  It then sends back the pty master file
descriptor (master_fd) to the client, who copies the properties of the
local terminal to it (most importantly, the window size).  That way the
worker process will "feel" as if it's running on exactly the same tty as
the client.  After the client sets up the pty, the sentry finally forks
the worker, moves it into its own process group, sets it as the pty's
foreground process, and sends the worker pid back to the client.

This worker process is finally allowed to return from
instastart.auto.start() and continue executing useful code -- from the
point of view of Python code, instastart.auto.start() just took a while
to return.  The worker's I/O is now connected to the pty which the client
controls (or to the duplicated file descriptors, if some std* streams
were redirected).  The client communicates with the worker by polling
master_fd (the worker's pty master end that the sentry sent back) for any
output, and its own STDIN for any input.  The client reads the output
from master_fd and writes it to its own terminal.  Similarly, the client
reads input from its own terminal and writes it to master_fd.  While not
zero, these are fairly low-overhead operations (and no worse than what
your typical SSH, tmux, or screen client does).  The sentry stays on,
waitpid()-ing on the worker, and passing back to the client any messages
on the worker exiting or stopping (i.e., SIGSTOP).

One tricky aspect is the handling of signals and special characters. We
want the worker to receive all of these, but the client must react in
synchrony with the worker if they go beyond just what's written out to
the screen (e.g., if they kill the worker).  That is acheived as follows:
The client's tty is set to raw mode so no special characters (^C, ^Z,
etc..) are interpreted on the client side; they're all read and written
to the worker's tty (who can then react to them as programmed).  Some of
those characters can cause the worker to stop or exit.  The client polls
the control connection to the sentry for notifications of those, and
replays them on itself (i.e., sends itself a signal with same exit code,
or stops itself if the worker has stopped).  For example, if a user types
^Z, the following (typically) happens: ^Z (ASCII 26) is read from the
client's STDIN and written to master_fd.  The client pty's line
discipline (assuming the pty is in cooked mode) sees ^Z and sends a
SIGTSTP to the foreground process -- the worker.  The worker reacts (by
default) by sending itself a SIGSTOP and going to sleep.  The sentry's
waitpid() returns, with WIFSTOPPED(status)==true.  The sentry sends a
message back to the client (via the control socket) that the worker has
gone to sleep.  The client receives the message, restores its own tty to
original (usually cooked) mode, and sends itself a SIGTSTP, which finally
puts it to sleep.  Though the signal route is circuitous, from the user's
perspective it all looks good: they've hit ^Z, and the client has gone to
sleep (i.e., exactly the same behavior as if there were no client/server
split).

Signals are also proxied from the client to the worker. We install a
signal handler on the client for all signals (but a few that wouldn't
make sense to proxy -- e.g., SIGCHLD) and pass them on to the worker
(i.e.  killpg(worker_pid, signum)).  This makes the client process look
and feel even more as if it were the actual worker.  E.g., if used in
bash scripts, etc.  -- killing it with anything but SIGKILL produces the
same effect as killing the underlying worker.  SIGWINCH is handhled
differently -- it's caught, the new terminal window size is read, and
written to the worker pty's master_fd (which causes the pty to trigger
SIGWINCH on the worker, which can then handle the window size change).

## Useful Links

* Handling broken pipe-related errors: https://bugs.python.org/issue11380,#msg153320
* Really useful explanation of how SIGTSTP SIGSTOP CTRL-Z work: https://news.ycombinator.com/item?id=8773740
* Signal characters: https://www.gnu.org/software/libc/manual/html_node/Signal-Characters.html
* Termination signals: https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html

import pytest, sys, subprocess, os, contextlib, glob, time, pexpect, tempfile
from ptyprocess import PtyProcessUnicode
from instastart.logging import _setup_logging, debug

logfile = os.getcwd() + "/pytest.log"
_setup_logging(name="tests", logfile=logfile)

@contextlib.contextmanager
def in_scripts_dir():
    try:
        os.chdir("tests/scripts")
        yield
    finally:
        os.chdir("../..")

@contextlib.contextmanager
def shell(env, must_exist=True, logfile="pexpect.out"):
    env = env.copy()

    # find the full path to xonsh
    import shutil
    xonsh = shutil.which("xonsh")
    bash = shutil.which("bash")

    # allow environmental overrides of pexpect timeout (useful for debugging)
    timeout = int(os.getenv("INSTA_TEST_PEXPECT_TIMEOUT", 2))
    if timeout <= 0: timeout = None

    def xonsh_last_cmd_exitstatus(p):
        p.sendline('echo f"ret:{_.proc.returncode} sig:{0 if _.proc.signal is None else _.proc.signal[0]}"')
        p.expect("ret:([0-9]+) sig:([0-9]+)")
        returncode = int(p.match.group(1))
        signum = int(p.match.group(2))
        if signum == "0":
            signum = None
        else:
            returncode = None
        return (returncode, signum)

    def bash_last_cmd_exitstatus(p):
        p.sendline("echo exitstatus:$?")
        p.expect("exitstatus:([0-9]+)")
        exitstatus = int(p.match.group(1))
        if os.WIFSIGNALED(exitstatus):
            return None, os.WTERMSIG(exitstatus)
        else:
            return os.WEXITSTATUS(exitstatus), None

    def capture(sh, cmd):
        stoken = "--HXaxK6h1kQm5zg--"
        etoken = "--2Jz1LYEjxIaTPw--"
        sh.sendline(f"echo '{stoken}'; {cmd}; echo '{etoken}'")
        sh.expect(f"{stoken}\r\n(.*){etoken}\r\n", timeout=3)
        output = sh.match.group(1)
        sh.expect_shell_prompt()
        return output

    with tempfile.TemporaryDirectory() as tmpdir, open(logfile, "w") as fp:
        env["INSTA_PID_DIR"] = tmpdir
        env["TERM"] = "dumb"  # to (partially) supress xonsh's escape sequence madness

        if True:
            prompt = "xonsh>"
            shell = f"{sys.executable} {xonsh}"
            last_cmd_exitstatus = xonsh_last_cmd_exitstatus
        else:
            prompt = "bash>"
            env["PS1"] = prompt
            shell = f"{bash} --noprofile --norc --noediting"
            last_cmd_exitstatus = bash_last_cmd_exitstatus

        p = pexpect.spawn(shell, env=env, encoding='utf-8', dimensions=(10, 30), timeout=timeout)#, logfile=fp)
        p.logfile_read = fp
        p.expect_shell_prompt = lambda: p.expect_exact(prompt)
        p.last_cmd_exitstatus = lambda: last_cmd_exitstatus(p)
        p.capture = lambda cmd: capture(p, cmd)
        p.expect_shell_prompt()

        # yield to do the work
        debug("shell started")
        yield p

        wait_for_pids(tmpdir, must_exist=must_exist)

        p.sendline("exit")
        p.expect_exact(pexpect.EOF)
        p.wait()

@pytest.fixture(scope="function")
def env():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    env["INSTA_TIMEOUT"] = "0"
    env["INSTA_LOG"] = logfile
    return env

@pytest.mark.parametrize("script", ["simple.py"])
def test_script(script, env):
    # a test with full redirects of all streams (no attached tty)
    with wait_all(env, must_exist=True) as env:
        ret = subprocess.check_output(
            [sys.executable, f"tests/scripts/{script}"],
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env
        )

    assert ret == b'Hello world\n'

def get_pids(dir, *args):
    # get pids for given processes, from .pid files in directory dir
    which = args if args else ("client", "server", "sentry", "worker")
    return tuple( int(open(os.path.join(dir, f"{name}.pid")).read()) for name in which )

def wait_for_pids(dir, must_exist=True):
    # wait for all pids in dir/*.pid to exit.
    # must_exist:
    #   True -- at least one .pid file must exist
    #   False -- OK if no files exist
    #   iterable -- the exact list of files allowed to exist (set this to [] to
    #      require no .pid files to exist)

    pids = {}
    for fn in glob.glob(os.path.join(dir, "*.pid")):
        pid = int(open(fn).read())
        pids[pid] = fn

    if isinstance(must_exist, bool):
        if must_exist is True:
            assert pids
    else:
        which = set(os.path.basename(fn)[:-4] for fn in pids.values())
        assert which == set(must_exist)

    debug(f"waiting for pids: {set(pids.keys())}")
    t0 = time.time()
    while pids:
        for pid in pids:
            try:
                os.kill(pid, 0)
            except (PermissionError, ProcessLookupError) as e:
                #print(pids[pid])
                os.unlink(pids[pid])
                del pids[pid]
                break
        else:
            time.sleep(0.001)

    dt = (time.time() - t0) * 1000
    debug(f"pids awaited in {dt:.0f}ms")

@contextlib.contextmanager
def wait_all(env, must_exist=True):
    env = env.copy()

    with tempfile.TemporaryDirectory() as tmpdir:
        env["INSTA_PID_DIR"] = tmpdir

        yield env

        wait_for_pids(tmpdir, must_exist=must_exist)

@pytest.mark.parametrize("script", ["{python} simple.py", "{python} simple.py yes", "{python} simple.py no"])
def test_with_pty(script, env):
    script = script.format(python=sys.executable)

    with in_scripts_dir(), shell(env) as sh:
        sh.sendline(script)
        sh.expect_exact('Hello world\r\n')
        if script.endswith("no"):
            sh.expect_exact('Exiting\r\n')
        sh.expect_shell_prompt()

def read_all(fp):
    # read all data on fp until EOFError (== fp is closed)
    ret = []
    try:
        while True:
            ret.append(fp.read(1024))
    except EOFError:
        return ''.join(ret)

def pty_run(cmd, env, with_insta=True, **kwargs):
    # run a process under a pty, returning the output. if with_insta=False,
    # INSTA_DISABLE=yes will be set.
    env = env.copy()
    env['INSTA_DISABLE'] = "yes" if not with_insta else "no"
    
    p = PtyProcessUnicode.spawn(cmd, env=env, **kwargs)
    output = read_all(p)
    p.wait()

    return output

def test_progress(env):
    # verify that progress bar output is the same with and without instastart
    with in_scripts_dir():
        # with instastart
        with shell(env) as sh:
            out_on = sh.capture(f"{sys.executable} progress.py")
            #print(out_on)
            #open("out_on.txt", "w").write(out_on)

        # no instastart
        env["INSTA_DISABLE"] = "yes"
        with shell(env, must_exist=[], logfile='pexpect2.out') as sh:
            out_off = sh.capture(f"{sys.executable} progress.py")
            #print(out_off)
            #open("out_off.txt", "w").write(out_off)

        assert out_on == out_off

def test_stop_server(env):
    env = env.copy()
    env["INSTA_TIMEOUT"] = "100"
    with in_scripts_dir(), shell(env) as p:
            # spin up a simple server with a longish timeout, and exit the client
            p.sendline(f"{sys.executable} echo.py")
            p.expect_exact("> ")
            p.sendeof()
            p.expect_exact("Done, exiting.\r\n")
            p.expect_shell_prompt()

            # verify the server is still running
            pid, = get_pids(p.env["INSTA_PID_DIR"], "server")
            os.kill(pid, 0) # this will raise an exception if the process doesn't exist

            # issue a stop command to the server
            env["INSTA_CMD"] = "stop"
            with shell(env, must_exist=['client'], logfile="pexpect2.out") as p2:
                p2.sendline(f"{sys.executable} echo.py")
                p2.expect_shell_prompt()

                # verify the client didn't spawn anything
                #pidfiles = set(glob.glob(os.path.join(envcli["INSTA_PID_DIR"], "*.pid")))
                #assert len(pidfiles) == 1 and pidfiles.pop().endswith('client.pid')

            # verify the server is gone
            with pytest.raises((ProcessLookupError, PermissionError)):
                os.kill(pid, 0)

import psutil, signal
def wait_for(procs, states, timeout):
    if isinstance(procs, psutil.Process):
        procs = [ procs ]
    if not isinstance(states, set):
        states = set(states)    # for performance

    t0 = time.time()
    while timeout is None or time.time() - t0 < timeout:
        for proc in procs:
            try:
                status = proc.status()
            except psutil.NoSuchProcess:
                status = 'terminated'

            if status not in states:
                break
        else:
            return

        time.sleep(0.02)

    raise TimeoutError(str(procs)) # pragma: no cover

def test_suspend_resume(env):
    with in_scripts_dir(), shell(env) as sh:
        # spin up a client + worker
        sh.sendline(f"{sys.executable} echo.py")
        sh.expect_exact("> ")

        client, worker = get_pids(sh.env["INSTA_PID_DIR"], "client", "worker")
        pcli, pwrk = psutil.Process(client), psutil.Process(worker)

        # make the client stop via explicit signal
        sh.sendcontrol('z')

        # verify that both the client and the worker went to sleep
        wait_for([pcli, pwrk], ['stopped'], timeout=sh.timeout)

        # verify we got "^Z" on output
        sh.expect_exact("^Z")

        # verify we're back in the shell
        sh.expect_shell_prompt()

        # resume and verify they both woke up (transitioned to 'sleeping'
        # state)
        # os.killpg(os.getpgid(client), signal.SIGCONT)
        sh.sendline("fg")
        wait_for([pcli, pwrk], ['sleeping'], timeout=sh.timeout)

        # make sure everything still works
        sh.sendline("Hello")
        sh.expect_exact("Hello\r\n> ")

        # exit the client
        sh.sendeof()
        sh.expect_exact("Done, exiting.\r\n")

@pytest.mark.parametrize("signum", [signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGKILL])
def test_intr(env, signum):
    with in_scripts_dir(), shell(env) as p:
            # spin up a client + worker
            p.sendline(f"{sys.executable} echo.py")
            p.expect_exact("> ")

            client, worker = get_pids(p.env["INSTA_PID_DIR"], "client", "worker")
            pwrk = psutil.Process(worker)

            # send the signal to the client (i.e., CTRL-C)
            os.kill(client, signum)

            # confirm the worker has exited
            wait_for(pwrk, ['terminated'], timeout=1.)

            # wait for the client to exit
            p.expect_shell_prompt()

            # pick up the exit code
            (returncode, signum) = p.last_cmd_exitstatus()

            # verify the correct signal killed the process
            assert (returncode, signum) == (None, signum)

def test_ctrl_d(env):
    # send CTRL-D to the client, and see if it will exit
    with in_scripts_dir(), shell(env) as p:
        p.sendline(f"{sys.executable} echo.py")
        p.expect_exact("> ")

        p.sendeof()
        p.expect_exact("Done, exiting.\r\n")

        p.expect_shell_prompt()

def test_reopen_tty(env):
    msg = "Hello from the tty"
    with in_scripts_dir():
        with shell(env, must_exist=False) as p:
            p.sendline("echo open stdin /dev/tty > input.tmp")
            p.expect_shell_prompt()
            try:
                os.unlink("foo.log")
            except FileNotFoundError:
                pass
            p.sendline(f"{sys.executable} rawecho.py --instastart < input.tmp > foo.log 2>&1")
            # Wait for the client to spin up fully before sending commands.
            # Otherwise they'll be discarded on tty mode change. (see docs of
            # Terminal.setraw())
            while True:
                try:
                    text = open("foo.log").read()
                    if text:
                        break
                except FileNotFoundError:
                    pass
                time.sleep(0.01)
            # check we can send a message (and that it's echoed by the tty)
            p.sendline(msg)
            p.expect(f"{msg}\r\n")

            # stop rawecho.py
            p.sendeof()
            p.expect_shell_prompt()

        # check that we have msg in the output file
        s = "> " + repr((msg + "\n").encode('utf-8'))
        with open('foo.log') as fp:
            for line in fp:
                if line == s + "\n": break
            else:
                assert False, f"'{s}' not found in output."

# TODO: tests to write
# - test running in the background
# - test window size changes
# - run w/o a tty
# - test HUP on client's tty
# - run w/o INSTA_PID_DIR set
# - test server timeout
# - test connect on already existing server
# - test incorrectly set INSTA_DISABLE variable

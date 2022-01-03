import pytest, sys, subprocess, os, contextlib, glob, time, pexpect, tempfile
from ptyprocess import PtyProcessUnicode

@contextlib.contextmanager
def in_scripts_dir():
    try:
        os.chdir("tests/scripts")
        yield
    finally:
        os.chdir("../..")

@pytest.fixture(scope="function")
def env():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    env["INSTA_TIMEOUT"] = "0"
    env["INSTA_LOG"] = os.getcwd() + "/pytest.log"
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

    with in_scripts_dir():
        with wait_all(env) as env:
            child = pexpect.spawn(f"./pidwait {script}", env=env)
            child.expect_exact('Hello world\r\n')
            if script.endswith("no"):
                child.expect_exact('Exiting\r\n')
            child.expect_exact(pexpect.EOF)
            child.close()

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
        # no instastart
        out_off = pty_run([sys.executable, "progress.py"], env, with_insta=False)

        # with instastart
        with wait_all(env) as env2:
            out_on = pty_run(["./pidwait", sys.executable, "progress.py"], env2)

        assert out_on == out_off

def test_stop_server(env):
    with in_scripts_dir():
        env_orig = env.copy()
        with wait_all(env_orig) as env:
            # spin up a simple server with a longish timeout, and exit the client
            env["INSTA_TIMEOUT"] = "100"
            p = pexpect.spawn(f"./pidwait {sys.executable} echo.py", env=env)
            p.expect_exact("> ")
            p.sendeof()
            p.expect_exact("Done, exiting.\r\n")
            p.wait()

            # verify the server is still running
            pid = int(open(f"{env['INSTA_PID_DIR']}/server.pid").read())
            os.kill(pid, 0) # this will raise an exception if the process doesn't exist
            
            # issue a stop command to the server
            with wait_all(env_orig, must_exist=['client']) as envcli:
                envcli["INSTA_CMD"] = "stop"
                out = pty_run([sys.executable, "echo.py"], env=envcli)

                # verify the client didn't spawn anything
                pidfiles = set(glob.glob(os.path.join(envcli["INSTA_PID_DIR"], "*.pid")))
                assert len(pidfiles) == 1 and pidfiles.pop().endswith('client.pid')

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
    with in_scripts_dir():
        with wait_all(env) as env:
            timeout = int(os.getenv("INSTA_TEST_PEXPECT_TIMEOUT", 1))
            if timeout <= 0: timeout = None

            # spin up a client + worker
            p = pexpect.spawn(f"./pidwait {sys.executable} echo.py", env=env, encoding='utf-8', timeout=timeout)
#            p = pexpect.spawn(f"{sys.executable} echo.py", env=env, encoding='utf-8', timeout=timeout)
            p.expect_exact("> ")

            client, worker = get_pids(env["INSTA_PID_DIR"], "client", "worker")
            pcli, pwrk = psutil.Process(client), psutil.Process(worker)
 
            # make the client stop via explicit signal
            p.sendcontrol('z')

            # verify that both the client and the worker went to sleep
            wait_for([pcli, pwrk], ['stopped'], timeout=timeout)

            # verify we got "^Z" on output
            p.expect_exact("^Z")

            # resume and verify they both woke up (transitioned to 'sleeping'
            # state)
            os.killpg(os.getpgid(client), signal.SIGCONT)
            wait_for([pcli, pwrk], ['sleeping'], timeout=timeout)

            # make sure everything still works
            p.sendline("Hello")
            p.expect_exact("Hello\r\n> ")

            # exit the client
            p.sendeof()
            p.expect_exact("Done, exiting.\r\n")
            p.expect_exact(pexpect.EOF)
            p.wait()

@pytest.mark.parametrize("signum", [signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGKILL])
def test_intr(env, signum):
    with in_scripts_dir():
        with wait_all(env) as env:
            # spin up a client + worker
            p = pexpect.spawn(f"./pidwait {sys.executable} echo.py", env=env, encoding='utf-8')
#            p = pexpect.spawn(f"{sys.executable} echo.py", env=env, encoding='utf-8')
            p.expect_exact("> ")

            client, worker = get_pids(env["INSTA_PID_DIR"], "client", "worker")
            pcli, pwrk = psutil.Process(client), psutil.Process(worker)
 
            # send the signal to the client (i.e., CTRL-C)
            os.kill(client, signum)

            # wait for the worker to exit
            wait_for(pwrk, ['terminated'], timeout=1.)

            # wait for the client to exit
            p.wait()

            # verify the correct signal killed the process
            #assert (p.exitstatus, p.signalstatus) == (None, signum)
            assert (p.exitstatus, p.signalstatus) == (128+signum, None) # see the comment in pidwait

def test_ctrl_d(env):
    with in_scripts_dir():
        with wait_all(env) as env:
            # spin up a client + worker
            p = pexpect.spawn(f"./pidwait {sys.executable} echo.py", env=env, encoding='utf-8')
            p.expect_exact("> ")

            client, worker = get_pids(env["INSTA_PID_DIR"], "client", "worker")
            pcli, pwrk = psutil.Process(client), psutil.Process(worker)

            # send CTRL-D to the client, and see if it will exit
            p.sendeof()

            p.expect_exact("Done, exiting.\r\n")
            p.wait()

def test_reopen_tty(env):
    msg = "Hello from the tty"
    with in_scripts_dir():
        with wait_all(env, must_exist=False) as env:
            cmd = f"{sys.executable} rawecho.py --instastart < <(echo open stdin /dev/tty) > foo.log 2>&1"
            p = pexpect.spawn(f'./pidwait -c "{cmd}"', env=env, encoding='utf-8')
            # Wait for the client to spin up fully before sending commands.
            # Otherwise they'll be discarded on tty mode change. (see docs of
            # Terminal.setraw())
            p.waitnoecho()
            # check we can send a message (and that it's echoed by the tty)
            p.sendline(msg)
            p.expect(f"^{msg}\r\n", timeout=1)
            # end of output
            p.sendeof()
            p.expect_exact(pexpect.EOF, timeout=1)
            assert p.before == '', "Unexpected output."
            p.wait()

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

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
    env["INSTA_TIMEOUT"] = "0.5"
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
            child = pexpect.spawn(script, env=env)
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
            out_on = pty_run([sys.executable, "progress.py"], env2)

        assert out_on == out_off

def test_stop_server(env):
    with in_scripts_dir():
        env_orig = env.copy()
        with wait_all(env_orig) as env:
            # spin up a simple server with a longish timeout, and exit the client
            env["INSTA_TIMEOUT"] = "100"
            p = pexpect.spawn(f"{sys.executable} echo.py", env=env)
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
    while time.time() - t0 < timeout:
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

    raise TimeoutError() # pragma: no cover

def find_coverage_atexit():
    class Capture:
        def __init__(self):
            self.captured = []
        def __eq__(self, other):
            self.captured.append(other)
            return False
    
    c = Capture()
    import atexit
    atexit.unregister(c)
    for fun in c.captured:
        print(fun)
        print(fun.__module__)

    for fun in c.captured:
        if fun.__module__.startswith("coverage"):
            return fun

    return None

def test_suspend_resume(env):
    def _ex1():
        print("EXIT1")

    def _ex2():
        print("EXIT2")

    import atexit
#    atexit.register(_ex1)
#    atexit.register(_ex2)
#    find_coverage_atexit()

#    atx = find_coverage_atexit()
#    atx()
#    print("Exiting")
#    os._exit(0)

    with in_scripts_dir():
        with wait_all(env) as env:
            # spin up a client + worker
            p = pexpect.spawn(f"{sys.executable} echo.py", env=env, encoding='utf-8')
            p.expect_exact("> ")

            client, worker = get_pids(env["INSTA_PID_DIR"], "client", "worker")
            pcli, pwrk = psutil.Process(client), psutil.Process(worker)
 
            # make the client stop
            os.kill(client, signal.SIGTSTP)

            # verify that both the client and the worker went to sleep
            wait_for([pcli, pwrk], ['stopped'], timeout=1.)

            # resume and verify they both woke up (transitioned to 'sleeping'
            # state)
            os.kill(client, signal.SIGCONT)
            wait_for([pcli, pwrk], ['sleeping'], timeout=1.)

            # make sure everything still works
            p.sendline("Hello")
            p.expect_exact("Hello\r\n> ")

            # exit the client
            p.sendeof()
            p.expect_exact("Done, exiting.\r\n")
            p.wait()

@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGKILL])
def test_intr(env, signum):
    with in_scripts_dir():
        with wait_all(env) as env:
            # spin up a client + worker
            p = pexpect.spawn(f"{sys.executable} echo.py", env=env, encoding='utf-8')
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
            assert (p.exitstatus, p.signalstatus) == (None, signum)

# Instastart: Speeding up Python script startup

A module to speed up command-line Python script start-up by 10x or more.

## Quick start
Take a piece of code that takes a long time to start (e.g., because it imports heavy modules) ...

```python
$ cat slow.py
import dask.distributed
import astropy
  
if __name__ == "__main__":
    print("Hello world!")

$ time python slow.py
Hello world!

real    0m2.087s
user    0m2.607s
sys     0m11.124s
```

... modify it to import `instastart`, and mark where the non-initialization code
begins with `start()` and ends with `done()`:

```python
$ cat fast.py
from instastart.auto import start, done
import dask.distributed
import astropy

if __name__ == "__main__":
    start()
    print("Hello world!")
    done()
```

to cut down(*) its startup time by 10x or more:

```bash
$ time python fast.py
Hello world!

real    0m0.098s
user    0m0.063s
sys     0m0.014s
```

(*) On second and subsequent invocations!

## Usage

Take your existing Python script, and make the following changes:

1. Import `instastart.auto` at the top of your file.
1. Add a call to `instastart.auto.start()` at the point in the file where the
   initialization code ends (usually just right after `if __name__ ==
   "__main__"` stanza)
1. Optional: add a call to `instastart.auto.done()` at the end of the file
   (this will also save you the time the Python interpreter takes to spin
   down, which can sometime be substantial)

All together, on an example:
```python
from instastart.auto import start, done
import dask.distributed
import astropy

if __name__ == "__main__":
    start()
    print("Hello world!")
    done()
```

## How it works

After the first invocation, `instastart` keeps a Python interpreter running in
the background which has completed the heavy initialization tasks (module
imports, etc.). On subsequent invocation, this intepreter is used ("forked") to
run the rest of the script code w/o having to repeat the costly initialization.
This can cut down startup times from 1-10 seconds to ~70 milliseconds. All this
is largely transparent to the user, and -- other than the module import and one
function invocsation -- the script programmer.

See the [implementation doc](docs/implementation.md) for implementation details.
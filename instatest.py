import instastart.auto

import dask.distributed as dd
#import astropy
#import vaex
import os

def func():
    pass

import time, tqdm, sys
def run_tqdm():
    for _ in tqdm.tqdm(range(20)):
        time.sleep(0.1)
    print("Out of the loop")

def run_echo():
    try:
        for line in sys.stdin:
            print("ECHO:", line, end='')
        pass
    except Exception as e:
        print("EXCEPTION", e)
        raise
    print("Exiting tqdm_echo")

if __name__ == "__main__":
    with instastart.auto.serve():
        print("Here!")
        print(f"{sys.argv=}")
        print(f"{os.getcwd()=}")
        print(f"{os.environ['PWD']=}")
        print(f"{os.environ.get('FOOBAR', None)=}")
        run_tqdm()
#       os.execl('/usr/bin/htop', 'htop')

        pass
#           os.execl("/astro/users/mjuric/lfs/bin/joe", "joe")
#           print(f"{__file__=}")
#           print("I'm here!")
    print("Left the instastart context manager!")

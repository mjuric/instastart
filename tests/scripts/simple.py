import instastart.auto
import sys, os

if __name__ == "__main__":
    if len(sys.argv) == 1:
        kwargs = {}
    elif sys.argv[1] == "yes":
        kwargs = dict(autodone=True)
    elif sys.argv[1] == "no":
        kwargs = dict(autodone=False)
    else:
        assert 0, "invalid test argument" #pragma: no cover

    with instastart.auto.serve(**kwargs):
        print("Hello world")

    # this shouldn't appear in the output if autodone=True
    print("Exiting", file=sys.stderr)

    # emulate slow shutdown
    import time
    time.sleep(0.5)

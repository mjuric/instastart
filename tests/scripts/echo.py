from instastart.auto import serve
import sys

def main():
    try:
        while True:
            data = input("> ")
            print(data)
            if data == "":
                import os
                os.write(1, b'\x04')
    except EOFError:
        print("\nDone, exiting.")

if __name__ == "__main__":
    with serve():
        main()

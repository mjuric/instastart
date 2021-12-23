from instastart.auto import serve
import sys

def main():
    try:
        while True:
            data = input("> ")
            print(data)
    except EOFError:
        print("\nDone, exiting.")

if __name__ == "__main__":
    with serve():
        main()

from instastart.auto import serve
import time
from tqdm import tqdm

def main():
    # print out a reproducible progress bar
    for _ in tqdm(range(30), bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}', miniters=1, mininterval=0):
        pass

if __name__ == "__main__":
    with serve():
        main()

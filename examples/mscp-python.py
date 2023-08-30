#!/usr/bin/env python3
"""mscp.py

An example python script running mscp
"""

import argparse
import time
import sys

from rich.progress import Progress

import mscp

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--from", dest = "fr",
                        metavar = "REMOTE", default = None,
                        help = "copy a file from this remote host")
    parser.add_argument("-t", "--to", metavar = "REMOTE", default = None,
                        help = "copy a file to this remote host")
    parser.add_argument("source", help = "path to source file to be copied")
    parser.add_argument("destination", help = "path of copy destination")

    args = parser.parse_args()

    if args.fr and args.to:
        print("-f and -t are exclusive", file = sys.stderr)
        sys.exit(1)
    elif args.fr:
        d = mscp.REMOTE2LOCAL
        remote = args.fr
    elif args.to:
        d = mscp.LOCAL2REMOTE
        remote = args.to
    else:
        print("-f or -t must be specified", file = sys.stderr)
        sys.exit(1)


    m = mscp.mscp(remote, d)
    m.connect()
    m.add_src_path(args.source)
    m.set_dst_path(args.destination)
    m.scan()
    m.start()

    total, done, finished = m.stats()
    with Progress() as progress:

        task = progress.add_task("[green]Copying...", total = total)

        while not progress.finished:
            total, done, finished = m.stats()
            progress.update(task, completed = done)
            time.sleep(0.5)

    m.join()
    m.cleanup()


if __name__ == "__main__":
    main()

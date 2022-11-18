#!/usr/bin/env python3

from os.path import dirname, basename, isfile, isdir, exists
from os import listdir
import sys

"""

This file simply implements the src_path to dst_path conversion logic
just for test. file_fill() and file_fill_recursive() in file.c
implements this logic.

"""


def recursive(src, rel_path, dst, dst_should_dir, replace_dir_name):
    
    if isfile(src):
        if dst_should_dir:
            print("{} => {}/{}{}".format(src, dst, rel_path, basename(src)))
        else:
            print("{} => {}{}".format(src, rel_path, dst))
        return
        
    # src is directory
    for f in listdir(src):
        next_src = "{}/{}".format(src, f)
        if replace_dir_name and dst_should_dir:
            next_rel_path = ""
        else:
            next_rel_path = "{}{}/".format(rel_path, basename(src))
        recursive(next_src, next_rel_path, dst, dst_should_dir, False)


def fill_dst(srclist, dst):
    dst_must_dir = len(srclist) > 1
    for src in srclist:
        dst_should_dir = isdir(src) | isdir(dst)
        replace_dir_name = not isdir(dst)
        recursive(src, "", dst, dst_should_dir | dst_must_dir, replace_dir_name)


def main():
    if (len(sys.argv) < 2):
        print("usage: {} source ... target".format(sys.argv[0]))
    fill_dst(sys.argv[1:len(sys.argv) - 1], sys.argv[len(sys.argv) - 1])

main()

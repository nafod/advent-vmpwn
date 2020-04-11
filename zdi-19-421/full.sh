#!/bin/bash
./heap.sh
sleep 5
./build.sh
sleep 1
python2 stage1.py
sleep 2
./test.sh

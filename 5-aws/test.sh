#!/usr/bin/env bash

cd cmake-build-debug
cmake ..
make clean
make
cp aws ../checker-lin

cd ../checker-lin
make -f Makefile.checker
rm aws
cd ..

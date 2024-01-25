#!/usr/bin/env bash

# Set up a Risc OS build - run from root of sz81
mkdir -p riscroot
cd riscroot
mkdir -p c
mkdir -p h
rm -f c/*
rm -f h/*
cp ../*.c c
cp ../*.h h
cd c
for v in *.c ; do mv "$v"  "$(basename "$v" .c)"; done
cd ../h
for v in *.h ; do mv "$v"  "$(basename "$v" .h)"; done
cd ..
cp -r ../RiscOS/* .
mkdir -p data
cp ../data/* data
cd zxpand
mkdir -p cpp
mkdir -p h
rm -f cpp/*
rm -f h/*
cp ../../zxpand/*.cpp cpp
cp ../../zxpand/*.h h
cd cpp
for v in *.cpp ; do mv "$v"  "$(basename "$v" .cpp)"; done
cd ../h
for v in *.h ; do mv "$v"  "$(basename "$v" .h)"; done
cd ../../sndrender
mkdir -p cpp
mkdir -p h
rm -f cpp/*
rm -f h/*
cp ../../sndrender/*.cpp cpp
cp ../../sndrender/*.h h
cd cpp
for v in *.cpp ; do mv "$v"  "$(basename "$v" .cpp)"; done
cd ../h
for v in *.h ; do mv "$v"  "$(basename "$v" .h)"; done
cd ../..
mkdir -p z80
cd z80
mkdir -p c
mkdir -p h
rm -f c/*
rm -f h/*
cp ../../z80/*.c c
cp ../../z80/*.h h
cd c
for v in *.c ; do mv "$v"  "$(basename "$v" .c)"; done
cd ../h
for v in *.h ; do mv "$v"  "$(basename "$v" .h)"; done


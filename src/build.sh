#!/bin/bash
cd "$(dirname "$0")"
[ -d mimalloc ] || git clone -b v2.1.7 --depth 1 https://github.com/microsoft/mimalloc
mkdir -p ../lib
x86_64-w64-mingw32-gcc -O2 -s -shared -static -static-libgcc -Imimalloc/include -DNDEBUG -DMI_SECURE=0 -DMI_DEBUG=0 -Wno-stringop-overflow -include tebslot.h -o ../lib/LinuxFixes.dll LinuxFixes.c mimalloc/src/static.c

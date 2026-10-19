# Sources

## VxHunter

The symbol-table recovery in this project is modeled on VxHunter, a VxWorks
reverse-engineering toolset by PAGalaxyLab.

- Repository: https://github.com/PAGalaxyLab/vxhunter
- License: BSD-2-Clause

VxHunter established the technique this project reimplements from scratch:

- VxWorks firmware holds a contiguous array of fixed-size symbol-table entries
  dumped from memory, with absolute name and value pointers and a one-byte type.
- The load address is unknown and is recovered by relating the entry name
  pointers to the file offsets of the name strings.
- The classic entry shapes are the VxWorks 5.x 16-byte entry and the 6.x
  20-byte entry, with the name field after a leading hash-chain pointer.
- The symbol-type byte uses a small set of values for text, data, bss, absolute
  and common, with a global flag bit.

This project does not vendor, copy, or link any VxHunter code. It is an
independent Rust implementation of the published idea. All tables are embedded
constants built from Wind River and VxWorks internal symbol names only, with no
device-vendor names.

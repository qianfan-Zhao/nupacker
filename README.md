nupacker
========

A tool for packing all images to [nuwriter](https://github.com/OpenNuvoton/NUC970_NuWriter) format.

Usage:

```
nupacker -i pack.bin: Show packed image's information
nupacker -ddr which_dir/ddr.ini
 -spl which_dir/u-boot-spl.bin@0,exec=0x200
 [-data which_dir/u-boot.bin@0x100000]
 [-data which_dir/uImage_dtb.bin@0x200000]
 [-data which_dir/rootfs.ubi@0x800000]
 -o which_dir/pack.bin: Pack images
nupacker -e which_dir/pack.bin [-O dir]: Extract packed image
nupacket -t ddr.ini [-o ddr.bin]:
nupacket -t ddr.bin [-o ddr.ini]:
  Translate ddr configuration between ini and bin
  Write translated data to stdout default
VERSION: 1.01
```

Example 1: Create a packed image:

```
$ nupacker -spl u-boot-spl.bin@0,exec=0x200 \
		-ddr nuc972_ddr.ini \
		-data u-boot.bin@0x100000 \
		-data kernel.bin@0x200000 \
		-data rootfs.bin@0x800000 -o xxx.pack.bin
```

Example 2: Unpack

```
$ ./nupacker -E 20190703.bin -O raw
Found DDR configures, size = 384
Found SPL  @ 0x00000000, exec = 0x00000200, size = 17436
Found DATA @ 0x00100000, size = 395200
Found DATA @ 0x00200000, size = 2289987
Found DATA @ 0x00500000, size = 2289987
Found DATA @ 0x00800000, size = 12058624

$ ls raw -l
total 16668
-rw-rw-r-- 1 xxx xxxx    17436 7月  29 16:37 0x0.bin
-rw-rw-r-- 1 xxx xxxx   395200 7月  29 16:37 0x100000.bin
-rw-rw-r-- 1 xxx xxxx  2289987 7月  29 16:37 0x200000.bin
-rw-rw-r-- 1 xxx xxxx  2289987 7月  29 16:37 0x500000.bin
-rw-rw-r-- 1 xxx xxxx 12058624 7月  29 16:37 0x800000.bin
-rw-rw-r-- 1 xxx xxxx      384 7月  29 16:37 ddr.bin
```

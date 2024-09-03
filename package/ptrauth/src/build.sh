#!/bin/sh

CC_PATH=../../../output/host/bin/aarch64-buildroot-linux-gnu-gcc
LD_PATH=../../../output/host/bin/aarch64-buildroot-linux-gnu-ld

make CC=$CC_PATH LD=$LD_PATH ARCH=arm64

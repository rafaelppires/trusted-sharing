## Process this file with automake to generate Makefile.in

# Copyright 2001, 2002, 2010 Free Software Foundation, Inc.
#
#  This file is part of the GNU MP Library.
#
#  The GNU MP Library is free software; you can redistribute it and/or modify
#  it under the terms of either:
#
#    * the GNU Lesser General Public License as published by the Free
#      Software Foundation; either version 3 of the License, or (at your
#      option) any later version.
#
#  or
#
#    * the GNU General Public License as published by the Free Software
#      Foundation; either version 2 of the License, or (at your option) any
#      later version.
#
#  or both in parallel, as here.
#
#  The GNU MP Library is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
#  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
#  for more details.
#
#  You should have received copies of the GNU General Public License and the
#  GNU Lesser General Public License along with the GNU MP Library.  If not,
#  see https://www.gnu.org/licenses/.


AM_CPPFLAGS = -D__GMP_WITHIN_GMP -I$(top_srcdir)

if SGXENABLED
AM_CPPFLAGS += -DENCLAVED -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin-printf -Wno-implicit-function-declaration -I$(SGXSDKPATH)/include -I$(SGXSDKPATH)/include/tlibc -I$(SGXCOMMONPATH) -I$(SGXCOMMONPATH)/enclave_include/
endif

noinst_LTLIBRARIES = librandom.la

librandom_la_SOURCES = randmt.h						\
  rand.c randclr.c randdef.c randiset.c randlc2s.c randlc2x.c randmt.c	\
  randmts.c rands.c randsd.c randsdui.c randbui.c randmui.c

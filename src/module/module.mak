
#__FUZZ_PROCS__=1

SRC_PATH = $(IDA)module/
BIN_PATH = $(R)procs/

BASE_OBJS += $(F)ana$(O)
BASE_OBJS += $(F)emu$(O)
BASE_OBJS += $(F)ins$(O)
BASE_OBJS += $(F)out$(O)
BASE_OBJS += $(F)reg$(O)

ifdef __NT__
  DLLFLAGS += /BASE:0x130000000
endif

# IDA Home edition has processor modules linked into the kernel
ifdef IDAHOME
  BUILD_STATIC_LIBRARY = 1
endif

include ../../module.mak

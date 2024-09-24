
__FUZZ_LOADERS__=1

SRC_PATH = $(IDA)ldr/
BIN_PATH = $(R)loaders/

BASE_OBJS += $(F)$(PROC)$(O)

ifdef __NT__
  DLLFLAGS += /BASE:0x140000000
endif

CC_DEFS += LOADER_COMPILE

include ../../module.mak

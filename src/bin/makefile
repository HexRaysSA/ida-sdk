include ../allmake.mak

GOALS += bats
.PHONY: $(GOALS)
all: $(GOALS)

ifdef __NT__
  CYGWINVER=$(subst ., ,$(shell uname -r))
  CYGWINVER_MAJOR=$(word 1,$(CYGWINVER))
  CYGWINVER_MINOR=$(word 2,$(CYGWINVER))
  ifeq ($(CYGWINVER_MAJOR),3)
    ifeq ($(CYGWINVER_MINOR),5)
      $(warning ***This version is unstable and may cause the build to fail!***)
    endif
  endif
endif
#######################################################################
# .bat files

ifdef __NT__
  BATS += $(RS)cl32.bat
  BATS += $(RS)cl64.bat
endif
bats: $(BATS)

# the following functions accept the path to main VS dir $(MSVC_PATH).
VCLIB=$(1)/lib/$(2);$(LIB_UCRT)/$(2);$(LIB_UM)/$(2)
VCINC=$(1)/Include;$(INCLUDE_UCRT);$(INCLUDE_UM);$(INCLUDE_SHARED)

#----------------------------------------------------------------------
define CL32_BAT
@echo off
setlocal
set MSVC_PATH=$(MSVC_PATH)
set LIB=$(call VCLIB,%MSVC_PATH%,x86)
set INCLUDE=$(call VCINC,%MSVC_PATH%)
set PATH=$(MSVC_BIN-X86);$(SDK_BIN);%PATH%
cl.exe %*
endef
$(RS)cl32.bat: makefile ../allmake.mak ../defaults.mk
	@echo -e '$(subst $(newline),\n,$(CL32_BAT))' >$@
	@chmod +x $@

#----------------------------------------------------------------------
define CL64_BAT
@echo off
setlocal
set MSVC_PATH=$(MSVC_PATH)
set LIB=$(call VCLIB,%MSVC_PATH%,x64)
set INCLUDE=$(call VCINC,%MSVC_PATH%)
set PATH=$(MSVC_BIN-X64);$(SDK_BIN);%PATH%
cl.exe %*
endef
$(RS)cl64.bat: makefile ../allmake.mak ../defaults.mk
	@echo -e '$(subst $(newline),\n,$(CL64_BAT))' >$@
	@chmod +x $@


include allmake.mak

.PHONY: env alldirs
all: env alldirs

#----------------------------------------------------------------------
ifdef __NT__
  ENV += env_vc
endif
env: $(ENV)

env_vc:
	$(Q)$(MAKE) -f makeenv_vc.mak
	$(Q)$(MAKE) -C bin

#----------------------------------------------------------------------
ifdef BUILD_IDA
  ALLDIRS += ldr
  ALLDIRS += module
  ALLDIRS += plugins
  ALLDIRS += idalib/examples
endif
ALLDIRS += dbg
alldirs: $(ALLDIRS)

$(ALLDIRS): env
	$(MAKE) -C $@

#----------------------------------------------------------------------
CLEAN_BIN_FILES += *.cfg
CLEAN_BIN_FILES += *.dll
CLEAN_BIN_FILES += *.dylib
CLEAN_BIN_FILES += *.idc
CLEAN_BIN_FILES += *.py
CLEAN_BIN_FILES += *.so
clean::
	find . -depth -type d -name "obj" -execdir rm -rf "{}" \;
	find . -maxdepth 1 -type f -name '*.cfg*' -delete
	find bin -type f \( -name $(subst $(space), -o -name ,$(patsubst %,"%",$(CLEAN_BIN_FILES))) \) -delete

build-all-opt:
ifdef __NT__
	mo.bat   -s $(MAKEFLAGS)
	mmo.bat  -s $(MAKEFLAGS)
	mso.bat  -s $(MAKEFLAGS)
	mmso.bat -s $(MAKEFLAGS)
else
	$(MAKE) -s NDEBUG=1 __EA64__=  __X64__=1
	$(MAKE) -s NDEBUG=1 __EA64__=1 __X64__=1
endif

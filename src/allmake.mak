#
#       Common part of make files for IDA.
#

ifndef __EA32__
  __EA64__:=1
else
  __EA32__?=1
endif

# find directory of allmake.mak:
IDA:=$(dir $(lastword $(MAKEFILE_LIST)))

# define the version number we are building
IDAVER_MAJOR:=9
IDAVER_MINOR:=0
# 900
IDAVERDECIMAL:=$(IDAVER_MAJOR)$(IDAVER_MINOR)0
# 9.0
IDAVERDOTTED:=$(IDAVER_MAJOR).$(IDAVER_MINOR)

# if no targets are defined, default to host OS
ifeq ($(or $(__ANDROID__),$(__ANDROID_X86__),$(__ARMLINUX__),$(__LINUX__),$(__MAC__),$(__NT__)),)
  ifeq ($(OS),Windows_NT)
    __NT__=1
  else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
      __LINUX__=1
    endif
    ifeq ($(UNAME_S),Darwin)
      __MAC__=1
    endif
  endif
endif

# only one build target may be defined
ifneq ($(__ANDROID__)$(__ANDROID_X86__)$(__ARMLINUX__)$(__LINUX__)$(__MAC__)$(__NT__),1)
  $(error Only one build target may be defined (__ANDROID__, __ANDROID_X86__, __ARMLINUX__, __LINUX__, __MAC__, or __NT__))
endif

# detect build configuration
# Note: will set one of M, M32, M32H, MX86, MO, M32O, M32HO, MX86O, MSO, M32SO, or MX86SO
# These should match the aliases defined in tools/*/env
BUILD_CONFIG-1                     := M
BUILD_CONFIG-$(__EA32__)           += 32
BUILD_CONFIG-$(__X86__)            += X86
BUILD_CONFIG-$(USE_STATIC_RUNTIME) += S
BUILD_CONFIG-$(IDAHOME)            += H
BUILD_CONFIG-$(NDEBUG)             += O
empty :=
space := $(empty) $(empty)
comma := ,
BUILD_CONFIG := $(subst $(space),,$(BUILD_CONFIG-1))
$(BUILD_CONFIG) := 1

# definition of a single \n character (empty lines are important!)
define newline


endef


# pick up mac architecture using `arch`
ifdef __MAC__
  ARCH_OUTPUT := $(shell arch)
  ifeq ($(ARCH_OUTPUT),arm64)
    __ARM__=1
  endif
endif

# support arm64 macOS11 builds
ifeq ($(and $(__MAC__),$(__ARM__)),1)
  ifdef __X86__
    $(error 32-bit ARM builds are not supported on mac.)
  endif
  # create a shortcut for convenience
  __APPLE_SILICON__=1
endif


ifdef __ARM__
  PROCDEF = __ARM__
  TARGET_PROCESSOR_NAME-1=arm
  TARGET_PROCESSOR_NAME-$(__MAC__)=arm64
  TARGET_PROCESSOR_NAME-$(__LINUX__)=arm64
  ifeq ($(__EA64__),1)
    TARGET_PROCESSOR_NAME-1=arm64
  endif
  TARGET_PROCESSOR_NAME=$(TARGET_PROCESSOR_NAME-1)
else ifndef __X86__
  ARCH_FLAGS = -m64
  TARGET_PROCESSOR_NAME=x64
else
  ARCH_FLAGS = -m32
  TARGET_PROCESSOR_NAME=x86
endif

# define some variables to simplify build system
ifndef __X86__
  __X64__ = 1
  ifndef __EA64__
    __X32__ = 1
  endif
endif
ifndef __NT__
  __UNIX__ = 1
endif

ifndef IDAHOME
  IDAADV = 1
endif

ifdef __LINUX__
  ifeq ($(COMPILER_NAME),clang)
    # experimental support
    CLANG_ON_LINUX := 1
  endif
endif

# define SYSNAME
SYSNAME-$(__LINUX__)       = linux
SYSNAME-$(__MAC__)         = mac
SYSNAME-$(__NT__)          = win
SYSNAME = $(SYSNAME-1)

# path functions (depending on host OS)
ifeq ($(OS),Windows_NT)
  # define: convert unix path to dos path by replacing slashes by backslashes
  dospath=$(subst /,\\,$(1))
else
  # define: dospath does not do anything in unix
  dospath=$(1)
endif
# define: return 1 if path exists, 0 otherwise
ls=$(if $(wildcard $(1)),1,0)

# define: logical negation
not = $(if $(1),,1)

include $(IDA)defaults.mk

#############################################################################
ifdef __NT__
  ifeq ($(COMPILER_NAME),clang)
    MSVC_PATH=$(VCINSTALLDIR)Tools\Llvm\x64\\#
  else
    COMPILER_NAME=vc

    # Visual C++ Toolchain and Windows SDK paths
    # Note: see comments in defaults.mk for more information about these
    #       variables.

    # This function searches for a specified path, converts it to a 8.3
    # path with forward slashes as separator, and exports it as an
    # environment variable. This way, subcalls to make do not need to
    # call $(shell) again.
    define require_path
      $$(if $(strip $$($(1))),,$$(eval $(1):=$$(subst \,/,$$(shell cygpath -d $(2) 2>/dev/null))))
      $$(if $(strip $$($(1))),,$$(error Could not find $(3) in $(2)$$(newline)*** See defaults.mk and "Visual C++ Toolchain and Windows SDK paths" in allmake.mak))
      $$(eval export $(1))
    endef

    # This function fixes variables imported from defaults.mk/vcvars.bat
    # by ensuring that they are surrounded by quotes and by removing the
    # trailing backslash.
    fix_var=$(1):='$$(patsubst %\,%,$$(patsubst '%,%,$$(patsubst %',%,$$(patsubst "%,%,$$(patsubst %",%,$$($(1)))))))'

    # Note: these cfg files are created in makeenv_vc.mak
    ifdef __XPCOMPAT__
      -include $(IDA)vs19paths_xp.cfg
    else
      -include $(IDA)vs19paths.cfg
    endif

    # Visual C++ 2019 Install Directory
    ifndef MSVC_ROOT
      ifneq (,$(findstring Microsoft$(space)Visual$(space)Studio$(space),$(VCINSTALLDIR)))
        ifeq (,$(findstring 2019,$(VCINSTALLDIR)))
          $(error Please check your system environment variable VCInstallDir [$(VCINSTALLDIR)].$(newline)It seems to be pointing to an old version of Visual Studio (and not version 2019).$(newline)You may override it in defaults.mk.)
        endif
      endif
      $(eval $(call fix_var,VCINSTALLDIR))
      $(eval $(call require_path,MSVC_ROOT,$(VCINSTALLDIR),Visual C++ 2019 Install Directory))
      export MSVC_ROOT
    endif

    # Visual C++ 2019 Tools Version
    ifndef MSVC_TOOLSVER
      ifndef VCToolsVersion
        # Try to obtain version from Microsoft.VCToolsVersion.default.txt
        MSVC_TOOLSVER_PATH = $(MSVC_ROOT)/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt
        VCToolsVersion := $(shell cat $(MSVC_TOOLSVER_PATH) 2> /dev/null)
        ifeq (,$(VCToolsVersion))
          # If that failed, try to detect latest version from the directory names
          VCToolsVersion := $(notdir $(lastword $(sort $(wildcard $(MSVC_ROOT)/Tools/MSVC/14.*))))
        endif
        ifeq (,$(VCToolsVersion))
          $(error Could not find Visual C++ 2019 Tools Version in $(MSVC_TOOLSVER_PATH))
        endif
      endif
      $(eval $(call fix_var,VCToolsVersion))
      MSVC_TOOLSVER := $(VCToolsVersion)
      export MSVC_TOOLSVER
    endif

    # Final Visual C++ 2019 Tools path
    $(eval $(call require_path,MSVC_PATH,$(MSVC_ROOT)/Tools/MSVC/$(MSVC_TOOLSVER),Visual C++ 2019 Tools))

    MSVC_BIN-X86 ?= $(MSVC_PATH)/bin/HostX86/x86
    MSVC_BIN-X64 ?= $(MSVC_PATH)/bin/HostX64/x64
    ifdef __X86__
      MSVC_BIN ?= $(MSVC_BIN-X86)
    else
      MSVC_BIN ?= $(MSVC_BIN-X64)
    endif
    MSVC_INCLUDE ?= $(MSVC_PATH)/Include

    # Windows SDK Install Directory
    ifndef WSDK_PATH
      $(eval $(call fix_var,WindowsSdkDir))
      $(eval $(call require_path,WSDK_PATH,$(WindowsSdkDir),Windows SDK Install Directory))
      export WSDK_PATH
    endif

    # Windows SDK Version
    ifndef WSDK_VER
      ifndef WindowsSDKVersion
        # Detect the latest version of the Windows SDK
        WSDK_VER_PATH = $(WSDK_PATH)/Include/10.*
        WindowsSDKVersion := $(notdir $(lastword $(sort $(wildcard $(WSDK_VER_PATH)))))
        ifeq (,$(WindowsSDKVersion))
          $(error Could not find Windows SDK Version in $(WSDK_VER_PATH))
        endif
      endif
      $(eval $(call fix_var,WindowsSDKVersion))
      WSDK_VER := $(WindowsSDKVersion)
      export WSDK_VER
    endif

    # Windows SDK Include/Lib paths
    INCLUDE_UCRT_PATH ?= $(WSDK_PATH)/Include/$(WSDK_VER)/ucrt
    LIB_UCRT_PATH ?= $(WSDK_PATH)/Lib/$(WSDK_VER)/ucrt
    $(eval $(call require_path,INCLUDE_UCRT,$(INCLUDE_UCRT_PATH),Windows SDK Include/ucrt))
    $(eval $(call require_path,LIB_UCRT,$(LIB_UCRT_PATH),Windows SDK Lib/ucrt))

    ifdef __XPCOMPAT__
      $(eval $(call require_path,INCLUDE_MSSDK71,$(MSSDK71_PATH)/Include,Microsoft SDK Include))
      $(eval $(call require_path,LIB_MSSDK71,$(MSSDK71_PATH)/Lib,Microsoft SDK Lib))
      $(eval $(call require_path,SDK_BIN,$(MSSDK71_PATH)/Bin,Microsoft SDK Bin))
    else
      INCLUDE_SHARED_PATH ?= $(WSDK_PATH)/Include/$(WSDK_VER)/shared
      INCLUDE_UM_PATH ?= $(WSDK_PATH)/Include/$(WSDK_VER)/um
      LIB_UM_PATH ?= $(WSDK_PATH)/Lib/$(WSDK_VER)/um
      SDK_BIN_PATH ?= $(WSDK_PATH)/Bin/$(WSDK_VER)/

      $(eval $(call require_path,INCLUDE_SHARED,$(INCLUDE_SHARED_PATH),Windows SDK Include/shared))
      $(eval $(call require_path,INCLUDE_UM,$(INCLUDE_UM_PATH),Windows SDK Include/um))
      $(eval $(call require_path,LIB_UM,$(LIB_UM_PATH),Windows SDK Lib/um))
      $(eval $(call require_path,SDK_BIN,$(SDK_BIN_PATH),Windows SDK Bin))
    endif

    # Export INCLUDE as an environment variable so it may be used by cl.
    ifndef INCLUDE
      ifdef __XPCOMPAT__
        INCLUDE = $(MSVC_INCLUDE);$(INCLUDE_UCRT);$(INCLUDE_MSSDK71)
      else
        INCLUDE = $(MSVC_INCLUDE);$(INCLUDE_UCRT);$(INCLUDE_UM);$(INCLUDE_SHARED)
      endif
      export INCLUDE
    endif

    # Export LIB as an environment variable so it may be used by cl/link.
    ifndef LIB
      ifdef __XPCOMPAT__
        ifdef __X86__
          LIB = $(MSVC_PATH)/lib/x86;$(LIB_UCRT)/x86;$(LIB_MSSDK71)
        else
          LIB = $(MSVC_PATH)/lib/x64;$(LIB_UCRT)/x64;$(LIB_MSSDK71)/x64
        endif
      else
        ifdef __X86__
          LIB = $(MSVC_PATH)/lib/x86;$(LIB_UCRT)/x86;$(LIB_UM)/x86
        else
          LIB = $(MSVC_PATH)/lib/x64;$(LIB_UCRT)/x64;$(LIB_UM)/x64
        endif
      endif
      export LIB
    endif

    # If a Visual Studio Command Prompt is used, make sure the target
    # architecture is correct.
    ifdef VSCMD_ARG_TGT_ARCH
      ifneq ($(VSCMD_ARG_TGT_ARCH),$(TARGET_PROCESSOR_NAME))
        ifdef __X86__
          EXPECTED_ARCH = x86
        else
          EXPECTED_ARCH = x64
        endif
        LOWERCASE_BUILD_CONFIG := $(subst M,m,$(subst S,s,$(subst O,o,$(BUILD_CONFIG))))
        $(error Please use the correct Visual Studio Command Prompt for the target architecture$(newline)*** The target architecture for '$(LOWERCASE_BUILD_CONFIG)' is $(EXPECTED_ARCH), and the architecture for the current Visual Studio Command Prompt is $(VSCMD_ARG_TGT_ARCH)))
      endif
    endif
  endif
#############################################################################
else ifdef __LINUX__
  ifdef CLANG_ON_LINUX
    COMPILER_NAME := clang
  else
    COMPILER_NAME := gcc
  endif
  PTHR_SWITCH=-pthread
  STDLIBS += -lrt -lpthread -lc -ldl
  ARCH_FLAGS-$(__ARM__) = -D__arm64__ -Wno-narrowing
  ARCH_FLAGS += $(ARCH_FLAGS-1)
#############################################################################
else ifdef __MAC__
  COMPILER_NAME=clang
  STDLIBS += -lpthread -liconv
  ARCH_FLAGS-$(__X64__) = -arch x86_64
  ARCH_FLAGS-$(__X86__) = -arch i386
  ARCH_FLAGS-$(__ARM__) = -arch arm64
  ARCH_FLAGS += $(ARCH_FLAGS-1)
  # The following value is defined in defaults.mk.
  ARCH_FLAGS += -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
  ifndef MACSDK
    MACSDK := $(shell /usr/bin/xcrun --sdk macosx --show-sdk-path)
    ifeq ($(MACSDK),)
      $(error Could not find MacOSX SDK)
    endif
    export MACSDK
  endif
  ARCH_FLAGS += -isysroot $(MACSDK)
endif

#############################################################################
# toolchain-specific variables

ifneq (,$(filter $(COMPILER_NAME),gcc clang))
  # file extensions
  A     = .a
  B     = $(SUFF32)
  O     = .o
  II    = .i
  # toolchain output switches
  OBJSW = -o # with space
  OUTAR =
  OUTII = -o # with space
  OUTSW = -o # with space
  ifdef __MAC__
    OUTMAP = -Wl,-map,
  else
    OUTMAP = -Wl,-Map,
  endif
  # misc switches
  AROPT = rc
  CPPONLY = -E
  FORCEC = -xc
  NORTTI = -fno-rtti
  ifdef __MAC__
    OUTDLL = -dynamiclib
  else
    OUTDLL = --shared
  endif
  # utilities
  CCACHE-$(USE_CCACHE) = ccache
  ifeq ($(COMPILER_NAME),clang)
    _CC  ?= clang
    _CXX ?= clang++
  else
    _CC  ?= gcc
    _CXX ?= g++
    ifdef USE_GOLD
      GOLD = -fuse-ld=gold
    endif
    ifdef USE_MOLD
      MOLD = -fuse-ld=mold
    endif
  endif
  AR  =             $(CROSS_PREFIX)ar$(HOST_EXE) $(AROPT)
  CC  = $(CCACHE-1) $(CROSS_PREFIX)$(_CC)$(HOST_EXE) $(ARCH_FLAGS)
  #+CCL =        $(CROSS_PREFIX)$(_CXX)$(HOST_EXE) $(ARCH_FLAGS) $(GOLD)
  CCL_REAL =        $(CROSS_PREFIX)$(_CXX)$(HOST_EXE) $(ARCH_FLAGS) $(GOLD) $(MOLD)
  CCL = $(CCL_REAL)
  CXX = $(CCACHE-1) $(CROSS_PREFIX)$(_CXX)$(HOST_EXE) $(ARCH_FLAGS)
else ifeq ($(COMPILER_NAME),vc)
  # file extensions
  A     = .lib
  B     = $(SUFF32).exe
  O     = .obj
  II    = .i
  # toolchain output switches
  OBJSW = /Fo
  OUTAR = /OUT:
  OUTII = /Fi
  OUTSW = /OUT:
  OUTMAP = /map:
  # misc switches
  CPPONLY = /P
  FORCEC = /TC
  NOLOGO = /nologo
  NORTTI = /GR-
  OUTDLL = /DLL
  # utilities
  AR  = $(MSVC_BIN)/lib.exe $(NOLOGO)
  CC  = $(MSVC_BIN)/cl.exe $(NOLOGO)
  CCL = $(MSVC_BIN)/link.exe $(NOLOGO)
  CXX = $(CC)
endif

##############################################################################
# target-specific cflags/ldflags
ifneq (,$(filter $(COMPILER_NAME),gcc clang))

  # system cflags
  CC_DEFS += $(PROCDEF)
  ifdef __MAC__
    CC_DEFS += __MAC__
  else
    CC_DEFS += __LINUX__
  endif

  ifdef __APPLE_SILICON__
    CC_DEFS += __APPLE_SILICON__
  endif

  # pic-related flags
  # Note: this variable may be overridden in other parts of the build
  PIC = -fPIC

  ifdef __MAC__
    LDPIE = $(PIC) -Wl,-pie
  else ifdef CLANG_ON_LINUX
    LDPIE = $(PIC) -Wl,-pie
  else
    LDPIE = $(PIC) -pie
  endif

  # common cflags
  CC_DEFS += $(EASIZE_DEF)
  CC_DEFS += $(DEFX86)

  CC_F += $(PIC)
  CC_F += -fdiagnostics-show-option
  CC_F += -fno-strict-aliasing
  CC_F += -fvisibility=hidden
  CC_F += -fwrapv
  ifneq ($(COMPILER_NAME),clang)
    CC_F += -fno-delete-null-pointer-checks
  endif

  CC_INCP += $(I)

  CC_W += -Wall
  CC_W += -Wextra
  CC_W += -Wformat=2
  CC_W += -Werror=format-security
  CC_W += -Werror=format-nonliteral
  CC_W += -Wshadow
  CC_W += -Wunused

  CC_WNO += -Wno-format-y2k
  CC_WNO += -Wno-missing-field-initializers
  CC_WNO += -Wno-sign-compare

  CC_X += -g
  CC_X += -pipe

  # enable c++11
  CXXSTD = -std=c++11

  CXX_F += -fvisibility-inlines-hidden
  CXX_WNO += -Wno-invalid-offsetof

  # system-specific cflags
  ifeq ($(COMPILER_NAME),clang) # mac/android
    # 'cc -dumpversion' always reports 4.2.1 for clang
    # https://stackoverflow.com/questions/12893731/why-does-clang-dumpversion-report-4-2-1

    # clang is extra picky - need to add some warning supressions
    # must eventually get rid of most of these
    CC_WNO += -Wno-char-subscripts
    CC_WNO += -Wno-dynamic-class-memaccess
    CC_WNO += -Wno-int-to-pointer-cast
    CC_WNO += -Wno-invalid-source-encoding
    CC_WNO += -Wno-logical-not-parentheses
    CC_WNO += -Wno-logical-op-parentheses
    CC_WNO += -Wno-null-conversion
    CC_WNO += -Wno-nullability-completeness
    CC_WNO += -Wno-parentheses-equality
    CC_WNO += -Wno-self-assign
    CC_WNO += -Wno-unused-const-variable
    CC_WNO += -Wno-unused-function
    CC_WNO += -Wno-unused-private-field
    CC_WNO += -Wno-unused-variable
    CC_WNO += -Wno-varargs

    CC_F += -fno-caret-diagnostics
  else # (arm)linux

    # get gcc version
    ifndef _GCC_VERSION
      _GCC_VERSION:=$(wordlist 1,2,$(subst ., ,$(shell $(CC) -dumpversion)))
      export _GCC_VERSION
    endif
    GCC_VERSION=$(firstword $(_GCC_VERSION)).$(lastword $(_GCC_VERSION))

    ifeq ($(GCC_GTE_80),)
      GCC_GTE_80 := $(shell [ $(firstword $(_GCC_VERSION)) -gt 7 ] && echo 1)
      export GCC_GTE_80
    endif

    CXX11_ABI=0
    ifdef __LINUX__
      ifdef __APPLE_SILICON__
        CXX11_ABI=1
      endif
    endif
    CC_DEFS += _GLIBCXX_USE_CXX11_ABI=$(CXX11_ABI)
    CC_W    += -Wimplicit-fallthrough=0
    CC_WNO  += -Wno-unused-local-typedefs
    CC_WNO  += -Wno-parentheses
    CC_F    += -fno-diagnostics-show-caret

    ifeq ($(GCC_GTE_80),1)
      CXX_WNO += -Wno-class-memaccess
    endif

    # suppress warning about ABI change in GCC 4.4
    CC_WNO-$(__ARMLINUX__) += -Wno-psabi
  endif

  # optimization cflags
  ifdef NDEBUG
    CC_F += -fdata-sections
    CC_F += -ffunction-sections
    ifndef __ASAN__
      ifndef __MAC__
        # Apple platforms don't seem to have entirely robust support for
        # frame pointer omission. Pushing the compiler to omit frame pointers
        # can lead to (compact) unwind info that crashes libunwind.
        CC_F += -fomit-frame-pointer
      endif
    endif
    # stack protector
    ifdef __TARGET_MAC_HOST_LINUX__
      # disable stack protector for our osxcross toolchain (we check
      # against __TARGET_MAC_HOST_LINUX__ since it is hard to check
      # for version number in clang).
    else
      CC_F += -fstack-protector-strong
    endif
    CC_DEFS += NDEBUG
    CC_DEFS += _FORTIFY_SOURCE=2
  else
    CC_DEFS += _DEBUG
  endif

  # system-specific ldflags
  ifdef __LINUX__
    LDFLAGS += -Wl,--build-id
    LDFLAGS += -Wl,--gc-sections
    LDFLAGS += -Wl,--warn-shared-textrel

    NO_UNDEFS ?= -Wl,--no-undefined
    DLL_W += $(NO_UNDEFS)
  else ifdef __MAC__
    LDFLAGS += -Wl,-dead_strip

    ifndef __TARGET_MAC_HOST_LINUX__
      DLL_X += -compatibility_version 1.0
      DLL_X += -current_version 1.0
    endif
  endif

  # common linker/compiler flags
  ifdef NDEBUG
    CCOPT += -O2
    ifdef __LINUX__
      LDOPT += -Wl,-O1
    endif
  endif

  # AddressSanitizer flags
  ifdef __ASAN__
    CC_DEFS += __ASAN__
    CC_F += -fno-omit-frame-pointer
    CC_F += -fsanitize=address
    LDFLAGS += -fsanitize=address
    export LSAN_OPTIONS=suppressions=$(IDA)etc/bin/known_leaks.txt:detect_leaks=0
  endif

  # final compiler flags
  CC_F += $(CC_F-1)
  CC_W += $(CC_W-1)
  CC_WNO += $(CC_WNO-1)
  CXX_WNO += $(CXX_WNO-1)
  CC_DEFS += $(CC_DEFS-1)
  CC_INCP += $(CC_INCP-1)
  CC_D += $(addprefix -D,$(CC_DEFS))
  CC_I += $(addprefix -I,$(CC_INCP))

  # the -Wno-* flags must come after the -W enabling flags
  WARNS = $(sort $(CC_W)) $(sort $(CC_WNO))

  CFLAGS += $(sort $(CC_X))
  CFLAGS += $(CCOPT)
  CFLAGS += $(sort $(CC_I))
  CFLAGS += $(sort $(CC_D))
  CFLAGS += $(sort $(CC_F))
  CFLAGS += $(WARNS)
  CFLAGS += $(PTHR_SWITCH)

  # for warning suppression, override the WARNS variable with NOWARNS:
  # $(TARGET): WARNS = $(NOWARNS)
  NOWARNS = -w

  # dll linker flags
  DLLFLAGS += $(DLL_W) $(DLL_X)

else ifeq ($(COMPILER_NAME),vc)
  # for warning suppression, override the WARNS variable with NOWARNS:
  # $(TARGET): WARNS = $(NOWARNS)
  NOWARNS = -w -wd4702 -wd4738

  # optimization ldflags
  LDOPT += /DEBUG
  ifdef NDEBUG
    LDOPT += /INCREMENTAL:NO /OPT:ICF /OPT:REF
  endif

  # set c runtime to use
  ifdef NDEBUG
    ifdef USE_STATIC_RUNTIME
      RUNTIME_LIBSW = /MT
    else
      RUNTIME_LIBSW = /MD
    endif
  else
    ifdef USE_STATIC_RUNTIME
      RUNTIME_LIBSW = /MTd
    else
      RUNTIME_LIBSW = /MDd
    endif
  endif

  # PDB options
  PDBFLAGS = /PDB:$(PDBDIR)/
  ifdef NDEBUG
    PDBFLAGS += /PDBALTPATH:%_PDB%
  endif
  # Generate debug info
  PDBFORMAT =
  # by default, use obj directory for common pdb file
  # /Z7 (embed into .obj)
  CLPDB = /Z7 /Fd$(F)

  # AddressSanitizer flags
  ifdef __ASAN__
    CC_DEFS += __ASAN__
    CC_F += -fsanitize=address
  endif

  # final compiler flags
  CC_DEFS += $(EASIZE_DEF)
  CC_DEFS += $(DEFX86)
  CC_DEFS += $(CC_DEFS-1)
  CC_INCP += $(CC_INCP-1)
  CC_D += $(addprefix -D,$(CC_DEFS))
  CC_I += $(addprefix -I,$(CC_INCP))

  CFGFILE = @$(IDA)$(SYSDIR).cfg
  CFLAGS += $(CFGFILE)
  CFLAGS += $(RUNTIME_LIBSW)
  CFLAGS += $(PDBFORMAT)
  CFLAGS += /Brepro
  CFLAGS += $(sort $(CC_I))
  CFLAGS += $(sort $(CC_D))
  CFLAGS += $(sort $(CC_F))
  CFLAGS += $(WARNS)
  CFLAGS += $(CLPDB)

  # final linker flags
  LDFLAGS += /Brepro
  LDFLAGS += $(PDBFLAGS)
  LDFLAGS += /ERRORREPORT:QUEUE
  LDFLAGS += /ignore:4286 # symbol '' defined in '' is imported by ''
#-[
  LDFLAGS += /ignore:4099 # PDB 'vc140.pdb' was not found with 'x.obj' or at '...\pdb\x64_...\vc140.pdb'; linking object as if no debug info
endif

# to enable obsolete functions, disable the NO_OBSOLETE_FUNCS variable:
# $(TARGET): NO_OBSOLETE_FUNCS =
NO_OBSOLETE_FUNCS = NO_OBSOLETE_FUNCS
CC_DEFS += $(NO_OBSOLETE_FUNCS)

CXXFLAGS += $(CXXSTD)
CXXFLAGS += $(CFLAGS)
CXXFLAGS += $(sort $(CXX_F))
CXXFLAGS += $(sort $(CXX_WNO))
CXXFLAGS += $(UFLAGS)

LDFLAGS += $(LDOPT)

#############################################################################
ifdef __X86__
  DEFX86 = __X86__
endif

ifdef __EA64__
  ADRSIZE=64
  EASIZE_DEF = __EA64__
else
  SUFF32=32
  ADRSIZE=32
  EASIZE_DEF = __EA32__
endif

ifdef NDEBUG
  OPTSUF=_opt
endif

ifdef IDAHOME
  EXTRASUF1:=_home
  IDAHOME_PROCESSORS=pc arm ppc mips riscv
  # Disable vault in the build
else ifdef DEMO_OR_FREE
  ifdef DEMO
    HOSTSUF=_demo
    EXTRASUF1:=_demo
  else
    HOSTSUF=_free
    EXTRASUF1:=_free
  endif
  IDADEMO_PROCESSOR=pc
  IDADEMO_LOADERS=pe elf mach-o
else
  ifdef IDACLASS
    EXTRASUF1:=_class
  endif
  ifdef USE_STATIC_RUNTIME
    EXTRASUF2:=_s
    # libraries for static build on Windows use different settings from dynamic
    EXTRASUFS:=_s
  endif
  ifdef __ASAN__
    EXTRASUF3:=_asan
    ifdef __LINUX__
      # we have ASAN libraries only for Linux
      THIRD_PARTY_EXTRASUF:=_asan
    endif
  endif
  ifdef __FUZZER__
    EXTRASUF4:=_afl
  endif
endif
EXTRASUF=$(EXTRASUF1)$(EXTRASUF2)$(EXTRASUF3)$(EXTRASUF4)

#############################################################################
SYSDIR=$(TARGET_PROCESSOR_NAME)_$(SYSNAME)_$(COMPILER_NAME)_$(ADRSIZE)$(OPTSUF)$(EXTRASUF)
# libraries directory
LIBDIR=$(IDA)lib/$(TARGET_PROCESSOR_NAME)_$(SYSNAME)_$(COMPILER_NAME)_$(ADRSIZE)$(EXTRASUF)
# object files directory (using ?= to allow overriding)
OBJDIR?=obj/$(SYSDIR)
# PDB files directory
PDBDIR=$(IDA)pdb/$(TARGET_PROCESSOR_NAME)_$(SYSNAME)_$(COMPILER_NAME)_$(ADRSIZE)$(EXTRASUF)
# output directory for target platform
R=$(IDA)bin/
# input directory with existing build utilities
RS=$(IDA)bin/
# _ida.hlp placed in main tool directory
HI=$(RS)
# help source
HS=.hls
# help headers
HH=.hhp
# include,help and other directories are common for all platforms and compilers:
I =$(IDA)include/
C =$(R)cfg/
RI=$(R)idc/
F=$(OBJDIR)/
L=$(LIBDIR)/

DUMB=$(L)dumb$(O)
HELP=$(L)help$(O)
HLIB=$(HI)_ida.hlp

# to be used like this:
# $(L)va$(A): $(call lib, $(VA_OBJS))
lib=$(1); $(strip $(QARf)$(AR) $(OUTAR)$$@ $$^)

# to be used like this: $(call _link_exe, target, objs, libs)
_link_exe=$(strip $(QCCL)$(CCL) $(OUTSW)$(1) $(2) $(3) $(LDFLAGS) $(STDLIBS))

# to be used like this: $(call link_exe, objs, libs)
link_exe=$(call _link_exe,$@,$(1),$(2))

# to be used like this: $(call _link_dll, target, objs, libs)
_link_dll=$(strip $(QCCL)$(CCL) $(OUTDLL) $(DLLFLAGS) $(OUTSW)$(1) $(2) $(3) $(LDFLAGS) $(STDLIBS))

# to be used like this: $(call link_dll, objs, libs)
link_dll=$(call _link_dll,$@,$(1),$(2))

# to be used like this: $(call link_dumb, target, libs, objs)
link_dumb=$(3) $(patsubst %,$(L)%$(A),$(2)); $(strip $(QCCLf)$(CCL) $(OUTSW)$(1) $(LDFLAGS) $(3) $(patsubst %,$(L)%$(A),$(2)) $(STDLIBS))

# to be used like this:
# target: $(call dumb_target, libs, objs) extra_ldflags
dumb_target=$(call link_dumb,$$@,$(1),$(2) $(DUMB))

# to be used like this:
# $(R)%$(B): $(F)%$(O) $(call dumb_pattern, libs, objs) extra_ldflags
dumb_pattern=$(call link_dumb,$$@ $$<,$(1),$(2) $(DUMB))

# to be used like this:
# OBJS += $(call objs,obj1 obj2 obj3 ...)
objs=$(addprefix $(F),$(addsuffix $(O),$(1)))

# output name for module dll
module_dll=$(BIN_PATH)$(1)$(SUFF32)$(DLLEXT)

# output name for server executable
server_exe=$(R)dbgsrv/$(1)

ifeq ($(or $(M),$(MM),$(MMH),$(MO),$(MMO),$(MMHO)),1)
  BUILD_IDA = 1
endif
ifdef __NT__
  ifeq ($(or $(M32),$(MM),$(MSO32),$(MMSO)),1)
    BUILD_DBGSRV = 1
  endif
else
  ifeq ($(or $(M32),$(MM),$(MO32),$(MMO)),1)
    BUILD_DBGSRV = 1
  endif
endif

# target-os specific variables
ifdef __NT__
  DLLEXT=.dll
else ifdef __MAC__
  DLLEXT=.dylib
else
  DLLEXT=.so
endif

# build system commands
ifeq ($(OS),Windows_NT)
  CP=cp -f --preserve=all
  MKDIR=-@mkdir
  AWK=gawk
else
  CP=cp -f
  MKDIR=-@mkdir 2>/dev/null
  AWK=awk
endif
RM=rm -f
MV=mv

# used to silence some makefile commands
# run 'make Q=' to prevent commands from being silenced
Q?=@

# some makefiles rebuild targets when the makefile itself changes.
# this makes debugging makefiles a pain.
# run 'make MAKEFILE_DEP=' to disable this behaviour.
MAKEFILE_DEP?=makefile

# libida-related
# Note: $(IDALIB) should be used in the dependency list
#       $(LINKIDA) should be used in the link command
ifdef __NT__
  # Note: on Windows, ida.lib does not have a "64" suffix for ea64
  IDALIB  = $(L)ida$(A)
  LINKIDA = $(IDALIB)
else
  IDALIB  = $(L)libida$(SUFF32)$(DLLEXT)
  LINKIDA = -L$(L) -lida$(SUFF32)
endif

# idalibrary-related
# Note: $(IDALIBRARY) should be used in the dependency list
#       $(LINKIDALIBRARY) should be used in the link command
IDALIBRARY_NAME = idalib
ifdef __NT__
  IDALIBRARY_BASE = $(IDALIBRARY_NAME)
  IDALIBRARY = $(L)$(IDALIBRARY_BASE)$(SUFF32)$(A)
  LINKIDALIBRARY = $(L)$(IDALIBRARY_BASE)$(SUFF32)$(A)
else
  IDALIBRARY_BASE = $(addprefix lib,$(IDALIBRARY_NAME))
  IDALIBRARY = $(L)$(IDALIBRARY_BASE)$(SUFF32)$(DLLEXT)
  LINKIDALIBRARY = -L$(L) -l$(IDALIBRARY_NAME)$(SUFF32)
endif

# simplify command echo
ifdef IDAMAKE_SIMPLIFY
  ifeq ($(Q),@)
    DO_IDAMAKE_SIMPLIFY=1
  endif
endif

ifdef DO_IDAMAKE_SIMPLIFY
  ifdef IDAMAKE_SIMPLIFY_NO_COLOR
    qcolor=$(1)
  else
    ifeq ($(OS),Windows_NT)
      qcolor=-e #
    endif
    qcolor+="\033[1;34m$(1)\033[0m"
  endif
  QCXX  = @echo $(call qcolor,compile) $< && #
  QCC   = @echo $(call qcolor,compile) $< && #
  QASM  = @echo $(call qcolor,asm) $< && #
  QARf  = @echo $(call qcolor,lib) $$@ && #
  QCCL  = @echo $(call qcolor,link) $@ && #
  QCCLf = @echo $(call qcolor,link) $$@ && #
endif

# simple build rules
CONLY?=-c

$(F)%$(O): %.cpp
	$(strip $(QCXX)$(CXX) $(CXXFLAGS) $(NORTTI) $(CONLY) $(OBJSW)$@ $<)

$(F)%$(O): %.c
	$(strip $(QCC)$(CC) $(CFLAGS) $(CONLY) $(OBJSW)$@ $(FORCEC) $<)

$(C)%.cfg: %.cfg
	$(CP) $? $@

# http://www.cmcrossroads.com/article/printing-value-makefile-variable
print-%:
	@echo $* = "$($*)"
	@echo $*\'s origin is $(origin $*)

#############################################################################
.PHONY: all test cfg includes

# Force make to delete the target if the rule to build it fails
.DELETE_ON_ERROR:

#----------------------------------------------------------------------
ifeq ($(or $(IDAHOME),$(DEMO_OR_FREE),$(NO_TXT)),)
  UI_BACKENDS += txt
endif
ifeq ($(or $(__CODE_CHECKER__),$(NO_QT)),)
  ifeq ($(__EA64__),1)
    UI_BACKENDS += qt
  endif
endif

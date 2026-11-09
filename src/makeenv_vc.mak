
# Create configuration files

include allmake.mak

define CFG0             # Common flags
/I$(shell cygpath -am $(IDA)include)
/DMAXSTR=1024
/DNO_TV_STREAMS
/D__NT__
endef

############################################################################
#               Visual Studio for Intel
define CFG1
#       Merge duplicate strings
/GF
#       Exception handling (try/catch can handle only C++ exceptions; use __except for SEH)
/EHs
#       Separate functions for linker
/Gy
#       show full paths
/FC
#       All warnings on
/Wall
#       warning C4018: >= : signed/unsigned mismatch
/wd4018
#       warning C4061: enumerator xxx in switch of enum yyy is not explicitly handled by a case label
/wd4061
#       warning C4121: xxx: alignment of a member was sensitive to packing
/wd4121
#       warning C4127: conditional expression is constant
/wd4127
#       warning C4200: nonstandard extension used: zero-sized array in struct/union
/wd4200
#       warning C4201: nonstandard extension used : nameless struct/union
/wd4201
#       warning C4239: nonstandard extension used : non-const refernece=>lvalue
/wd4239
#       warning C4242: initializing : conversion from a to b, possible loss of data
/wd4242
#       warning C4244: xxx : conversion from a to b, possible loss of data
/wd4244
#       warning C4245: xxx : conversion from a to b, signed/unsigned mismatch
/wd4245
#       warning C4267: xxx : conversion from size_t to b, possible loss of data
/wd4267
#       warning C4310: cast truncates constant value
/wd4310
#       warning C4324: xxx : structure was padded due to __declspec(align())
/wd4324
#       warning C4350: behavior change: '' called instead of ''
#       for some reason vc11 started to complain about it and i do not see
#       how to shut it up
/wd4350
#       warning C4355: this : used in base member initializer list
/wd4355
#       warning C4365: xx : signed/unsigned mismatch (= or return)
/wd4365
endef
define CFG1a
#       warning C4366: The result of the unary & operator may be unaligned
/wd4366
#       warning C4371: xxx : layout of class may have changed from a previous version of the compiler due to better packing of member xxx
/wd4371
#       warning C4388: != : signed/unsigned mismatch
/wd4388
#       warning C4389: != : signed/unsigned mismatch
/wd4389
#       warning C4458: declaration of '' hides class member
/wd4458
#       warning C4480: != :  nonstandard extension used: ....
/wd4480
#       warning C4512: xxx : assignment operator could not be generated
/wd4512
#       warning C4514: xxx : unreferenced inline function has been removed
/wd4514
#       warning C4548: expression before comma has no effect; expected expression with side-effect
/wd4548
#       warning C4571: Informational: catch(...) semantics changed since Visual C++ 7.1; structured exceptions (SEH) are no longer caught
/wd4571
#       warning C4574: yvals.h(vc10): '_SECURE_SCL' is defined to be '0': did you mean to use '#if _SECURE_SCL'?
#       warning C4574: ws2tcpicp.h(vc14): 'INCL_WINSOCK_API_TYPEDEFS' is defined to be '0': did you mean to use '#if INCL_WINSOCK_API_TYPEDEFS'?
/wd4574
#       warning C4611: interaction between _setjmp and C++ object destruction is non-portable
/wd4582
#		    warning C4582: constructor is not implicitly called
/wd4583
#		    warning C4583: destructor is not implicitly called
/wd4611
#       warning C4619: pragma warning : there is no warning number xxx
/wd4619
#       warning C4623: xxx : default constructor was implicitly defined as deleted
/wd4623
#       warning C4625: xxx : copy constructor could not be generated because a base class copy constructor is inaccessible
/wd4625
#       warning C4626: xxx : assignment operator could not be generated because a base class assignment operator is inaccessible
/wd4626
#       warning C4640: p : construction of local static object is not thread-safe
/wd4640
#       warning C4668: xxx is not defined as a preprocessor macro, replacing with 0 for #if/#elif
/wd4668
#       warning C4686: xxx : possible change in behavior, change in UDT return calling convention
/wd4686
#       warning C4701: xxx : potentially uninitialized local variable
/wd4701
#       warning C4710: xxx : function not inlined
/wd4710
#       warning C4711: xxx : function select for automatic inline expansion
/wd4711
#       warning C4738: storing 32-bit float result in memory, possible loss of performance
/wd4738
#       warning C4820: xxx : x bytes padding added after member xxx
/wd4820
#       warning C4917: xxx : a GUID can only be associated with a class, interface or namespace
/wd4917
#       warning C4986: operator new[]: exception specification does not match previous declaration entered the game.
/wd4986
#       warning C4987: setjmp.h(vc10) nonstandard extension used: throw(...)
/wd4987
#
# treat as errors:
#       warning C4541: 'dynamic_cast' used on polymorphic type 'xxx' with /GR-; unpredictable behavior may result
/we4541
#       warning C4715: 'function' : not all control paths return a value
/we4715
#       warning C4296:  '' : expression is always false
/we4296
#       warning C4315: 'class' : 'this' pointer for member 'class::member' may not be aligned 8 as expected by the constructor
/we4315
#       warning C4805: 'operation' : unsafe mix of type 'type' and type 'type' in operation
/we4805
#
endef

define CFG2
#       Separate data for linker
/Gw
#       warning C4091: 'typedef ': ignored on left of '' when no variable is declared
#       skd.../um/dbghelp/h
/wd4091
#       warning C4435: Object layout under /vd2 will change due to virtual base ''
/wd4435
#       warning C4456: declaration of '' hides previous local declaration
/wd4456
#       warning C4457: declaration of '' hides function parameter
/wd4457
#       warning C4459: declaration of '' hides global declaration
/wd4459
#       warning C4464: relative include path contains '..'
/wd4464
#       warning C4774: '' : format string expected in argument 1 is not a string literal
#       this warning cannot handle cnd ? "fmt1" : "fmt2" while gcc can
/wd4774
#       warning C4589: Constructor of abstract class '' ignores initializer for virtual base class
#       completely wrong warning
/wd4589
#       warning C5025: move assignment operator was implicitly defined as deleted
/wd5025
#       warning C5026: move constructor was implicitly defined as deleted because a base class move constructor is inaccessible or deleted
/wd5026
#       warning C5027: move assignment operator was implicitly defined as deleted because a base class move assignment operator is inaccessible or deleted
/wd5027
#       warning C5039: '': pointer or reference to potentially throwing function passed to extern C function under -EHc. Undefined behavior may occur if this function throws an exception.
/wd5039
#       warning C5045: Compiler will insert Spectre mitigation for memory load if /Qspectre switch specified
/wd5045
#       warning C5204: class has virtual functions, but its trivial destructor is not virtual; instances of objects derived from this class may not be destructed correctly
/wd5204
#       warning C5220: '': a non-static data member with a volatile qualified type no longer implies that compiler generated copy/move constructors and copy/move assignment operators are not trivial
/wd5220
#       warning C6323: Use of arithmetic operator on Boolean type(s).
/wd6323
#       warning C5038: data member '' will be initialized after data member ''
/wd5038
#       warning C6340: Mismatch on sign: '' passed as '' when some signed type is required in call to ''
/wd6340
endef

ifdef NDEBUG            # Optimization flags
define CFG3
/DNDEBUG
# Do not use checked iterators
/D_SECURE_SCL=0
# Maximum optimization
/Ox
# Enable intrinsic functions
/Oi
endef
else                    # Debug flags
define CFG3
/D_DEBUG
# Enable security checks
/GS
# Disable optimizations
/Od
endef
endif

ifdef USE_VS15
  VSCFG = vs15paths.cfg
else
  ifdef __XPCOMPAT__
    VSCFG = vs19paths_xp.cfg
  else
    VSCFG = vs19paths.cfg
  endif
endif

all: $(SYSDIR).cfg $(VSCFG)
$(SYSDIR).cfg: makeenv_vc.mak allmake.mak defaults.mk makefile
	@echo -e '$(subst $(newline),\n,${CFG0})' | grep -v '^#' >$@
	@echo -e '$(subst $(newline),\n,${CFG1})' | grep -v '^#' >>$@
	@echo -e '$(subst $(newline),\n,${CFG1a})'| grep -v '^#' >>$@
	@echo -e '$(subst $(newline),\n,${CFG2})' | grep -v '^#' >>$@
	@echo -e '$(subst $(newline),\n,${CFG3})' | grep -v '^#' >>$@
ifdef __EA64__
	@echo /D__EA64__                        >>$@
endif
ifdef __X86__
	@echo /D__X86__                         >>$@
endif
ifdef USE_STATIC_RUNTIME
	@echo /D__NOEXPORT__                    >>$@
endif
ifdef __XPCOMPAT__
	@echo /D_USING_V110_SDK71_              >>$@
	@echo /Zc:threadSafeInit-               >>$@
endif

# these cfg files speed up the build process by caching compiler/sdk paths.
# this allows the build system to avoid calling cygpath multiple times on every run.

define VS15PATHS_CFG
export MSVC_PATH = $(MSVC_PATH)
export MSVC_INCLUDE = $(MSVC_INCLUDE)
export MSVC_BIN-X86 = $(MSVC_BIN-X86)
export MSVC_BIN-X64 = $(MSVC_BIN-X64)
export WSDK_PATH = $(WSDK_PATH)
export WSDK_VER = $(WSDK_VER)
export INCLUDE_UCRT_PATH = $(INCLUDE_UCRT_PATH)
export LIB_UCRT_PATH = $(LIB_UCRT_PATH)
export INCLUDE_UCRT = $(INCLUDE_UCRT)
export LIB_UCRT = $(LIB_UCRT)
endef
vs15paths.cfg:
	@echo -e '$(subst $(newline),\n,$(VS15PATHS_CFG))' >$@

define VS17PATHS_CFG
export MSVC_ROOT = $(MSVC_ROOT)
export MSVC_TOOLSVER = $(MSVC_TOOLSVER)
export MSVC_PATH = $(MSVC_PATH)
export MSVC_INCLUDE = $(MSVC_INCLUDE)
export MSVC_BIN-X86 = $(MSVC_BIN-X86)
export MSVC_BIN-X64 = $(MSVC_BIN-X64)
export WSDK_PATH = $(WSDK_PATH)
export WSDK_VER = $(WSDK_VER)
export INCLUDE_UCRT_PATH = $(INCLUDE_UCRT_PATH)
export LIB_UCRT_PATH = $(LIB_UCRT_PATH)
export INCLUDE_UCRT = $(INCLUDE_UCRT)
export LIB_UCRT = $(LIB_UCRT)
export INCLUDE_SHARED_PATH = $(INCLUDE_SHARED_PATH)
export INCLUDE_UM_PATH = $(INCLUDE_UM_PATH)
export LIB_UM_PATH = $(LIB_UM_PATH)
export SDK_BIN_PATH = $(SDK_BIN_PATH)
export INCLUDE_SHARED = $(INCLUDE_SHARED)
export INCLUDE_UM = $(INCLUDE_UM)
export LIB_UM = $(LIB_UM)
export SDK_BIN = $(SDK_BIN)
endef
vs19paths.cfg:
	@echo -e '$(subst $(newline),\n,$(VS17PATHS_CFG))' >$@

define VS17PATHS_XP_CFG
export MSVC_ROOT = $(MSVC_ROOT)
export MSVC_TOOLSVER = $(MSVC_TOOLSVER)
export MSVC_PATH = $(MSVC_PATH)
export MSVC_INCLUDE = $(MSVC_INCLUDE)
export MSVC_BIN-X86 = $(MSVC_BIN-X86)
export MSVC_BIN-X64 = $(MSVC_BIN-X64)
export WSDK_PATH = $(WSDK_PATH)
export WSDK_VER = $(WSDK_VER)
export INCLUDE_UCRT_PATH = $(INCLUDE_UCRT_PATH)
export LIB_UCRT_PATH = $(LIB_UCRT_PATH)
export INCLUDE_UCRT = $(INCLUDE_UCRT)
export LIB_UCRT = $(LIB_UCRT)
export INCLUDE_MSSDK71 = $(INCLUDE_MSSDK71)
export LIB_MSSDK71 = $(LIB_MSSDK71)
export SDK_BIN = $(SDK_BIN)
endef
vs19paths_xp.cfg:
	@echo -e '$(subst $(newline),\n,$(VS17PATHS_XP_CFG))' >$@

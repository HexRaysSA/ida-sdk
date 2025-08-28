#############################################################################
# versions and paths for various external libraries and utils

ifdef __NT__
  PROGRAMFILES_X86 ?= ${ProgramFiles(x86)}

  #force use of cygwin tar
  TAR = $(shell cygpath -m /bin/tar)

  # The following variables may have been set by vcvars.bat. You may
  # also set them manually. The default installation directories are
  # defined below in case these variables are not set.
  # Note: the following paths use backslashes (and may also contain a
  #       trailing backslash) in order to conform to the variables
  #       exported by vcvars.bat.

  # Default Visual C++ Install Directory
  VCINSTALLDIR ?= '$(PROGRAMFILES)\Microsoft Visual Studio\2022\Professional\VC\'

  # Visual C++ Tools Version
  # Note: if this variable is not set, the default version is obtained
  #       in allmake.mak under "Visual C++ 2019 Tools Version".
  # VCToolsVersion ?= '14.29.30133'

  # Windows SDK Install Directory
  WindowsSdkDir ?= '$(PROGRAMFILES_X86)\Windows Kits\10\'

  # Windows SDK version
  # Note: if this variable is not set, the latest version is detected
  #       in allmake.mak under "Windows SDK Version".
  # WindowsSDKVersion ?= '10.0.19041.0\'

  # Microsoft SDK v7.1A is only used for the win32 debugger server for
  # Windows XP compatibility.
  MSSDK71_PATH ?= '$(PROGRAMFILES_X86)/Microsoft SDKs/Windows/v7.1A'
else ifdef __MAC__
  # oldest supported version of MacOSX
  # bumped on 2024-07-18 by Henri for IOKit's kIOMainPortDefault (kIOMasterPortDefault has been deprecated with macOS12, we'd have to have a macOS 11 ARM builder)
  MACOSX_DEPLOYMENT_TARGET ?= 12.0
endif

# Python
PYTHON_VERSION_MAJOR?=3
PYTHON_VERSION_MINOR?=11
PYTHON_VERSION_SUFFIX?=
PYTHON_VERNAME=python$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR)$(PYTHON_VERSION_SUFFIX)

ifneq ($(filter $(PYTHON_VERSION_MINOR),0 1 2 3 4 5 6 7),)
$(error Must build against Python 3.8 or newer; set PYTHON_VERSION_MINOR accordingly.)
endif

# TODO clean this up
ifdef __NT__
  ifneq (,$(wildcard /cygdrive/c/Program\ Files/Python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)/python.exe))
    PYTHON_ROOT ?= C:/Program Files/Python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)
  else
    ifeq ($(PYTHON_VERSION_MAJOR),2)
      PYTHON_VERSUF=-x64
    endif
    PYTHON_ROOT ?= $(SYSTEMDRIVE)/Python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)$(PYTHON_VERSUF)
  endif
  PYTHON ?= "$(PYTHON_ROOT)/python.exe"
else
  PYTHON ?= $(PYTHON_VERNAME)
endif

#
# Qt
#

# Use the debug build of Qt on linux/macOS (`export DEBUG_QT=1`)
# on macOS macdeployqt takes care of it
THIRD_PARTY_QT?=$(THIRD_PARTY)
ifndef __NT__
  ifndef NDEBUG
    ifeq ($(QTVER),)
      ifneq ($(DEBUG_QT),)
        ifneq ($(DEBUG_THIRD_PARTY),)
          THIRD_PARTY_QT=$(DEBUG_THIRD_PARTY)
          QTDEBUG=-debug
        else
          $(error 'DEBUG_THIRD_PARTY' should point at a repository when using 'DEBUG_QT')
        endif
      endif
    endif
  endif
endif
QTVER?=6.8.0
QT_VERSION_MAJOR=$(firstword $(subst ., ,$(QTVER)))
ifeq ($(QT_VERSION_MAJOR),6)
  CC_DEFS += QT6=1
endif

QTDIR-$(__LINUX__) = $(THIRD_PARTY_QT)Qt/$(QTVER)/$(TRGT_ARCH)linux$(QTDEBUG)/
QTDIR-$(__MAC__)   = $(THIRD_PARTY_QT)Qt/$(QTVER)/$(TRGT_ARCH)mac$(QTDEBUG)/
QTDIR-$(__NT__)    = $(THIRD_PARTY_QT)Qt/$(QTVER)/$(TRGT_ARCH)win$(QTDEBUG)/
QTDIR ?= $(QTDIR-1)

QTDIR-HOST-$(__LINUX__) = $(THIRD_PARTY_QT)Qt/$(QTVER)/$(HOST_ARCH)linux$(QTDEBUG)/
QTDIR-HOST-$(__MAC__)   = $(THIRD_PARTY_QT)Qt/$(QTVER)/$(HOST_ARCH)mac$(QTDEBUG)/
QTDIR-HOST-$(__NT__)    = $(THIRD_PARTY_QT)Qt/$(QTVER)/$(HOST_ARCH)win$(QTDEBUG)/
QTDIR-HOST ?= $(QTDIR-HOST-1)

# where to find moc?
ifeq ($(QT_VERSION_MAJOR)$(__NT__),6)
  QT_LIBEXEC=$(QTDIR-HOST)libexec/
else
  QT_LIBEXEC=$(QTDIR-HOST)bin/
endif

ifdef __NT__
  ifdef NDEBUG
    QTSUFF=.dll
  else
    QTSUFF=d.dll
  endif
  QTLIBDIR=bin
else ifdef __LINUX__
  QTPREF=lib
  QTSUFF=.so.$(QT_VERSION_MAJOR)
  QTLIBDIR=lib
endif

# Z3
Z3_BIN-$(__LINUX__) = $(THIRD_PARTY)z3/z3-z3-4.11.2/build/linux_$(TRGT_ARCH)/
Z3_BIN-$(__NT__)    = $(THIRD_PARTY)z3/z3-z3-4.11.2/build/win32_$(TRGT_ARCH)/
Z3_BIN-$(__MAC__) = $(THIRD_PARTY)z3/z3-z3-4.11.2/build/mac_$(TRGT_ARCH)/
Z3_BIN ?= $(Z3_BIN-1)

Z3_INCLUDE ?= $(THIRD_PARTY)z3/z3-z3-4.11.2/src/api/

# SWiG
#SWIG_VERSION?=4.2.0
#SWIG_VERSION?=240215
SWIG_VERSION?=4.3.0
ifdef __NT__
  SWIG_DIR_SUFFIX?=-cygwin
endif
ifdef __NT__
  ifeq ($(PYTHON_VERSION_MAJOR),3)
    SWIG_DISTRIBUTION_HAS_UNIX_LAYOUT:=1
  endif
else
  SWIG_DISTRIBUTION_HAS_UNIX_LAYOUT:=1
endif

ifeq ($(SWIG_DISTRIBUTION_HAS_UNIX_LAYOUT),1)
  ifdef USE_CCACHE
    # we set CCACHE_DIR so as to not interfere with the system's ccache
    # and we set CCACHE_CPP2 to prevent SWiG from printing a bunch of
    # warnings due to re-using of the preprocessed source.
    SWIG?=CCACHE_DIR='$${HOME}/.ccache-swig' CCACHE_CPP2=1 $(SWIG_HOME)/bin/ccache-swig $(SWIG_HOME)/bin/swig
  else
    SWIG?=$(SWIG_HOME)/bin/swig
  endif
  SWIG_INCLUDES?=-I$(SWIG_HOME)/share/swig/$(SWIG_VERSION)/python -I$(SWIG_HOME)/share/swig/$(SWIG_VERSION)
else
  SWIG?=$(SWIG_HOME)/swig.exe
  SWIG_INCLUDES?=-I$(SWIG_HOME)/Lib/python -I$(SWIG_HOME)/Lib
endif

#############################################################################
# keep all paths in unix format, with forward slashes
ifeq ($(OS),Windows_NT)
  # define: convert dos path to unix path by replacing backslashes by slashes
  unixpath=$(subst \,/,$(1))

  PYTHON_ROOT  :=$(call unixpath,$(PYTHON_ROOT))
  PYTHON       :=$(call unixpath,$(PYTHON))
  SWIG         :=$(call unixpath,$(SWIG))
  QTDIR        :=$(call unixpath,$(QTDIR))
endif

#############################################################################
# http://stackoverflow.com/questions/16467718/how-to-print-out-a-variable-in-makefile
.print-%  : ; @echo $($*)

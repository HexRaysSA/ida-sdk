
# definitions for idapython (& other plugins dynamically linked to Python)
ifdef __NT__
  PYTHON_CFLAGS  := -I"$(PYTHON_ROOT)/include"
  PYTHON_LDFLAGS := "/LIBPATH:$(PYTHON_ROOT)/libs/"
else
  PYTHON_CFLAGS := $(shell $(PYTHON)-config --includes)
  ifdef __MAC__
    # on macOS, we'll also load libpython3 using RTLD_GLOBAL to avoid having
    # to patch idapython's dylib.
    # for that to work, the users of libpython3 must be built using a flat namespace
    # to avoid that idapython3 fails to load if it can't load its libpython dependency,
    # we use a weak link.
    PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags) -weak-lpython3.$(PYTHON_VERSION_MINOR) -flat_namespace
  else
    # Yay! https://bugs.python.org/issue36721
    ifeq ($(USE_EMBED),true)
      PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags --embed)
    else
      PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags)
    endif
  endif
endif


# definitions for idapython (& other plugins dynamically linked to Python)
# PYTHON_CFLAGS/PYTHON_LDFLAGS may be pre-set for cross-compilation (via PYTHON_LDFLAGS_SET)
ifdef __NT__
  PYTHON_CFLAGS  ?= -I"$(PYTHON_ROOT)/include"
  PYTHON_LDFLAGS ?= "/LIBPATH:$(PYTHON_ROOT)/libs/"
else
  PYTHON_CFLAGS ?= $(shell $(PYTHON)-config --includes)
  # Yay! https://bugs.python.org/issue36721
  # Skip python-config if PYTHON_LDFLAGS_SET=1 (cross-compilation)
  ifndef PYTHON_LDFLAGS_SET
    ifeq ($(USE_EMBED),true)
      PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags --embed)
    else
      PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags)
    endif
  endif
endif

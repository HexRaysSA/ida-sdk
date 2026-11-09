
# this makefile creates the output directories for object/library files
# when the makefile is parsed.

ifeq ($(wildcard $(OBJDIR)/.),)
  $(shell mkdir -p 2>/dev/null $(OBJDIR))
endif

ifeq ($(wildcard $(PDBDIR)/.),)
  $(shell mkdir -p 2>/dev/null $(PDBDIR))
endif

ifeq ($(wildcard $(LIBDIR)/.),)
  $(shell mkdir -p 2>/dev/null $(LIBDIR))
endif

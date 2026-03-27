
SERVER_LIBS += $(L)dbg_server$(A)
SERVER_LIBS += $(L)dbg_rpc$(A)
SERVER_LIBS += $(L)dbg_proc$(A)
SERVER_LIBS += $(L)network$(A)
SERVER_LIBS += $(DUMB)
SERVER_LIBS += $(L)unicode$(A)
SERVER_LIBS += $(L)pro$(A)
SERVER_LIBS += $(L)int128$(A)
SERVER_LIBS += $(L)compress$(A)

ifeq ($(__XPCOMPAT__)$(__X86__),11)
  SERVER_OBJS += $(F)crt_oldwin_compat_stubs$(O)
  SERVER_OBJS += $(F)crt_oldwin_compat_stubs_asm$(O)
$(F)crt_oldwin_compat_stubs_asm$(O): crt_oldwin_compat_stubs.asm
	$(MSVC_BIN)/ml.exe /nologo /c /Fo$@ $<
endif

server: $(SERVERS)
$(SERVERS): LDFLAGS += $(SERVER_LDFLAGS)
$(SERVERS): STDLIBS += $(SERVER_STDLIBS)
$(SERVERS): $(SERVER_OBJS) $(SERVER_LIBS)
	$(call link_exe, $(SERVER_OBJS), $(SERVER_LIBS))
	$(CHECKSYMS_CMD)
	$(SERVER_POSTACTION)


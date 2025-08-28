// read symbols from an elf file
#ifndef __SYMELF__
#define __SYMELF__

struct symbol_visitor_t
{
  symbol_visitor_t(int visit_flags) : velf(visit_flags) {}

  int velf;
#define VISIT_SYMBOLS  0x0001
#define VISIT_INTERP   0x0002
#define VISIT_DYNINFO  0x0004
#define VISIT_SEGMENTS 0x0008
#define VISIT_BUILDID  0x0010
#define VISIT_DBGLINK  0x0020

  // any callback returns nonzero - stop enumeration
  virtual int visit_symbol(ea_t /*ea*/, const char * /*name*/) { return 0; }
  virtual int visit_interp(const char * /*name*/) { return 0; }
  virtual int visit_segment(ea_t /*start*/, size_t /*size*/, const char * /*name*/) { return 0; }
  virtual int visit_dyninfo(uint64 /*tag*/, const char * /*name*/, uint64 /*value*/) { return 0; }
  virtual int visit_buildid(const char * /*Build ID*/) { return 0; }
  virtual int visit_debuglink(const char * /*debug*/, uint32 /*crc*/) { return 0; }
};

// returns -1 on errors
// otherwise returns the non-zero code returned by the visitor or 0
int load_elf_symbols(const char *fname, symbol_visitor_t &sv, bool remote=false);

#endif

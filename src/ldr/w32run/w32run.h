#ifndef __W32RUN_H__
#define __W32RUN_H__

struct w32_hdr
{
  uint32   ident;
  uint32   beg_fileoff;
  uint32   read_size;
  uint32   reltbl_offset;
  uint32   mem_size;
  uint32   start_offset;
};

#define W32_ID ('F'<<8)+'C'

#define W32_DOS_LOAD_BASE 0x10000 // regular dos loading

#endif

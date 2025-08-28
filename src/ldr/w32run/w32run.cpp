/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      Watcom DosExtender loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

/*
        L O A D E R  for Watcom W32RUN DOS32-extender
*/

#include "../idaldr.h"
#include <exehdr.h>
#include <problems.hpp>
#include "w32run.h"
//lint !e451 header file 'stddef.h' repeatedly included but has no header guard
#include <stddef.h>   // offsetof

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  union
  {
    exehdr  ex;
    w32_hdr wh;
  };
  uint32 pos;

  if ( qlread(li, &ex, sizeof(ex)) != sizeof(ex)
    || ex.exe_ident != EXE_ID
    || (pos = ex.HdrSize) == 0 )
  {
    return 0;
  }
  uint64 fsize = qlsize(li);
  qlseek(li, pos *= 16, SEEK_SET);
  if ( qlread(li, &wh, sizeof(wh)) != sizeof(wh) )
    return 0;
  if ( wh.ident != W32_ID || wh.beg_fileoff < pos+sizeof(wh)
//    || ph->memsize >= MAXLOADMEM
    || wh.read_size > wh.mem_size
    || wh.start_offset >= wh.reltbl_offset
    || wh.beg_fileoff > fsize
    || wh.read_size > fsize - wh.beg_fileoff
    || wh.reltbl_offset > wh.read_size - 2 )
  {
    return 0;
  }
  *fileformatname = "Watcom DOS32-extender file";
  *processor      = "metapc";
  return f_W32RUN;
}

//--------------------------------------------------------------------------
static w32_hdr wh;
static uint32 minea, topea;
static linput_t *li;

//-------------------------------------------------------------------------
static int mread(void *buf, size_t size)
{
  if ( qlread(li, buf, size) == size )
    return 0;
  if ( ask_yn(ASKBTN_NO,
              "HIDECANCEL\n"
              "Read error or bad file structure. Continue loading?") <= ASKBTN_NO )
  {
    loader_failure();
  }
  return 1;
}

//-------------------------------------------------------------------------
static void realize_relocation(void)
{
  char first = 0;
  ushort cnt, tmp;
  uint32 offset;
  uint32 curv, maxv = 0, ost = wh.read_size - wh.reltbl_offset;

  fixup_data_t fd(FIXUP_OFF32);

  msg("Reading relocation table...\n");

  for ( ; ; )
  {
    if ( ost < sizeof(short) )
    {
      first = -1;
      break;
    }
    ost -= sizeof(short);
    if ( mread(&cnt, sizeof(cnt)) )
      return;
    if ( cnt == 0 )
      break;
    if ( ost < sizeof(int32) )
    {
      first = -1;
      break;
    }
    ost -= sizeof(int32);
    if ( mread(&tmp, sizeof(tmp)) )
      return;
    offset = (uint32)tmp << 16;
    if ( mread(&tmp, sizeof(tmp)) )
      return;
    offset |= tmp;
    while ( true )
    {
      if ( offset > wh.reltbl_offset - 4 )
      {
        if ( !first )
        {
          ++first;
          warning("Bad value(s) in relocation table!");
        }
      }
      else
      {
        uint32 ea = minea + offset;
        show_addr(ea);
        curv = get_dword(ea);
        if ( curv >= wh.mem_size )
        {
          msg("Doubtful value after relocation! (%x=>%x)\n", ea, curv + minea);
          remember_problem(PR_ATTN, ea);
        }
        else if ( curv > maxv )
        {
          maxv = curv;
        }
        curv += minea;
        put_dword(ea, curv);
        fd.off = offset;
        fd.sel = curv >= topea ? 2 : 1;
        fd.set(ea);
      }
      if ( --cnt == 0 )
        break;
      if ( ost < sizeof(short) )
      {
        first = -1;
        break;
      }
      ost -= sizeof(short);
      if ( mread(&tmp, sizeof(tmp)) )
        return;
      offset += tmp;
    }
  }
  if ( first < 0 )
    warning("Truncated relocation table!");
  if ( !first && ost )
    warning("Information after relocation table!");
  if ( ost == 0
    && !first
    && maxv > wh.start_offset
    && (maxv += minea) < topea )
  {
    set_segm_end(topea, maxv, SEGMOD_KILL);
  }
}

//--------------------------------------------------------------------------
static void add_all_comments(void)
{
  create_filename_cmt();
  add_pgm_cmt("Full size of allocation memory: %08Xh", wh.mem_size);
  add_pgm_cmt("Calling convention for W32RUN\n\n"
              "  ah     - OS type\n"
              "  ecx    - low stack limit\n"
              "  bx:edx - int 21h interface\n"
              "  edi    - struct {");
  add_pgm_cmt("                    char * ModuleFileName;\n"
              "                    char * CommandLine;\n"
              "                    char * Environment;");
  add_pgm_cmt("                    char * ExeTrademarkString;\n"
              "                    long   SystemDepenced_1;\n"
              "                    long   SystemDepenced_2;");
  add_pgm_cmt("                   }");

  set_cmt(inf_get_start_ip(), "Calling convention declared in file header", 1);
}

//--------------------------------------------------------------------------
static void create32(
        sel_t sel,
        ea_t start_ea,
        ea_t end_ea,
        const char *name,
        const char *sclass)
{
  set_selector(sel, 0);

  segment_t s;
  s.sel     = sel;
  s.start_ea = start_ea;
  s.end_ea   = end_ea;
  s.align   = saRelByte;
  s.comb    = scPub;
  s.bitness = 1; // 32-bit

  if ( !add_segm_ex(&s, name, sclass, ADDSEG_NOSREG|ADDSEG_SPARSE) )
    loader_failure();
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *_li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  ushort pos;

  set_processor_type("metapc", SETPROC_LOADER);

  li = _li;
  qlseek(li, offsetof(exehdr, HdrSize));
  lread(li, &pos, sizeof(pos));
  qlseek(li, (uint32)pos * 16);
  lread(li, &wh, sizeof(wh));

  inf_set_baseaddr(0);
//  inf.s_prefflag &= ~PREF_SEGADR;
//  inf.nametype = NM_EA4;
  inf_set_lflags(inf_get_lflags() | LFLG_PC_FLAT);
  minea = (uint32)to_ea(W32_DOS_LOAD_BASE, 0);
  inf_set_start_ip(minea + wh.start_offset);
  inf_set_start_cs(1); // selector of code
  topea = minea + wh.reltbl_offset;
  uint64 fsize = qlsize(li);
  if ( wh.beg_fileoff > fsize || topea-minea > fsize-wh.beg_fileoff )
    loader_failure("Corrupted file");
  file2base(li, wh.beg_fileoff, minea, topea, FILEREG_PATCHABLE);
  create32(1, minea, topea, NAME_CODE, CLASS_CODE);
  create32(2, topea, minea+wh.mem_size, NAME_BSS, CLASS_BSS);
  set_default_dataseg(1);
  realize_relocation();
  add_all_comments();
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  nullptr,
//      take care of a moved segment (fix up relocations, for example)
  nullptr,
  nullptr,
};

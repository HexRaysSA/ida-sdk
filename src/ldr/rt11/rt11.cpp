/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      RT11 executable Loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

/*
        L O A D E R  for RT11 .sav-files
*/

#include "../idaldr.h"
#include "../../module/pdp11/pdp_ml.h"

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
        const char *filename)
{
  uint64 fsize = qlsize(li);

  if ( (fsize % 512) || !fsize )
    return 0;
  qlseek(li, 040);

  ushort tmp;
  lread2bytes(li, &tmp, 0);
  if ( tmp > fsize || (tmp & 1) || tmp < 0400 )
    return 0;
  lread2bytes(li, &tmp, 0);
  if ( tmp > fsize )
    return 0;
  qlseek(li, 050);
  lread2bytes(li, &tmp, 0);
  if ( tmp & 1 || tmp > fsize )
    return 0;

// 20.11.01, ig
// got tired of too many false positives
// now we'll check the file extension

  const char *ext = get_file_ext(filename);
  if ( ext == nullptr || stricmp(ext, "sav") != 0 )
    return 0;

  *fileformatname = "RT11 (pdp11) sav-file";
  *processor      = "pdp11";
  return f_LOADER;
}

//--------------------------------------------------------------------------
static void loadchunk(
        linput_t *li,
        ea_t ea,
        size_t size,
        ea_t base,
        int32 fpos,
        const char *sclass)
{
  qoff64_t p = qltell(li);
  file2base(li, fpos, ea, ea+size, FILEREG_PATCHABLE);
  add_segm(base, ea, ea+size, nullptr, sclass);
  qlseek(li, p);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//

void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  set_processor_type("pdp11", SETPROC_LOADER);

  pdp_ml_t *ml = nullptr;
  netnode  *ml_ovrtrans = nullptr;
  if ( !pdp11_module_t::get_ml_ptr(&ml, &ml_ovrtrans)
    || !ml
    || !ml_ovrtrans )
  {
    error("Internal error in loader<->module link");
  }
//
//  Find out asect section and load it
//
  int i;
  segment_t s;
  s.start_ea = to_ea(inf_get_baseaddr(), 0);
  qlseek(li, 040);
  ushort startIP, topPrg, svrEnd, ovt;
  lread(li, &startIP, sizeof(ushort));
  lread(li, &ml->asect_top, sizeof(ushort));
  if ( (startIP & 1) || startIP < 0400 )
    startIP = 0;
  else
    inf_set_start_ip(startIP);
  qlseek(li, 050);
  lread(li, &topPrg, sizeof(ushort));
  if ( topPrg & 1 || (uint64)topPrg > qlsize(li) )
    topPrg = 0;
  if ( topPrg > 01000
    && ml->asect_top < (topPrg - 01000 )
    && ml->asect_top > 0400 )
  {
    svrEnd = ml->asect_top;
    if ( ml->asect_top > 01000 )
      svrEnd = 01000;
  }
  else
  {
    ml->asect_top = svrEnd = 01000;
  }
  if ( startIP && ml->asect_top > startIP )
  {
    svrEnd = 01000;
    if ( svrEnd > startIP )
      svrEnd = startIP;
    s.end_ea = s.start_ea + svrEnd;
  }
  else
  {
    s.end_ea = s.start_ea + ml->asect_top;
  }
  inf_set_start_cs(inf_get_baseaddr());
  file2base(li, 0, s.start_ea, s.end_ea, FILEREG_PATCHABLE);
  s.type = SEG_IMEM;
  s.sel  = find_selector(inf_get_baseaddr());
  add_segm_ex(&s, "asect", nullptr, ADDSEG_NOSREG);

  if ( inf_get_start_ip() != BADADDR )
    op_plain_offset(s.start_ea + 040, 0, s.start_ea);
  else
    create_word(s.start_ea + 040, 2);
  create_word(s.start_ea + 042, 2);  // begin stack value
  create_word(s.start_ea + 044, 2);  // JSW
  create_word(s.start_ea + 046, 2);  // load USR address
  create_word(s.start_ea + 050, 2);  // top programm loading address

  ushort begovrtbl = get_word(s.start_ea + 064);
  ea_t ei;
  for ( ei = s.start_ea; ei < s.start_ea + 040; ei += 2 )
  {
    if ( get_word(ei) )
    {
      create_word(ei, 2);
    }
    else
    {
      del_value(ei);
      del_value(ei+1);
    }
  }
  for ( ei = s.start_ea + 052; ei < s.end_ea; ei += 2 )
  {
    if ( get_word(ei) )
    {
      create_word(ei, 2);
    }
    else
    {
      del_value(ei);
      del_value(ei+1);
    }
  }

  ovt = ml->asect_top;
  if ( s.end_ea != (s.start_ea + ml->asect_top) )
  {
    loadchunk(li, s.end_ea, ml->asect_top - svrEnd, inf_get_baseaddr(), svrEnd, "USER");
    s.end_ea += (ml->asect_top - svrEnd);
    ml->asect_top = svrEnd;
  }

  if ( get_word(s.start_ea + 044) & 01000 )
  {
    if ( begovrtbl == 0 )
    {
      static const ushort chkold[] = { 010046, 010146, 010246, 0421, 010001, 062701 };
      qlseek(li, ovt);
      ushort temp;
      for ( i = 0; i < sizeof(chkold)/2; i++ )
      {
        lread(li, &temp, sizeof(ushort));
        if ( temp != chkold[i] )
          goto nons;
      }
      lread(li, &temp, sizeof(ushort));
      if ( temp != ovt + 076 )
        goto nons;
      qlseek(li, ovt + 0100);
      lread(li, &temp, sizeof(ushort));
      if ( temp != 0104376 )
        goto nons;
      lread(li, &temp, sizeof(ushort));
      if ( temp != 0175400 )
      {
nons:
        warning("OLD-style overlay not implemented.");
        goto stdload;
      }
      begovrtbl = ovt + 0104;
      warning("Loader overlay v3 is not fully tested.");
    }
    else
    {
      qlseek(li, begovrtbl);
    }
    ushort root_top;
    lread(li, &root_top, sizeof(ushort));
    if ( root_top == 0 || (root_top & 1) || root_top >= topPrg )
    {
      warning("Illegal overlay structure. Not implemented.");
      goto stdload;
    }
    msg("loading overlay program...\n");
    netnode temp;    // temporary array for overlay start addresses
    temp.create();
    // load root module at the end of asect (& USER)
    inf_set_start_cs(inf_get_baseaddr()+2);
    loadchunk(li, s.end_ea += 0x20, root_top - ovt, inf_get_start_cs(), ovt, "ROOT");
    add_segment_translation(inf_get_start_cs()<<4,
                            inf_get_baseaddr()<<4); // translate to asect
    ushort loadAddr = root_top, fileBlock, ovrsizeW,
           oldBase = 0, numOvr = 0, numSeg = 0;
    char name[8] = "ov";
    for ( i = 6; loadAddr != 04537; begovrtbl += 6, i += 6 )
    {
      if ( loadAddr != oldBase )
      {
        oldBase = loadAddr;
        ++numOvr;
        numSeg = 1;
      }
      else
      {
        ++numSeg;
      }
      qsnprintf(&name[2], sizeof(name)-2, "%02d_%02d", numOvr, numSeg);
      lread(li, &fileBlock, sizeof(ushort));// file block number
      lread(li, &ovrsizeW, sizeof(ushort)); // segment size in words
      ovrsizeW <<= 1;      // in bytes
      uint32 ovrstart = (inf_get_max_ea() & ~0xF) + (loadAddr & 0xF) + 0x10;
      uint32 sel_l = ushort((ovrstart >> 4) - (loadAddr >> 4));
      loadchunk(li, ovrstart+2, ovrsizeW-2, sel_l, fileBlock*512+2, "OVR");
      add_segment_translation(sel_l<<4, inf_get_baseaddr()<<4); // translate to asect
      add_segment_translation(sel_l<<4, inf_get_start_cs()<<4);  // translate to main
      segment_t *s2 = getseg(ovrstart+2);
      s2->ovrname = ((uint32)numOvr << 16) | numSeg;
      set_segm_name(s2, name);
      temp.altset(i, ovrstart - loadAddr);
      lread(li, &loadAddr, sizeof(ushort)); // segment loading address
    }
    // Entry points loading
    ml->ovrcallbeg = begovrtbl;
    for ( ; loadAddr == 04537; begovrtbl += 8 )
    {
      ushort ovrentry, ovrind, ovraddr;
      lread(li, &ovrentry, sizeof(ushort)); // overlay entry-
      lread(li, &ovrind, sizeof(ushort));  // index+6 in the segments table
      lread(li, &ovraddr, sizeof(ushort)); // segment entry point
      ml_ovrtrans->altset(begovrtbl, temp.altval(ovrind) + ovraddr);
      lread(li, &loadAddr, sizeof(ushort)); // next jsr R5,@#
    }
    ml->ovrcallend = begovrtbl - 8;
    temp.kill();
    ea_t base = s.end_ea - ovt + ml->ovrcallbeg;
    i = ml->ovrcallend - ml->ovrcallbeg + 8;
    set_segm_start(s.end_ea, base+i, SEGMOD_KILL);
    set_segm_name(getseg(base+i), "main");
    loadchunk(li, base -= 0x10, i, inf_get_baseaddr()+1, ml->ovrcallbeg, "TBL");
    ml->ovrtbl_base = (uint32)to_ea(inf_get_baseaddr()+1, 0);
    set_segm_name(getseg(base), "ov_call");
    char labname[17] = "cl_";
    for ( int j = 0; j < i; j += 8 )
    {
      uint32 trans = (uint32)ml_ovrtrans->altval(ml->ovrcallbeg+j);
      qstring sname;
      get_segm_name(&sname, getseg(trans));
      labname[3+7] = '\0';
      if ( sname == &labname[3] )
      {
        ++numSeg;
      }
      else
      {
        numSeg = 1;
        qstrncpy(&labname[3], sname.c_str(), sizeof(labname)-3);
      }
      qsnprintf(&labname[3+7], sizeof(labname)-3-7, "_en%02d", numSeg);
      auto_make_code(trans);
      set_name(trans, &labname[3], SN_IDBENC);
      set_name(base + j, labname, SN_IDBENC);
      create_word(base + j, 2*3);
      op_plain_offset(base + j + 6, 0, get_segm_base(getseg(trans)));
    }
  }
  else
  {
//
//      Load regular file/load root of overlay
//
stdload:
    loadchunk(li, s.end_ea, qlsize(li) - ovt, inf_get_baseaddr(), ovt, "CODE");
  }
  ml_ovrtrans->altset(n_asect,  ml->asect_top);
  ml_ovrtrans->altset(n_ovrbeg, ml->ovrcallbeg);
  ml_ovrtrans->altset(n_ovrend, ml->ovrcallend);
  ml_ovrtrans->altset(n_asciiX, false);
  ml_ovrtrans->altset(n_ovrbas, ml->ovrtbl_base);
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

/*
  IDA LOADER  for QNX 16/32 bit executables
  (c) Zhengxi Ltd., 1998.

  start: 25.07.98
  end:   26.07.98

changed:
  28.07.98  Yury Haron
  09.08.98  Denis Petrov
  10.08.98  YH - patch to new sdk format

*/


#include "../idaldr.h"
#include "lmf.h"

//--------------------------------------------------------------------------
//
//  check input file format. if recognized, then return 1
//  and fill 'fileformatname'.
//  otherwise return 0
//
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  ex_header ex;      // lmf header
  uint32 n_segments; // segment count

  if ( qlread(li, &ex, sizeof(ex)) != sizeof(ex) )
    return 0;
  if ( 0 != ex.lmf_header.rec_type )
    return 0;
  if ( 0 != ex.lmf_header.zero1 )
    return 0;
//  if ( 0x38 != ex.lmf_header.data_nbytes  ) return 0;
  if ( 0 != ex.lmf_header.spare )
    return 0;
  if ( 386  != ex.lmf_definition.cpu
    && 286  != ex.lmf_definition.cpu )
  {
    return 0;
  }
  n_segments = (ex.lmf_header.data_nbytes - sizeof(_lmf_definition))
               / sizeof (uint32);

  if ( (MIN_SEGMENTS > n_segments) || (n_segments > MAX_SEGMENTS) )
    return 0;

  _lmf_data lmf_data;
  lmf_data.segment_index = -1;

  uint64 file_size = qlsize(li);

  for ( uint32 at = sizeof(ex.lmf_header) + ex.lmf_header.data_nbytes;
        lmf_data.segment_index != _LMF_EOF_REC;
        )
  {
    qlseek(li, at, 0);
    if ( sizeof(_lmf_data) != qlread(li, &lmf_data, sizeof(_lmf_data) ) )
      return 0;

    switch ( lmf_data.segment_index )
    {
      case _LMF_DEFINITION_REC:
        return 0;
      case _LMF_COMMENT_REC:
        break;
      case _LMF_DATA_REC:
        break;
      case _LMF_FIXUP_SEG_REC:
        break;
      case _LMF_FIXUP_80X87_REC:
        break;
      case _LMF_EOF_REC:
        if ( lmf_data.offset != sizeof(_lmf_eof) )
          return 0;
        break;
      case _LMF_RESOURCE_REC:
        break;
      case _LMF_ENDDATA_REC:
        if ( lmf_data.offset != 6 /*sizeof(???)*/ )
          return 0;
        break;
      case _LMF_FIXUP_LINEAR_REC:
        break;
      case _LMF_PHRESOURCE:
        return 0;
      default:
        return 0;
    }
    if ( sizeof(lmf_data) + uint64(lmf_data.offset) > file_size )
      return 0;
    at += sizeof(lmf_data) + lmf_data.offset;
  }

  fileformatname->sprnt("QNX %d-executable",
                        (_PCF_32BIT & ex.lmf_definition.cflags)
                      ? 32
                      : 16);
  *processor = "metapc";
  return f_LOADER;
}

//--------------------------------------------------------------------------
//
//  load file into the database.
//
//#define _CODE   0
//#define _DATA   1
//#define _BSS    2
//#define _STACK  3
//#define MAXSEG  2

void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  ex_header ex;         // lmf header
  uint32 n_segments;    // segment count
  uint32 nseg;          // watcom 10.6 not working properly without this!
  qoff64_t filelen = qlsize(li);

  set_processor_type("metapc", SETPROC_LOADER);

  qlseek(li, 0);
  lread(li, &ex, sizeof(ex));

  struct
  {
    uint32 minea,topea;
  } perseg[MAX_SEGMENTS];

  n_segments = (ex.lmf_header.data_nbytes - sizeof(_lmf_definition))
               / sizeof (uint32);
  if ( n_segments > MAX_SEGMENTS )
  {
    msg("QNX: a lot of segments %u\n", n_segments);
    loader_failure("Bad file header format");
  }

  for ( nseg = 0; nseg < n_segments; nseg++ )
  {
    if ( nseg == 0 )
      perseg[nseg].minea = ex.lmf_definition.flat_offset;
    else
      perseg[nseg].minea = (perseg[nseg-1].topea + 0x0FFF) & ~0x0FFF;
    perseg[nseg].topea = perseg[nseg].minea + (ex.segsizes[nseg] & 0x0FFFFFFF);

    if ( perseg[nseg].minea > perseg[nseg].topea )
      loader_failure("Bad file header format");
  }

  uint32 ring = (_PCF_PRIVMASK &ex.lmf_definition.cflags)>>2;

//  uint32 myselector = 0x04 + ring;

// LDT selectors in order.
#define LDT_SELECTOR(nseg) (((nseg)<<3)+0x04+ring)
#define ISFLAT (_PCF_FLAT &ex.lmf_definition.cflags)

  inf_set_baseaddr(0);
  inf_set_app_bitness(ISFLAT ? 32 : 16);
//  if ( ISFLAT )
//  {
//    inf.s_prefflag &= ~PREF_SEGADR;
//    inf.nametype   =  NM_EA4;
//  }

  inf_set_start_ip(ex.lmf_definition.code_offset);
  if ( ex.lmf_definition.code_index >= n_segments )
    loader_failure("Corrupted file");

  if ( ISFLAT )
    inf_set_start_ip(inf_get_start_ip() + perseg[ex.lmf_definition.code_index].minea);
  inf_set_start_cs(LDT_SELECTOR(ex.lmf_definition.code_index));

  _lmf_data lmf_data, lmf_data2;
  lmf_data.segment_index = -1;

  for ( uint32 at = sizeof(ex.lmf_header)+ex.lmf_header.data_nbytes;
        lmf_data.segment_index != _LMF_EOF_REC;
        at += sizeof(lmf_data) + lmf_data.offset )
  {
    if ( qlseek(li, at ) != at )
      loader_failure("Corrupted file");
    lread(li, &lmf_data, sizeof(_lmf_data));
    switch ( lmf_data.segment_index )
    {

      case _LMF_DEFINITION_REC:
        break;

      case _LMF_COMMENT_REC:
        break;

      case _LMF_DATA_REC:
        {
          lread(li, &lmf_data2, sizeof(_lmf_data));
          if ( lmf_data2.segment_index >= n_segments )
            loader_failure("Corrupted file");
          uint32 body_offset = perseg[lmf_data2.segment_index].minea
                             + lmf_data2.offset;
          uint32 body_size   = lmf_data.offset-sizeof(_lmf_data);
          if ( body_offset > body_offset + body_size
            || body_offset + body_size > perseg[lmf_data2.segment_index].topea )
          {
            loader_failure("Corrupted file");
          }

          file2base(li,
                    at+sizeof(_lmf_data)+sizeof(_lmf_data),
                    body_offset,
                    body_offset + body_size,
                    FILEREG_PATCHABLE);
        }
        break;

      case _LMF_FIXUP_SEG_REC:
        {
          fixup_data_t fd(FIXUP_SEG16);
          uint32 n_fixups;
          _lmf_seg_fixup lmf_seg_fixup;
          n_fixups = lmf_data.offset / sizeof(_lmf_seg_fixup);
          while ( n_fixups-- )
          {
            lread(li, &lmf_seg_fixup, sizeof(_lmf_seg_fixup));
            uint32 ea=lmf_seg_fixup.data[0].fixup_offset;
            if ( lmf_seg_fixup.data[0].fixup_seg_index >= n_segments )
              loader_failure("Corrupted file");
            ea += perseg[ lmf_seg_fixup.data[0].fixup_seg_index ].minea; // fix!
            if ( perseg[ lmf_seg_fixup.data[0].fixup_seg_index ].minea > ea
              || ea > perseg[ lmf_seg_fixup.data[0].fixup_seg_index ].topea )
            {
              loader_failure("Corrupted file");
            }
            fd.sel = get_word(ea); //lmf_seg_fixup.data[0].fixup_seg_index;
            fd.set(ea);
          }
        }
        break;

      case _LMF_FIXUP_80X87_REC: // x87 FPU instruction offsets
        break;

      case _LMF_EOF_REC:         // no interesting for ida
        break;

      case _LMF_RESOURCE_REC: // don't support now
        break;

      case _LMF_ENDDATA_REC:  // 6 bytes of uknown data
        break;

      case _LMF_FIXUP_LINEAR_REC:
        break;

      case _LMF_PHRESOURCE: // don't support now
        break;

    }
  }

  uint32 itxt = 0;
  uint32 idat = 0;
  for ( nseg = 0; nseg < n_segments; nseg++ )
  {
    uint32 selector = LDT_SELECTOR(nseg);
    char seg_name[8];
    const char *seg_class;

    if ( (ex.segsizes[nseg]>>28) == _LMF_CODE )
    {
      qsnprintf(seg_name, sizeof(seg_name), "cseg_%.02u", ++itxt);
      seg_class = CLASS_CODE;
    }
    else
    {
      qsnprintf(seg_name, sizeof(seg_name), "dseg_%.02u", ++idat);
      seg_class = CLASS_DATA;
    }

    set_selector(selector, ISFLAT ? 0 : perseg[nseg].minea>>4);

    segment_t s;
    s.sel     = selector;
    s.start_ea = perseg[nseg].minea;
    s.end_ea   = perseg[nseg].topea;
    s.align   = saRelByte;
    s.comb    = scPub;
    s.bitness = (_PCF_32BIT & ex.lmf_definition.cflags) ? 1 : 0;
    bool sparse = (perseg[nseg].topea - perseg[nseg].minea) > filelen;
    int flags = (sparse ? ADDSEG_SPARSE : 0) | ADDSEG_NOSREG;
    if ( !add_segm_ex(&s, seg_name, seg_class, flags) )
      loader_failure();
    if ( _PCF_32BIT &ex.lmf_definition.cflags )
      set_segm_addressing(getseg(perseg[nseg].minea), 1); // 32bit
  }

  set_default_dataseg(LDT_SELECTOR(ex.lmf_definition.argv_index));



  create_filename_cmt();
  add_pgm_cmt("Version     : %d.%d",
              ex.lmf_definition.version_no>>8,
              ex.lmf_definition.version_no&255);

  add_pgm_cmt("Priv level  : %d",
              (_PCF_PRIVMASK &ex.lmf_definition.cflags)>>2);

  char str[MAXSTR], *p = str;
  char *e = str + sizeof(str);


  if ( _PCF_LONG_LIVED & ex.lmf_definition.cflags )
    APPEND(p, e, " LONG_LIVED");
  if ( _PCF_32BIT & ex.lmf_definition.cflags )
  {
    if ( p != str )
      APPCHAR(p, e, ',');
    APPEND(p, e, " 32BIT");
  }
  if ( ISFLAT )
  {
    if ( p != str )
      APPCHAR(p, e, ',');
    APPEND(p, e, " FLAT");
  }
  if ( _PCF_NOSHARE & ex.lmf_definition.cflags )
  {
    if ( p != str )
      APPCHAR(p, e, ',');
    APPEND(p, e, " NOSHARE");
  }
  if ( p == str ) APPEND(p, e, " None");
  add_pgm_cmt("Code flags  :%s", str);

  // ig 08.09.00: Automatically load the Watcom signature file
  plan_to_apply_idasgn(ISFLAT ? "wa32qnx" : "wa16qnx");
}

//----------------------------------------------------------------------
//
//  LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,        // loader flags
//
//  check input file format. if recognized, then return 1
//  and fill 'fileformatname'.
//  otherwise return 0
//
  accept_file,
//
//  load file into the database.
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

#define BUFFSIZE  ((255+6)*2+76)    // buffer to read the string
#define MAX_BYTES  24               // Max number of bytes per line for write
#define SEGMENTGAP (1*1024*1024)    // make new segment if gap between addresses
                                    // is greater than this value
#define SPARSE_GAP (256*1024)       // switch to sparse storage if the gap
                                    // is greater than this value

/*
 *  This Loader Module is written by Ilfak Guilfanov and
 *                        rewriten by Yury Haron
 *
 */

/*
   Interesting documentation:

   http://www.intel.com/design/zapcode/Intel_HEX_32_Format.doc
   http://www.keil.com/support/docs/1584.htm

*/

#include "../idaldr.h"

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *,
        linput_t *li,
        const char *)
{
  char str[80];
  if ( qlgets(str, sizeof(str), li) == nullptr )
    return 0;

  const char *p = str;
  while ( *p == ' ' )
    p++;

  int type = 0;
  if ( qisxdigit((uchar)*(p+1)) && qisxdigit((uchar)*(p+2)) )
  {
    switch ( *p )
    {
      case ':':
        p = "Intel Hex Object Format";
        type = f_HEX;
        break;

      case ';':
        p = "MOS Technology Hex Object Format";
        type = f_MEX;
        break;

      case 'S':
        p = "Motorola S-record Format";
        type = f_SREC;
      default:
        break;

    }
  }
  if ( type != 0 )
    *fileformatname = p;
  return type;
}

//--------------------------------------------------------------------------
// this struct was created to save space in the data segment (yes, we were
// counting each byte at that time)
static struct local_data
{
  union
  {
    char   *ptr;  // load
    int    sz;    // write
  };
  union
  {
    uint32 ln;    // load
    int size;     // write
  };
  ushort sum;     // load/write
  uchar  len;     // load
} lc;

//--------------------------------------------------------------------------
NORETURN static void errfmt(void)
{
  loader_failure("Bad hex input file format, line %u", lc.ln);
}

//--------------------------------------------------------------------------
// reads the specified number of bytes from the input line
// if size==0, then initializes itself for a new line
static uint32 hexdata(int size)
{
  int i = size;
  if ( i == 0 )
  {
    i = 2;
  }
  else
  {
    if ( lc.len < i )
      errfmt();
    lc.len -= (uchar)i;
    i <<= 1;
  }
  char n[10];
  char *p = n;
  while ( i-- )
    *p++ = *lc.ptr++;
  *p = '\0';
  char *endp;
  uint32 data = strtoul(n, &endp, 16);
  if ( endp != p )
    errfmt();
  switch ( size )
  {
    case 0:
      lc.len = (uchar)data;
      lc.sum = lc.len;
      break;

    case 4:
      lc.sum += (uchar)(data >> 24);
    case 3:
      lc.sum += (uchar)(data >> 16);
    case 2:
      lc.sum += (uchar)(data >> 8);
    default:  // 1
      lc.sum += (uchar)data;
      break;
  }
  return data;
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort neflag, const char * /*fileformatname*/)
{
  ea_helper_t eah;
  eah.setup(false);   // file format does not support 64-bit data
  inf_set_64bit(false);

  memset(&lc, 0, sizeof(local_data));
  inf_set_start_ip(BADADDR);          // f_SREC without start record

  processor_t &ph = PH;
  bool iscode = (neflag & NEF_CODE) != 0;
  uint bs = iscode ? ph.cbsize() : ph.dbsize();   // number of bytes
  ea_t start_ea = to_ea(inf_get_baseaddr(), 0);
  sel_t sel = setup_selector(start_ea >> 4);
  bool segment_created = false;

  bool cvt_to_bytes = false;
  if ( ph.id == PLFM_PIC )
  {
    // pic12xx and pic16xx use 12-bit and 14-bit words in program memory
    // pic18xx uses 16-bit opcodes but byte addressing
    if ( strncmp(inf_get_procname().c_str(), "PIC18", 5) != 0 )
    {
      static const char *const form =
//      "PIC HEX file addressing mode\n"
//      "\n"
      "There are two flavors of HEX files for PIC: with word addressing\n"
      "and with byte addressing. It is not possible to recognize the\n"
      "flavor automatically. Please specify what addressing mode should\n"
      "be used to load the input file. If you don't know, try both and\n"
      "choose the one which produces the more meaningful result\n";
      int code = ask_buttons("~B~yte addressing",
                             "~W~ord addressing",
                             "~C~ancel",
                             1,
                             form);
      switch ( code )
      {
        case 1:
          break;
        case 0:
          cvt_to_bytes = true;
          break;
        default:
          loader_failure();
      }
    }
  }

  bool bs_addr_scale = true;
  if ( ph.id == PLFM_TMS320C28 )
    bs_addr_scale = false;

  filetype_t ftype = inf_get_filetype();
  char rstart = (ftype == f_SREC) ? 'S'
              : (ftype == f_HEX)  ? ':'
              :                     ';';
  ea_t addr;
  ea_t end_ea = 0;
  ea_t seg_start = 0;
  ea_t subs_addr20 = 0;
  ea_t subs_addr32 = 0;
  bool bigaddr = false;
  char line[BUFFSIZE];
  for ( lc.ln = 1; qlgets(line, BUFFSIZE, li); lc.ln++ )
  {
    char *p = line;
    while ( *p == ' ' )
      ++p;
    if ( *p == '\n' || *p == '\r' )
      continue;
    if ( *p++ != rstart )
      errfmt();

    int sz = 2;
    int mode = (ftype == f_SREC) ? (uchar)*p++ : 0x100;
    lc.ptr = p;
    hexdata(0);
    if ( mode == 0x100 )
    {
      if ( !lc.len )
        break;
      lc.len += 2;
      if ( ftype == f_HEX )
        ++lc.len;
    }
    else
    {
      switch ( mode )
      {
        default:
          errfmt();

        case '0':
        case '5':
          continue;

        case '3':
        case '7':
          ++sz;
          // fallthrough
        case '2':
        case '8':
          ++sz;
          // fallthrough
        case '1':
        case '9':
          if ( mode > '3' )
            mode = 0;
          --lc.len;
          break;
      }
    }
    addr = hexdata(sz);
    if ( ftype != f_SREC && bs_addr_scale )
      addr = addr / bs;
    if ( !mode )
    {
      inf_set_start_ip(addr);
      continue;
    }

    if ( ftype == f_HEX )
    {
      int type = hexdata(1);      // record type
      switch ( type )
      {
        case 0xFF:                // mitsubishi hex format
        case 4:                   // Extended linear address record (bits 16..31 of the start address)
          {
            uint32 seg_addr = uint32(hexdata(2) << 16);
            if ( bs_addr_scale )
              seg_addr /= bs;
            subs_addr32 = seg_addr;
          }
          break;
        case 2:                   // Extended segment address record (bits 4..19 of the start address)
          {
            uint32 seg_addr = uint32(hexdata(2) << 4);
            if ( bs_addr_scale )
              seg_addr /= bs;
            subs_addr20 = seg_addr;
          }
          break;
        case 5:                  // start address  (ARM)
          {
            uint32 start_addr = hexdata(4);
            if ( ph.has_code16_bit() && (start_addr & 1) != 0 )
            {
              processor_t::set_code16_mode(start_addr, true);
              start_addr &= ~1;
            }
            inf_set_start_ip(start_addr);
            inf_set_start_ea(start_addr);
          }
          break;
      }
      if ( type != 0 )
      {
        if ( type == 1 )
          break;                  // end of file record
        continue;                 // not a data record
      }
    }
    // add the extended address bits
    addr += subs_addr20;
    addr += subs_addr32;
    if ( lc.len )
    {
      ea_t top = eah.trunc_uval(addr + lc.len / bs);
      p = line;
      while ( lc.len )
      {
        *p++ = (uchar)hexdata(1);
        if ( cvt_to_bytes ) // pic
          *p++ = '\0';
      }
      if ( top >= 0x10000 )
        bigaddr = true;
      addr = eah.trunc_uval(addr + start_ea);
      show_addr(addr);
      top = eah.trunc_uval(top + start_ea);
      if ( top > end_ea || !segment_created )
      {
        asize_t delta = addr - end_ea;
        if ( delta >= SEGMENTGAP )
          segment_created = false; // force creation of new segment

        end_ea = top;
        if ( neflag & NEF_SEGS )
        {
          if ( !segment_created )
          {
            if ( !add_segm(sel, addr, end_ea, nullptr, iscode ? CLASS_CODE : CLASS_DATA) )
              loader_failure();
            segment_created = true;
            seg_start = addr;
          }
          else
          {
            int flags = delta > SPARSE_GAP ? SEGMOD_SPARSE : 0;
            set_segm_end(seg_start, end_ea, flags);
          }
        }
      }
      if ( seg_start > addr )
      {
        if ( (neflag & NEF_SEGS) != 0 )
        {
          int flags = seg_start-addr > SPARSE_GAP ? SEGMOD_SPARSE : 0;
          set_segm_start(seg_start, addr, flags);
        }
        seg_start = addr;
      }
      mem2base(line, addr, top, -1);
    }
    {
      ushort chi;       // checksum
      ++lc.len;
      switch ( ftype )
      {
        case f_SREC:
          chi = (uchar)(~lc.sum);
          chi ^= (uchar)hexdata(1);
          break;
        case f_HEX:
          hexdata(1);
          chi = (uchar)lc.sum;
          break;
        default:  // MEX
          ++lc.len;
          chi = lc.sum;
          chi -= (ushort)hexdata(2);
          break;
      }
      if ( chi )
      {
        static bool displayed = false;
        if ( !displayed )
        {
          displayed = true;
          warning("Bad hex input file checksum, line %u. Ignore?", lc.ln);
        }
      }
    }
  }

  if ( (neflag & NEF_SEGS) != 0 )
  {
    if ( bigaddr )
    {
      set_segm_addressing(get_first_seg(), 1);
      if ( ph.id == PLFM_386 )
        inf_set_lflags(inf_get_lflags() | LFLG_PC_FLAT);
    }
    set_default_dataseg(sel);
    inf_set_start_cs(sel);
  }
  else
  {
    enable_flags(start_ea, end_ea, STT_CUR);
  }
  inf_set_af(inf_get_af() & ~AF_FINAL); // behave as a binary file

  create_filename_cmt();
}

//--------------------------------------------------------------------------
static int set_s_type(ea_t addr)
{
  int off = 0;
  lc.sz = 4;
  lc.size += 3;
  if ( addr >= 0x10000 )
  {
    ++off;
    lc.sz += 2;
    lc.sum += (uchar)(addr >> 16);
    ++lc.size;
    if ( addr >= 0x01000000 )
    {
      ++off;
      lc.sz += 2;
      lc.sum += (uchar)(addr >> 24);
      ++lc.size;
    }
  }
  return off;
}

//--------------------------------------------------------------------------
GCC_DIAG_OFF(format-nonliteral);
int idaapi write_file(FILE *fp, const char * /*fileformatname*/)
{
//#define TEST_COMPILATION
#ifdef TEST_COMPILATION
#  define DECL_FMT(x, y) static const char *const x = y
#else
#  define DECL_FMT(x, y) static char x[] = y
#endif
  DECL_FMT(fmt0, "%02X%0*" FMT_EA "X%s%0?X\r\n");
  DECL_FMT(fmt1, "?00?00001FF\r\n");
  DECL_FMT(fone, "%02X");

  ea_t base = to_ea(inf_get_baseaddr(), 0);
  if ( inf_get_min_ea() < base )
    base = BADADDR;

  if ( fp == nullptr )
  {
    if ( inf_get_filetype() == f_SREC )
      return 1;
    ea_t ea1 = inf_get_max_ea() - inf_get_min_ea();
    if ( ea1 <= 0x10000 )
      return 1;
    ea_t strt = 0;
    ea_t addr;
    for ( addr = inf_get_min_ea(); addr < inf_get_max_ea(); )
    {
      segment_t *ps = getseg(addr);
      if ( ps == nullptr || ps->type != SEG_IMEM )
      {
        if ( is_loaded(addr) )
          break;
        if ( base != BADADDR )
        {
          if ( --ea1 <= 0x10000 )
            return 1;
        }
        else
        {
          ++strt;
        }
        ++addr;
        continue;
      }
      if ( strt )
      {
        ea1 -= strt;
        if ( ea1 != 0x10000 )
          return 1;
        strt = 0;
      }
      ea1 -= (ps->end_ea - addr);
      if ( ea1 < 0x10000 )
        return 1;
      ++ea1;
      addr = ps->end_ea;
    }
    if ( base == BADADDR )
    {
      segment_t *ps = getseg(addr);
      ea1 -= (ps == nullptr) ? addr : ps->start_ea;
      if ( ea1 <= 0x10000 )
        return 1;
    }
    if ( addr == inf_get_max_ea() )
      return 0;
    for ( base = inf_get_max_ea()-1; base > addr; )
    {
      segment_t *ps = getseg(base);
      if ( ps == nullptr || ps->type != SEG_IMEM )
      {
        if ( is_loaded(base) )
          break;
        if ( --ea1 <= 0x10000 )
          return 1;
        --base;
        continue;
      }
      ea1 -= (base - ps->start_ea);
      if ( ea1 < 0x10000 )
        return 1;
      ++ea1;
      base = ps->start_ea;
    }
    return 0;
  }

  char ident;
  const char *found = qstrrchr(fmt0, '?');
  QASSERT(20067, found != nullptr);
  int fmt0_marker = ((char *) found) - fmt0;
  fmt0[fmt0_marker] = '2';
  switch ( inf_get_filetype() )
  {
    case f_SREC:
      ident = 'S';
      break;
    case f_HEX:
      ident = ':';
      fmt1[3] = '0';
      break;
    default:
      ident = ';';
      fmt0[fmt0_marker] = '4';
      fmt1[3] = '\0';
      break;
  }
  fmt1[0] = ident;
  lc.sz = 4;

  ea_t strt = inf_get_start_ip();
  for ( ea_t ea1 = inf_get_min_ea(); ea1 < inf_get_max_ea(); )
  {
    char str[(2 * MAX_BYTES) + 3];
    char *const end = str + sizeof(str);
    if ( !is_loaded(ea1) || segtype(ea1) == SEG_IMEM )
    {
      ++ea1;
      continue;
    }
    if ( base == BADADDR )
    {
      segment_t *ps = getseg(ea1);
      base = ps == nullptr ? ea1 : ps->start_ea;
      if ( strt != BADADDR )
        strt += inf_get_min_ea() - base;
    }
    ea_t addr = ea1 - base;
    lc.sum = (uchar)addr + (uchar)(addr >> 8);
    char *p = str;
    if ( inf_get_filetype() == f_HEX )
    {
      *p++ = '0';
      *p++ = '0';
    }
    lc.size = 0;
    do
    {
      uchar b = get_byte(ea1++);
      p += qsnprintf(p, end-p, fone, (unsigned)b);
      lc.sum += b;
    } while ( ++lc.size < MAX_BYTES
           && ea1 < inf_get_max_ea()
           && is_loaded(ea1)
           && segtype(ea1) != SEG_IMEM );
    qfputc(ident, fp);
    if ( inf_get_filetype() == f_SREC )
    {
      char type = '1' + (char)set_s_type(addr);
      qfputc(type, fp);
      ++lc.sum;  // correct to NOT
    } // else addr = (ushort)addr; // force check
    lc.sum += (ushort)lc.size;
    if ( inf_get_filetype() != f_MEX )
      lc.sum = (uchar)(0-lc.sum);
    qfprintf(fp, fmt0, lc.size, lc.sz, addr, str, lc.sum);
  }
  if ( inf_get_filetype() != f_SREC )
  {
    qfprintf(fp, "%s", fmt1);
  }
  else if ( strt != BADADDR )
  {
    qfputc(ident, fp);
    lc.sum  = 0;
    lc.size = 0;
    char type = '9' - (char)set_s_type(strt);
    qfputc(type, fp);
    lc.sum = (~(lc.size + lc.sum)) & 0xFF;
    qfprintf(fp, fmt0, lc.size, lc.sz, strt, &fone[sizeof(fone)-1], lc.sum);
  }
  return 1;
}
GCC_DIAG_ON(format-nonliteral);

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  LDRF_REQ_PROC,                // requires the target processor to the set
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
  write_file,
  nullptr,
  nullptr,
};

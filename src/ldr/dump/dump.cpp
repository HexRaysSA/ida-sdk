/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov (ig@datarescue.com)
 *                                              http://www.datarescue.com
 *      ALL RIGHTS RESERVED.
 *
 */

#include "../idaldr.h"

//--------------------------------------------------------------------------
static int make_words(char *line, char **words, int maxwords)
{
  while ( qisspace(*line) )
    line++;
  int i;
  for ( i=0; *line && i < maxwords; i++ )
  {
    words[i] = line;
    while ( !qisspace(*line) && *line != '\0' )
      line++;
    if ( *line != '\0' )
      *line++ = '\0';
    while ( qisspace(*line) )
      line++;
  }
  return i;
}

//--------------------------------------------------------------------------
inline uint64 hex(char *&word)
{
  return strtoull(word, &word, 16);
}

//--------------------------------------------------------------------------
inline uint64 oct(char *&word)
{
  return strtoull(word, &word, 8);
}

#define FAILED                                 \
  do                                           \
  {                                            \
    deb(IDA_DEBUG_LDR,                         \
        "failed at %d (input file line %d)\n", \
        __LINE__,                              \
        nl);                                   \
    return 0;                                  \
  } while ( false )

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *,
        linput_t *li,
        const char *)
{
  char line[MAXSTR];
  char *words[MAXSTR];

  // We try to interpret the input file as a text
  // file with a dump format, i.e. all lines should look like

// 00000020:  59 69 74 54-55 B6 3E F7-D6 B9 C9 B9-45 E6 A4 52
// 0020: 59 69 74 54 55 B6 3E F7 D6 B9 C9 B9 45 E6 A4 52
// 1000: 12 23 34 56 78
// 0100: 31 C7 1D AF 32 04 1E 32 05 1E 3C 32 07 1E 21 D9
// 12 23 34 56 78

  // and similar lines
  // We allow non-ascii characters at the end of the line
  // We skip empty lines

  ssize_t p0len = -1;    // length of the first word's hex part
  char w0sep[10];        // separator after the first word
  w0sep[0] = '\0';
  int nl = 0;
  int nontrivial_line_count = 0;
  bool no_more_lines = false;
  bool has_star = false;
  uint64 adr;
  uint64 oldadr=0;
  while ( qlgets(line, sizeof(line), li) )
  {
    nl++;
    strrpl(line, '-', ' ');
    int nw = make_words(line, words, qnumber(words));
    if ( line[0] == ';' || line[0] == '#' || nw == 0 )
    {
      if ( has_star )
        FAILED;
      continue;
    }
    if ( no_more_lines )
      FAILED;
    // od -x format may contain '*' lines which mean repetition
    if ( strcmp(words[0], "*") == 0 && nw == 1 )
    {
      if ( nontrivial_line_count == 0 )
        FAILED;
      if ( has_star )
        FAILED;
      has_star = true;
      continue;
    }
    has_star = false;
    nontrivial_line_count++;
    // the first word must be a number (more than one digit)
    char *ptr = words[0];
    adr = hex(ptr);
    ssize_t p0 = ptr - words[0];
    if ( p0 <= 1 || p0 > 16 )
      FAILED;
    if ( nontrivial_line_count > 1 && p0 < p0len )
      FAILED;
    p0len = p0;
    // take the separator from the first line
    if ( nontrivial_line_count == 1 )
    {
      qstrncpy(w0sep, ptr, sizeof(w0sep));
      while ( *ptr )
        if ( strchr(":>-.", *ptr++) == nullptr )
          FAILED;
    }
    else
    {
      if ( strcmp(w0sep, ptr) != 0 )
        FAILED;
    }
    bool haspref = p0len >= 4 || w0sep[0] != '\0';
    if ( haspref )
    {
      // if the line contains only the address, then don't accept lines anymore
      if ( nw == 1 )
      {
        if ( nontrivial_line_count == 1 )
          FAILED;
        no_more_lines = true;
        if ( adr <= oldadr )
          FAILED;
      }
      else
      {
        // the remaining words should be numbers with at least 1 position
        // (at least the second word should be so)
        ptr = words[1];
        hex(ptr);
        if ( ptr == words[1] )
          FAILED;
      }
    }
    oldadr = adr;
  }
  if ( nontrivial_line_count == 0 || has_star )
    FAILED;

  *fileformatname = "Dump file";
  return 1;
}

//--------------------------------------------------------------------------
static uchar bytes[MAXSTR/2];
static bool iscode;
static sel_t sel;
static ea_t sea;
static ea_t eea;
static ushort neflag;

static void copy(const ea_t ea, const ea_t top)
{
  if ( sea == BADADDR )
  {
    if ( neflag & NEF_SEGS )
    {
      const char *sname = iscode ? "CODE" : "DATA";
      sel = setup_selector(0);
      if ( add_segm(sel, ea, top, sname, sname) && top == BADADDR )
      {
        // in this case the segment will be created 1 byte size and we have
        // to extend it
        set_segm_end(ea, top, 0);
      }
    }
    sea = ea;
    eea = top;
  }
  else
  {
    if ( eea < top )
    { // if the gap > 256KB, use sparse storage
      int flags = top - eea > 256 * 1024 ? SEGMOD_SPARSE : 0;
      eea = top;
      set_segm_end(sea, eea, flags);
    }
  }
  mem2base(bytes, ea, top, -1);
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort _neflag, const char * /*fileformatname*/)
{
  char line[MAXSTR];
  char *words[MAXSTR];

  neflag = _neflag;
  iscode = (neflag & NEF_CODE) != 0;
  sel = BADSEL;
  sea = BADADDR;
  ea_t ea = 0;
  ea_t top= 0;
  bool octpref = false;
  bool octnum  = false;
  size_t fill = 0;

  // Since we made all the checks in accept_file,
  // here we don't repeat them

  size_t max_p0len = 0;
  char w0sep[10];        // separator after the first word
  w0sep[0] = '\0';
  int nontrivial_line_count = 0;
  while ( qlgets(line, sizeof(line), li) )
  {
    strrpl(line, '-', ' ');
    if ( line[0] == ';' || line[0] == '#' )
      continue;
    int n = make_words(line, words, qnumber(words));
    if ( n == 0 )
      continue;
    nontrivial_line_count++;
    ssize_t bi;
    // od -x format may contain '*' lines which means repetition
    if ( streq(words[0], "*") && n == 1 )
    {
      fill = size_t(top - ea);
      octpref = true;             // od -x have octal prefixes
      continue;
    }
    // the first word must be a number (more than one digit)
    char *ptr = words[0];
    uint64 w0 = octpref ? oct(ptr) : hex(ptr);
    // length of the first word's hex part
    size_t p0len = ptr - words[0];
    if ( p0len > max_p0len )
      max_p0len = p0len;

    // take the separator from the first line
    if ( nontrivial_line_count == 1 )
      qstrncpy(w0sep, ptr, sizeof(w0sep));

    // process '*' and fill the gap
    if ( fill > 0 )
    {
      while ( top < w0 )
      {
        ea = top;
        top = ea + fill;
        copy(ea, top);
      }
    }

    int idx = 0;
    if ( w0sep[0] != '\0' || p0len >= 4 )
    {
      if ( nontrivial_line_count > 1 && !octpref && top != w0 )
      {
        // strange, the sequence is not contiguous
        // check if the prefixes are octal (od -x)
        ptr = words[0];
        if ( oct(ptr) == top )
        {
          octpref = true;
          ptr = words[0];
          w0 = oct(ptr);
        }
      }
      ea = w0;
      idx = 1;
    }
    else
    {
      ea = top;
    }
    for ( bi=0; idx < n; idx++ ) //lint !e443
    {
      ptr = words[idx];
      if ( nontrivial_line_count == 1 && !octnum && strlen(ptr) == 6 )
      {
        oct(ptr);
        if ( ptr-words[idx] == 6 )
          octnum = true;
        ptr = words[idx];
//        msg("ptr=%s octnum=%d\n", ptr, octnum);
      }
      uint32 b = octnum ? oct(ptr) : hex(ptr);
      ssize_t nc = ptr - words[idx];
      if ( nc < 2 )
      {
        // we tolerate one-letter separators between numbers
        if ( words[idx][1] == '\0' && strchr("\xA6|-:", words[idx][0]) != nullptr )
          continue;
        break;
      }
      nc /= octnum ? 3 : 2;             // number of bytes
      *(uint32 *)&bytes[bi] = b;
      bi += nc;
    }
    ea_t space_end = EAH.ea_space_end();
    bool overflow = !is_add_ok(ea, bi);
    top = ea + bi;
    if ( !overflow && top > space_end )
      overflow = true;
    if ( overflow )
    {
      msg("The size 0x%a is too big and does not fit into the address space, "
          "truncating to 0x%a\n",
          asize_t(bi),
          space_end - ea);
      top = space_end;
    }
    copy(ea, top);
  }

  if ( neflag & NEF_SEGS )
  {
    // 1 means 32-bit, 0 means 16-bit
    size_t bitness = eea >= 0x10000
                  || max_p0len > 4
                  || PH.get_default_segm_bitness(inf_is_64bit());
#ifdef __EA64__
    if ( eea > ea_t(0x100000000ull) || max_p0len > 8 )
      bitness = 2; // 64
#endif
    inf_set_app_bitness(1 << (4 + bitness)); // 16, 32 or 64
    set_segm_addressing(getseg(sea), bitness);
    set_default_dataseg(sel);
  }
  if ( (neflag & NEF_RELOAD) == 0 )
    create_filename_cmt();
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  LDRF_REQ_PROC              // requires the target processor to the set
| LDRF_RELOAD,               // supports reloading the input file
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
  nullptr,
  nullptr,
};

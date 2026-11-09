/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "hppa.hpp"

//--------------------------------------------------------------------------
struct cond_text_t
{
  const char *text;
  char c;       // -1 means any value
  char f;       // -1 means any value
};

static const cond_text_t D3[] = // and D4 combined
{            // c  f
  { "",         0, 0 },      // never
  { "=",        1, 0 },      // op1 is equal to op2 (word)
  { "<",        2, 0 },      // op1 is less than op2 (signed word)
  { "<=",       3, 0 },      // op1 is less than or equal to op2 (signed word)
  { "<<",       4, 0 },      // op1 is less than op2 (unsigned word)
  { "<<=",      5, 0 },      // op1 is less than or equal to op2 (unsigned word)
  { "sv",       6, 0 },      // op1 minus op2 overflows (signed word)
  { "od",       7, 0 },      // op1 minus op2 is odd
  { "tr",       0, 1 },      // always
  { "<>",       1, 1 },      // op1 is not equal to op2 (word)
  { ">=",       2, 1 },      // op1 is greater than or equal to op2 (signed word)
  { ">",        3, 1 },      // op1 is greater than op2 (signed word)
  { ">>=",      4, 1 },      // op1 is greater than or equal to op2 (unsigned word)
  { ">>",       5, 1 },      // op1 is greater than op2 (unsigned word)
  { "nsv",      6, 1 },      // op1 minus op2 does not overflow (signed word)
  { "ev",       7, 1 },      // op1 minus op2 is even
  { nullptr },
};

static const cond_text_t D5[] =  // f should be 0!
{            // c  f
  { "*<<",      0, 0 },      // op1 is less than op2 (unsigned doubleword)
  { "*=",       1, 0 },      // op1 is equal to op2 (doubleword)
  { "*<",       2, 0 },      // op1 is less than op2 (signed doubleword)
  { "*<=",      3, 0 },      // op1 is less than or equal to op2 (signed doubleword)
  { "*>>=",     4, 0 },      // op1 is greater than or equal to op2 (unsigned doubleword)
  { "*<>",      5, 0 },      // op1 is not equal to op2 (doubleword)
  { "*>=",      6, 0 },      // op1 is greater than or equal to op2 (signed doubleword)
  { "*>",       7, 0 },      // op1 is greater than op2 (signed doubleword)
  { nullptr },
};

static const cond_text_t D6[] = // and D7 combined
{            // c  f
  { "",         0, 0 },      // never
  { "=",        1, 0 },      // op1 is equal to negative of op2 (word)
  { "<",        2, 0 },      // op1 is less than negative of op2 (signed word)
  { "<=",       3, 0 },      // op1 is less than or equal to negative of op2 (signed word)
  { "nuv",      4, 0 },      // op1 plus op2 does not overflow (unsigned word)
  { "znv",      5, 0 },      // op1 plus op2 is zero or no overflow (unsigned word)
  { "sv",       6, 0 },      // op1 plus op2 overflows (signed word)
  { "od",       7, 0 },      // op1 plus op2 is odd
  { "tr",       0, 1 },      // always
  { "<>",       1, 1 },      // op1 is not equal to negative of op2 (word)
  { ">=",       2, 1 },      // op1 is greater than or equal to negative of op2 (signed word)
  { ">",        3, 1 },      // op1 is greater than negative of op2 (signed word)
  { "uv",       4, 1 },      // op1 plus op2 overflows (unsigned word)
  { "vnz",      5, 1 },      // op1 plus op2 is nonzero and overflows (unsigned word)
  { "nsv",      6, 1 },      // op1 minus op2 does not overflow (signed word)
  { "ev",       7, 1 },      // op1 minus op2 is even
  { nullptr },
};

static const cond_text_t D8[] = // d should be 0!
{            // c  f
  { "",         0, 0 },      // never
  { "=",        1, 0 },      // op1 is equal to negative of op2 (word)
  { "<",        2, 0 },      // op1 is less than negative of op2 (signed word)
  { "<=",       3, 0 },      // op1 is less than or equal to negative of op2 (signed word)
  { "nuv",      4, 0 },      // op1 plus op2 does not overflow (unsigned word)
  { "*=",       5, 0 },      // op1 is equal to negative of op2 (doubleword)
  { "*<",       6, 0 },      // op1 is less than negative of op2 (signed doubleword)
  { "*<=",      7, 0 },      // op1 is less than or equal to negative of op2 (signed doubleword)
  { "tr",       0, 1 },      // always
  { "<>",       1, 1 },      // op1 is not equal to negative of op2 (word)
  { ">=",       2, 1 },      // op1 is greater than or equal to negative of op2 (signed word)
  { ">",        3, 1 },      // op1 is greater than negative of op2 (signed word)
  { "uv",       4, 1 },      // op1 plus op2 overflows (unsigned word)
  { "*<>",      5, 1 },      // op1 is not equal to negative of op2 (doubleword)
  { "*>=",      6, 1 },      // op1 is greater than or equal to negative of op2 (signed doubleword)
  { "*>",       7, 1 },      // op1 is greater than negative of op2 (signed doubleword)
  { nullptr },
};

static const cond_text_t D9[] = // and D10 combined
{            // c  f
  { "",         0, 0 },      // never
  { "=",        1, 0 },      // all bits in word are 0
  { "<",        2, 0 },      // leftmost bit in word is 1
  { "<=",       3, 0 },      // leftmost bit in word is 1 or all bits in word are 0
  { "od",       7, 0 },      // rightmost bit is 1
  { "tr",       0, 1 },      // always
  { "<>",       1, 1 },      // some bits in word are 1
  { ">=",       2, 1 },      // leftmost bit in word is 0
  { ">",        3, 1 },      // leftmost bit in word is 0 and some bits in word are 1
  { "ev",       7, 1 },      // rightmost bit is 0
};


static const cond_text_t D11[] = // and D12 combined
{            // c  f
  { "",         0, 0 },      //     never
  { "swz",      1, 0 },      // 64! some word zero
  { "sbz",      2, 0 },      //     some byte zero
  { "shz",      3, 0 },      //     some halfword zero
  { "sdc",      4, 0 },      //     some digit carry
  { "swc",      5, 0 },      // 64! some word carry
  { "sbc",      6, 0 },      //     some byte carry
  { "shc",      7, 0 },      //     some halfword carry
  { "tr",       0, 1 },      //     always
  { "nwz",      1, 1 },      // 64! no word zero
  { "nbz",      2, 1 },      //     no byte zero
  { "nhz",      3, 1 },      //     no halfword zero
  { "ndc",      4, 1 },      //     no digit carry
  { "nwc",      5, 1 },      // 64! no word carry
  { "nbc",      6, 1 },      //     no byte carry
  { "nhc",      7, 1 },      //     no halfword carry
};


static const cond_text_t D13[] = // and D14 combined (f should be 0)
{            // c  f
  { "",         0, 0 },      // never
  { "=",        1, 0 },      // all bits in word are 0
  { "<",        2, 0 },      // leftmost bit in word is 1
  { "od",       3, 0 },      // rightmost bit is 1
  { "tr",       4, 0 },      // always
  { "<>",       5, 0 },      // some bits in word are 1
  { ">=",       6, 0 },      // leftmost bit in word is 0
  { "ev",       7, 0 },      // rightmost bit is 0
};

static const cond_text_t D15[] = // (f should be 0)
{            // c  f
  { "<",        0, 0 },      // leftmost bit in word is 1
  { ">=",       1, 0 },      // leftmost bit in word is 0
};

static char *append_conds(
        const cond_text_t *table,
        int c,
        int f,
        int d,
        char *ptr,
        char *end)
{
  if ( !d && table == D11 && (c == 1 || c == 5) )
    return nullptr;
  while ( table->text != nullptr )
  {
    if ( table->c == c && table->f == f )
    {
      if ( table->text[0] != '\0' )
      {
        APPCHAR(ptr, end, ',');
        if ( d != 0 )
          APPCHAR(ptr, end, '*');
        APPEND(ptr, end, table->text);
      }
      return ptr;
    }
    table++;
  }
  return nullptr;
}

//--------------------------------------------------------------------------
// short displacement load and store instruction completers
static const char *h1_comp(int a, int m, int im5)
{
  if ( m )
  {
    if ( a )
      return ",mb";              // a=1 m=1
    return im5
         ? ",ma"                 // a=0 m=1 im5 != 0
         : ",o";                 // a=0 m=1 im5 == 0
  }
  return "";                     //     m=0
}

//--------------------------------------------------------------------------
// store bytes instruction completers
static const char *h2_comp(int a, int m)
{
  static const char *const suffixes[] =
  {
    "",         // beginning case, don't modify base register
    ",b,m",     // beginning case, modify base register
    ",e",       // ending case, don't modify base register
    ",e,m"      // ending case, modify base register
  };
  int idx = (a<<1) | m;
  return suffixes[idx & 3];
}

//--------------------------------------------------------------------------
// indexed instruction completers
static const char *h3_comp(int u, int m)
{
  static const char *const suffixes[] =
  {
    "",         // no index shift, don't modify base register
    ",m",       // no index shift, modify base register
    ",s",       // shift index by data size, don't modify base register
    ",sm"       // shift index by data size, modify base register
  };
  int idx = (u<<1) | m;
  return suffixes[idx & 3];
}

//--------------------------------------------------------------------------
static char *append_cc(char *ptr, const char *end, int cc, bool isload)
{
  static const char *const ld_suffixes[] = { "", nullptr,  ",sl", nullptr };
  static const char *const st_suffixes[] = { "", ",bc", ",sl", nullptr };
  const char *comp = (isload ? ld_suffixes : st_suffixes)[cc];
  if ( comp == nullptr )
    return nullptr;
  APPEND(ptr, end, comp);
  return ptr;
}

//--------------------------------------------------------------------------
static char *ldst_short(const insn_t &insn, uint32 code, char *ptr, const char *end)
{
  int cc  = (code>>10) & 3;
  int m   = (code & BIT26) ? 1 : 0;
  int a = (code & BIT18) ? 1 : 0;
  const char *comp;
  if ( code & BIT19 )
  {
    int im5 = (code>>16) & 0x1F;
    comp = h1_comp(a, m, im5);
  }
  else
  {
    int u = a;
    comp = h3_comp(u, m);
  }
  bool isload;
  switch ( insn.itype )
  {
    default:
      INTERR(10125);    //-V796 no break
    case HPPA_cldd:
    case HPPA_cldw:
    case HPPA_ldb:
    case HPPA_ldcd:
    case HPPA_ldcw:
    case HPPA_ldd:
    case HPPA_ldda:
    case HPPA_ldh:
    case HPPA_ldw:
    case HPPA_ldwa:
    case HPPA_fldd:
    case HPPA_fldw:
      isload = true;
      break;
    case HPPA_stby:
    case HPPA_stdby:
      comp = h2_comp(a, m);
      // no break
    case HPPA_cstd:
    case HPPA_cstw:
    case HPPA_stb:
    case HPPA_std:
    case HPPA_stda:
    case HPPA_sth:
    case HPPA_stw:
    case HPPA_stwa:
    case HPPA_fstd:
    case HPPA_fstw:
      isload = false;
      break;
  }
  APPEND(ptr, end, comp);
  ptr = append_cc(ptr, end, cc, isload);
  return ptr;
}

//--------------------------------------------------------------------------
static const char *const fpp_comp[] =
{
  "false?",   // 0
  "false",    // 1
  "?",        // 2
  "!<=>",     // 3
  "=",        // 4
  "=T",       // 5
  "?=",       // 6
  "!<>",      // 7
  "!?>=",     // 8
  "<",        // 9
  "?<",       // 10
  "!>=",      // 11
  "!?>",      // 12
  "<=",       // 13
  "?<=",      // 14
  "!>",       // 15
  "!?<=",     // 16
  ">",        // 17
  "?>",       // 18
  "!<=",      // 19
  "!?<",      // 20
  ">=",       // 21
  "?>=",      // 22
  "!<",       // 23
  "!?=",      // 24
  "<>",       // 25
  "!=",       // 26
  "!=T",      // 27
  "!?",       // 28
  "<=>",      // 29
  "true?",    // 30
  "true",     // 31
};

static const char *const fpp_test[] =
{
  "",      // 0
  "acc",   // 1
  ",rej",  // 2
  nullptr,    // 3
  nullptr,    // 4
  ",acc8", // 5
  ",rej8", // 6
  nullptr,    // 7
  nullptr,    // 8
  ",acc6", // 9
  nullptr,    // 10
  nullptr,    // 11
  nullptr,    // 12
  ",acc4", // 13
  nullptr,    // 14
  nullptr,    // 15
  nullptr,    // 16
  ",acc2", // 17
  nullptr,    // 18
  nullptr,    // 19
  nullptr,    // 20
  nullptr,    // 21
  nullptr,    // 22
  nullptr,    // 23
  nullptr,    // 24
  nullptr,    // 25
  nullptr,    // 26
  nullptr,    // 27
  nullptr,    // 28
  nullptr,    // 29
  nullptr,    // 30
  nullptr,    // 31
};

static const char *const fpp_sngop[] =
{
  "",         // 0 or sgl
  ",dbl",     // 1
  nullptr,       // 2
  ",quad",    // 3
};

//--------------------------------------------------------------------------
inline char *append_fmt(int fmt, char *ptr, const char *end)
{
  if ( fmt == 2 || fmt > 3 )
    return nullptr;
  APPEND(ptr, end, fpp_sngop[fmt]);
  return ptr;
}

//--------------------------------------------------------------------------
char *hppa_t::build_insn_completer(const insn_t &insn, uint32 code, char *buf, size_t bufsize)
{
  char *ptr = buf;
  char *const end = buf + bufsize;
  switch ( insn.itype )
  {
    case HPPA_ldo:      // format 1 (special case)
    case HPPA_ldi:      // pseudo-op
    case HPPA_nop:      // pseudo-op
    case HPPA_copy:     // pseudo-op (ldo or or)
      break;

    case HPPA_ldb:      // formats 1-5
    case HPPA_ldcd:
    case HPPA_ldcw:
    case HPPA_ldd:
    case HPPA_ldda:
    case HPPA_ldh:
    case HPPA_ldw:
    case HPPA_ldwa:
    case HPPA_stb:
    case HPPA_stby:
    case HPPA_std:
    case HPPA_stda:
    case HPPA_stdby:
    case HPPA_sth:
    case HPPA_stw:
    case HPPA_stwa:
    case HPPA_fldd:
    case HPPA_fldw:
    case HPPA_fstd:
    case HPPA_fstw:
      switch ( opcode(code) )
      {
        case 0x10:      // format 1
        case 0x11:
        case 0x12:
        case 0x18:
        case 0x19:
        case 0x1A:
        case 0x17:      // format 2
        case 0x1F:
          // nothing to do
          break;
        case 0x13:      // ldw (mod)
        case 0x1B:      // stw (mod)
          {
            sval_t off = insn.itype == HPPA_ldw ? insn.Op1.addr : insn.Op2.addr;
            APPEND(ptr, end, off < 0 ? ",mb" : ",ma");
          }
          break;
        case 0x14:      // format 3
        case 0x1C:
          {
            int m = (code & BIT28) ? 1 : 0;
            int a = (code & BIT29) ? 1 : 0;
            int im10a = ((code >> 3) & 0x7FE) | (code & 1);
            APPEND(ptr, end, h1_comp(a, m, im10a));
          }
          break;
        case 0x16:      // format 44 (fldw)
        case 0x1E:      // format 44 (fstw)
          {
            int m = 0;
            int a = (code & BIT29) ? 1 : 0;
            int im11a = ((code >> 2) & 0xFFE) | (code & 1);
            APPEND(ptr, end, h1_comp(a, m, im11a));
          }
          break;
        case 0x03:      // formats 4 & 5
        case 0x09:      // formats 39 & 41
        case 0x0B:      // formats 39 & 41
          ptr = ldst_short(insn, code, ptr, end);
          break;
        default:
          interr(insn, "format1");
      }
      break;

    case HPPA_addil:    // format 7
    case HPPA_ldil:
      break;

    case HPPA_hadd:     // format 8 (special case)
    case HPPA_hsub:
      {
        int sat = (code>>6) & 3;
        static const char *const suffixes[4] = { ",us", ",ss", nullptr, "" };
        if ( sat == 2 )
          return nullptr;
        APPEND(ptr, end, suffixes[sat]);
      }
    case HPPA_havg:     // format 8 (special case2)
    case HPPA_hshladd:
    case HPPA_hshradd:
      break;

    case HPPA_add:      // format 8
    case HPPA_and:
    case HPPA_andcm:
    case HPPA_cmpclr:
    case HPPA_dcor:
    case HPPA_ds:
    case HPPA_or:
    case HPPA_shladd:
    case HPPA_sub:
    case HPPA_uaddcm:
    case HPPA_uxor:
    case HPPA_xor:
      {
        int c  = (code>>13) & aux_cndc;
        int f  = (code & BIT19) ? 1 : 0; // aux_cndf
        int d  = (code & BIT26) ? 1 : 0; // aux_cndd
        const cond_text_t *table = nullptr;
        switch ( insn.itype )
        {
          case HPPA_cmpclr:
          case HPPA_ds:
            table = D3;
            break;
          case HPPA_add:
          case HPPA_shladd:
            {
              int e1 = (code>>10) & 3;
              int e2 = (code & BIT23) ? 1 : 0;
              if ( !e1 )
                return nullptr;
              if ( e1 == 2 && e2 )
                return nullptr; // not defined
              if ( e2 )
                APPEND(ptr, end, d ? ",dc" : ",c");
              static const char *const suffixes[4] = { "", "", ",l", ",tsv" };
              APPEND(ptr, end, suffixes[e1]);
            }
            table = D6;
            break;
          case HPPA_sub:
            {
              int e1 = (code>>10) & 3;
              int e2 = (code & BIT23) ? 1 : 0;
              int e3 = (code>> 6) & 3;
              if ( e1 != 1 && e1 != 3 )
                return nullptr;
              if ( e3 != 0 && e3 != 3 )
                return nullptr;
              if ( e2 && e3 )
                return nullptr;
              if ( e2 )
                APPEND(ptr, end, d ? ",db" : ",b");
              if ( e3 )
                APPEND(ptr, end, ",tc");
              if ( e1 == 3 )
                APPEND(ptr, end, ",tsv");
            }
            table = D3;
            break;
          case HPPA_or:
          case HPPA_and:
          case HPPA_andcm:
          case HPPA_xor:
            table = D9;
            break;
          case HPPA_uaddcm:
            {
              int e1 = (code>>6) & 3;
              if ( e1 != 2 && e1 != 3 )
                return nullptr;
              if ( e1 == 3 )
                APPEND(ptr, end, ",tc");
            }
            table = D11;
            break;
          case HPPA_dcor:
            {
              int e1 = (code>>6) & 3;
              if ( e1 != 2 && e1 != 3 )
                return nullptr;
              if ( e1 == 3 )
                APPEND(ptr, end, ",i");
            }
            table = D11;
            break;
          case HPPA_uxor:
            table = D11;
            if ( c > 3 )
              return nullptr;   // disable carry conditions
            break;
          default:
            interr(insn, "format8");
        }
        ptr = append_conds(table, c, f, d, ptr, end);
      }
      break;

    case HPPA_addi:     // format 9 (special case)
    case HPPA_subi:
      {
        if ( (code & BIT20) != 0 )
          APPEND(ptr, end, ",tsv");
        if ( opcode(code) == 0x2C )
          APPEND(ptr, end, ",tc");
        int c  = (code>>13) & 7;
        int f  = (code & BIT19) ? 1 : 0;
        ptr = append_conds(insn.itype == HPPA_subi ? D3 : D6, c, f, 0, ptr, end);
      }
      break;

    case HPPA_cmpiclr:  // format 9
      {
        int c  = (code>>13) & 7;
        int f  = (code & BIT19) ? 1 : 0;
        int d  = (code & BIT20) ? 1 : 0;
        ptr = append_conds(D3, c, f, d, ptr, end);
      }
      break;

    case HPPA_permh:     // format 10
      {
        int c0 = (code>>13) & 3;
        int c1 = (code>>10) & 3;
        int c2 = (code>> 8) & 3;
        int c3 = (code>> 6) & 3;
        ptr += qsnprintf(ptr, end-ptr, ",%d%d%d%d", c0, c1, c2, c3);
      }
      break;

    case HPPA_mixh:     // format 10
    case HPPA_mixw:
      {
        int ea = (code>>13) & 3;
        if ( ea & 1 )
          return nullptr;
        APPEND(ptr, end, ea ? ",r" : ",l");
      }
      break;

    case HPPA_hshr:     // format 10
      {
        int se = (code>>10) & 3;
        if ( se < 2 )
          return nullptr;
        if ( se == 2 )
          APPEND(ptr, end, ",u");
      }
    case HPPA_hshl:     // format 10 (special case)
      break;

    case HPPA_shrpd:    // formats 11 & 14
    case HPPA_shrpw:
      ptr = append_conds(D13, (code>>13) & 7, 0, insn.itype == HPPA_shrpd, ptr, end);
      break;

    case HPPA_extrd:    // formats 12 & 15
    case HPPA_extrw:
    case HPPA_shrd:     // pseudo-op
    case HPPA_shrw:     // pseudo-op
      if ( (code & BIT21) == 0 )
        APPEND(ptr, end, ",u");
      ptr = append_conds(D13, (code>>13) & 7, 0, insn.itype == HPPA_extrd, ptr, end);
      break;

    case HPPA_depd:     // formats 13 & 16
    case HPPA_depdi:
    case HPPA_depw:
    case HPPA_depwi:
    case HPPA_shld:     // pseudo-op
    case HPPA_shlw:     // pseudo-op
      {
        int nz = (code & BIT21) ? 1 : 0;
        int c  = (code>>13) & 7;
        int d = 0;
        switch ( insn.itype )
        {
          case HPPA_depd:
          case HPPA_depdi:
            ++d;
          case HPPA_depw:
          case HPPA_depwi:
            break;
          default:
            interr(insn, "format13");
        }
        if ( !nz && insn.itype < HPPA_call )
          APPEND(ptr, end, ",z");
        ptr = append_conds(D13, c, 0, d, ptr, end);
      }
      break;

    case HPPA_addb:     // format 17
    case HPPA_addib:
    case HPPA_cmpb:
    case HPPA_cmpib:
    case HPPA_movb:
    case HPPA_movib:
      {
        int c = (code>>13) & 7;
        int f = 0;
        const cond_text_t *table = psw_w() ? D8 : D6;
        switch ( opcode(code) )
        {
          case 0x20:            // cmpb
          case 0x21:            // cmpib
          case 0x27:            // cmpb
            table = D3;
          case 0x28:            // addb
          case 0x29:            // addib
            break;
          case 0x22:            // cmpb
          case 0x23:            // cmpib
          case 0x2F:            // cmpb
            table = D3;
            // fallthrough
          case 0x2A:            // addb
          case 0x2B:            // addib
            ++f;
            break;
          case 0x32:            // movb
          case 0x33:            // movib
            table = D13;
            break;
          case 0x3B:            // cmpib 64 bit
            table = D5;
            break;
          default:
            interr(insn, "format17");
        }
        ptr = append_conds(table, c, f, 0, ptr, end);
        if ( ptr == nullptr )
          return nullptr;
      }
      goto NULLIFY;

    case HPPA_bb:       // format 18
      {
        int c  = (code & BIT16) ? 1 : 0;
        int d  = (code & BIT18) ? 1 : 0;
        ptr = append_conds(D15, c, 0, d, ptr, end);
      }
      goto NULLIFY;

    case HPPA_be:       // format 19
      if ( opcode(code) == 0x39 )
        APPEND(ptr, end, ",l");
      goto NULLIFY;

    case HPPA_b:        // format 20
      if ( insn.Op2.type != o_void )
      {
        int subopcode = (code>>13) & 7;
        if ( subopcode >= 6 )
          goto BVE;
        static const char *const suffixes[8] =
        {
          ",l",    ",gate", nullptr, nullptr,
          ",push", ",l",    nullptr, nullptr
        };
        const char *s = suffixes[subopcode];
        if ( s == nullptr )
          return nullptr;
        APPEND(ptr, end, s);
      }
      goto NULLIFY;

    case HPPA_blr:      // format 21
    case HPPA_bv:
    case HPPA_call:     // pseudo-op
NULLIFY:
      if ( (code & BIT30) != 0 )
        APPEND(ptr, end, ",n");
      break;

    case HPPA_bve:      // format 22
    case HPPA_ret:      // pseudo-op
BVE:
      {
        int subopcode = (code>>13) & 7;
        if ( subopcode != 6 && subopcode != 7 )
          return nullptr;
        if ( subopcode == 7 && insn.itype == HPPA_bve )
          APPEND(ptr, end, ",l");
        if ( (code & BIT31) != 0 )
          APPEND(ptr, end, (subopcode == 7) ? ",push" : ",pop");
      }
      goto NULLIFY;

    case HPPA_clrbts:   // format 23
    case HPPA_popbts:
    case HPPA_pushbts:
    case HPPA_pushnom:
      break;

    case HPPA_pdtlb:    // formats 24 & 25 & 26
    case HPPA_pitlb:
      if ( (code & BIT21) != 0 )
        APPEND(ptr, end, ",l");
      // no break
    case HPPA_fdc:
    case HPPA_fdce:
    case HPPA_fic:
    case HPPA_fice:
    case HPPA_lpa:
    case HPPA_pdc:
    case HPPA_pdtlbe:
    case HPPA_pitlbe:
      if ( (code & BIT26) != 0 )
        APPEND(ptr, end, ",m");
    case HPPA_lci:      // format 24 (special case)
      break;

    case HPPA_probe:    // format 24 (special case)
    case HPPA_probei:
      APPEND(ptr, end, (code & BIT25) != 0 ? ",w" : ",r");
      break;

    case HPPA_idtlbt:   // format 26
    case HPPA_iitlbt:
      break;

    case HPPA_break:    // format 27
      break;

    case HPPA_diag:     // format 28
      break;

    case HPPA_mfsp:     // format 29
    case HPPA_mtsp:
      break;

    case HPPA_ldsid:    // format 30
      break;

    case HPPA_mtctl:    // format 31
    case HPPA_mtsar:    // pseudo-op
    case HPPA_mtsarcm:
      break;

    case HPPA_mfctl:    // format 32
      if ( (code & BIT17) != 0 )
        APPEND(ptr, end, ",w");
    case HPPA_mfia:     // format 32 (special case)
      break;

    case HPPA_rfi:      // format 33
      {
        int e1 = (code>>5) & 0xF;
        if ( e1 != 0 && e1 != 5 )
          return nullptr;
        if ( e1 == 5 )
          APPEND(ptr, end, ",r");
      }
    case HPPA_mtsm:     // format 33
    case HPPA_rsm:
    case HPPA_ssm:
    case HPPA_sync:
    case HPPA_syncdma:
      break;

    case HPPA_spop0:    // format 34
      {
        int sfu = (code>> 6) & 7;
        int sop1 = (code>>11) & 0x7FFF;
        int sop2 = (code>> 0) & 0x1F;
        uint32 sop = (sop1 << 5) | sop2;
        ptr += qsnprintf(ptr, end-ptr, ",%d,", sfu);
        ptr += btoa(ptr, end-ptr, sop);
      }
      goto NULLIFY2;

    case HPPA_spop1:    // format 35
      {
        int sfu = (code>> 6) & 7;
        uint32 sop = (code>>11) & 0x7FFF;
        ptr += qsnprintf(ptr, end-ptr, ",%d,", sfu);
        ptr += btoa(ptr, end-ptr, sop);
      }
      goto NULLIFY2;

    case HPPA_spop2:    // format 36
      {
        int sfu = (code>> 6) & 7;
        int sop1 = (code>>11) & 0x3FF;
        int sop2 = (code>> 0) & 0x1F;
        uint32 sop = (sop1 << 5) | sop2;
        ptr += qsnprintf(ptr, end-ptr, ",%d,", sfu);
        ptr += btoa(ptr, end-ptr, sop);
      }
      goto NULLIFY2;

    case HPPA_spop3:    // format 37
      {
        int sfu = (code>> 6) & 7;
        int sop1 = (code>>11) & 0x1F;
        int sop2 = (code>> 0) & 0x1F;
        uint32 sop = (sop1 << 5) | sop2;
        ptr += qsnprintf(ptr, end-ptr, ",%d,", sfu);
        ptr += btoa(ptr, end-ptr, sop);
      }
      goto NULLIFY2;

    case HPPA_copr:     // format 38
      {
        int uid = (code>> 6) & 7;
        uint32 sop = (code & 0x1F) | ((code>>4)&(0x1FFFF<<5));
        ptr += qsnprintf(ptr, end-ptr, ",%d,", uid);
        ptr += btoa(ptr, end-ptr, sop);
      }
      goto NULLIFY2;

    case HPPA_pmdis:    // format 55
NULLIFY2:
      {
        int n = (code & BIT26) ? 1 : 0;
        if ( n != 0 )
          APPEND(ptr, end, ",n");
      }
      break;

    case HPPA_cldd:     // formats 39 & 41
    case HPPA_cldw:
    case HPPA_cstd:     // formats 40 & 42
    case HPPA_cstw:
      {
        int uid = (code>> 6) & 7;
        ptr += qsnprintf(ptr, end-ptr, ",%d", uid);
        ptr = ldst_short(insn, code, ptr, end);
      }
      break;

    case HPPA_fabs:     // formats 45 & 49
    case HPPA_fcpy:
    case HPPA_fneg:
    case HPPA_fnegabs:
    case HPPA_frem:
    case HPPA_frnd:
    case HPPA_fsqrt:
    case HPPA_fadd:     // formats 48 & 52
    case HPPA_fdiv:
    case HPPA_fmpy:
    case HPPA_fsub:
      {
        int fmt = 0;
        switch ( opcode(code) )
        {
          case 0x0E:      // formats 49 & 52
            fmt = (code>>11) & 1;
            break;
          case 0x0C:      // formats 45 & 48
            fmt = (code>>11) & 3;
            break;
          default:
            INTERR(10126);
        }
        ptr = append_fmt(fmt, ptr, end);
      }
      break;
    case HPPA_fid:      // format 45
      break;

    case HPPA_fcnv:     // formats 46 & 50
      {
        int sub = (code>>15) & 7;
        int df, sf;
        if ( opcode(code) == 0x0E )     // format 50
        {
          df = (code>>13) & 1;
          sf = (code>>11) & 1;
        }
        else                            // format 46
        {
          df = (code>>13) & 3;
          sf = (code>>11) & 3;
        }
        if ( sf == 2 || df == 2 )
          return nullptr;
        if ( (sub & 3) == 3 )
          APPEND(ptr, end, ",t"); // with explicit round to zero
        static const char *const cnv_fpp[] = { ",sgl", ",dbl", nullptr, ",quad" };
        static const char *const cnv_sfx[] = { ",w",   ",dw",  nullptr, ",qw" };
        static const char *const cnv_ufx[] = { ",uw",  ",udw", nullptr, ",uqw" };
        const char *const *s1 = nullptr;
        const char *const *s2 = nullptr;
        switch ( sub )
        {
          case 0:       // fpp->fpp
            s1 = cnv_fpp;
            s2 = cnv_fpp;
            break;
          case 2:       // fpp->fix
          case 3:       // fpp->fix with explicit round to zero
            s1 = cnv_fpp;
            s2 = cnv_sfx;
            break;
          case 6:       // fpp->unsigned fix
          case 7:       // fpp->unsigned fix with explicit round to zero
            s1 = cnv_fpp;
            s2 = cnv_ufx;
            break;
          case 4:       // undefined
            return nullptr;
          case 1:       // fix->fpp
            s1 = cnv_sfx;
            s2 = cnv_fpp;
            break;
          case 5:       // unsigned fix->fpp
            s1 = cnv_ufx;
            s2 = cnv_fpp;
            break;
        }
        APPEND(ptr, end, s1[sf]);
        APPEND(ptr, end, s2[df]);
      }
      break;

    case HPPA_fcmp:     // formats 47 & 51
      if ( opcode(code) == 0x0C )
      {
        int fmt = (code>>11) & 3;
        ptr = append_fmt(fmt, ptr, end);
        if ( ptr == nullptr )
          return nullptr;
      }
      {
        int c = code & 0x1F;
        APPCHAR(ptr, end, ',');
        APPEND(ptr, end, fpp_comp[c]);
      }
      break;

    case HPPA_ftest:    // format 47
      {
        int y = (code>>13) & 7;
        if ( y == 1 )   // queue test
        {
          int c = code & 0x1F;
          const char *s = fpp_test[c];
          if ( s == nullptr )
            return nullptr;
          APPEND(ptr, end, s);
        }
      }
      break;

    case HPPA_xmpyu:    // format 52
      break;

    case HPPA_fmpyadd:  // format 53
    case HPPA_fmpysub:
      {
        int f = (code>>5) & 1;
        if ( f == 0 )
          APPEND(ptr, end, ",dbl");
      }
      break;

    case HPPA_fmpyfadd:  // format 54
    case HPPA_fmpynfadd:
      {
        int f = (code>>11) & 1;
        if ( f != 0 )
          APPEND(ptr, end, ",dbl");
      }
      break;

    default:
      interr(insn, "build_insn_completer");
  }
  if ( ptr == nullptr )
    return nullptr;
  APPZERO(ptr, end);
  return buf;
}

//----------------------------------------------------------------------
class out_hppa_t : public outctx_t
{
  out_hppa_t(void) = delete; // not used
public:
  void out_bad_address(ea_t addr);
  void outreg(int r);
  void out_ip_rel(int displ);
  void out_memref(ea_t ea);
  void resolve_possible_memref(const op_t &x);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_hppa_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_hppa_t)

//----------------------------------------------------------------------
void out_hppa_t::out_bad_address(ea_t addr)
{
  out_tagon(COLOR_ERROR);
  out_btoa(addr, 16);
  out_tagoff(COLOR_ERROR);
  remember_problem(PR_NONAME, insn.ea);
}

//----------------------------------------------------------------------
void out_hppa_t::outreg(int r)
{
  bool right = false;
  out_tagon(COLOR_REG);
  if ( r >= F0+32 && r < F0+64  // fpp register half
    && insn.itype != HPPA_fmpyadd
    && insn.itype != HPPA_fmpysub )
  {
    r -= 32;
    right = true;
  }
  out_line(ph.reg_names[r]);
  if ( right )
    out_char('r');
  out_tagoff(COLOR_REG);
}

//----------------------------------------------------------------------
void out_hppa_t::out_ip_rel(int displ)
{
  out_printf(COLSTR("%s+", SCOLOR_SYMBOL) COLSTR("%d", SCOLOR_NUMBER),
               ash.a_curip, displ);
}

//----------------------------------------------------------------------
bool out_hppa_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_imm:
      out_value(x, OOF_SIGNED|OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_reg:
      outreg(x.reg);
      break;

    case o_near:
      {
        ea_t ea = calc_mem(x.addr);
        if ( ea == insn.ea+4 )
          out_ip_rel(4);
        else if ( !out_name_expr(x, ea, ea) )
          out_bad_address(x.addr);
      }
      break;

    case o_displ:
      out_value(x, OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED|OOFW_32);
      // no break
    case o_based:
OUT_PHRASE:
      out_symbol('(');
      if ( insn.auxpref & aux_space )
      {
        outreg(x.sid);
        out_symbol(',');
      }
      outreg(x.phrase);
      out_symbol(')');
      break;

    case o_phrase:
      outreg(x.secreg);
      goto OUT_PHRASE;

    default:
      interr(insn, "out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_hppa_t::out_memref(ea_t ea)
{
  out_char(' ');
  out_line(ash.cmnt, COLOR_AUTOCMT);
  out_char(' ');
  if ( has_any_name(get_flags(ea)) )
  {
    qstring nbuf = get_colored_name(ea);
    out_line(nbuf.c_str());
  }
  else
  {
    // do not sign extend values that fit 32 bits
#ifdef __EA64__
    if ( int32(ea) == ea )
      ea = uint32(ea);
#endif
    out_printf("%0*a", 8, ea);
  }
}

//----------------------------------------------------------------------
void out_hppa_t::resolve_possible_memref(const op_t &x)
{
  hppa_t &pm = *static_cast<hppa_t *>(procmod);
  ea_t ea = pm.calc_possible_memref(insn, x);
  if ( ea != BADADDR )
    out_memref(ea);
}

//----------------------------------------------------------------------
void out_hppa_t::out_proc_mnem(void)
{
  hppa_t &pm = *static_cast<hppa_t *>(procmod);
  char postfix[80];
  uint32 code = get_dword(insn.ea);
  char *pfx = pm.build_insn_completer(insn, code, postfix, sizeof(postfix));
  out_mnem(16, pfx);
}

//----------------------------------------------------------------------
void out_hppa_t::out_insn(void)
{
  // output instruction mnemonics
  out_mnemonic();

  int i;
  bool comma = false;
  for ( i=0; i < PROC_MAXOP; i++ )
  {
    if ( insn.ops[i].type == o_void )
      continue;
    if ( comma )
    {
      out_symbol(',');
      out_char(' ');
    }
    comma = out_one_operand(i);
  }

  out_immchar_cmts();

  if ( insn.Op1.type == o_displ )
    resolve_possible_memref(insn.Op1);
  if ( insn.Op2.type == o_displ )
    resolve_possible_memref(insn.Op2);

  flush_outbuf();
}

//--------------------------------------------------------------------------
//lint -esym(818, Srange) could be made const
void hppa_t::hppa_segstart(outctx_t &ctx, segment_t *Srange) const
{
  const char *const predefined[] =
  {
    ".text",    // Text section
    ".data",    // Data sections
    ".rdata",
    ".comm",
  };

  if ( is_spec_segm(Srange->type) )
    return;

  qstring sname;
  qstring sclas;
  get_segm_name(&sname, Srange);
  get_segm_class(&sclas, Srange);

  if ( !print_predefined_segname(ctx, &sname, predefined, qnumber(predefined)) )
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR(".section %s", SCOLOR_ASMDIR) "" COLSTR("%s %s", SCOLOR_AUTOCMT),
                   sname.c_str(),
                   ash.cmnt,
                   sclas.c_str());
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
void hppa_t::hppa_assumes(outctx_t &ctx)                // function to produce assume directives
{
  ea_t ea = ctx.insn_ea;
  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || got == BADADDR )
    return;
  sreg_range_t sra;
  if ( !get_sreg_range(&sra, ea, DPSEG) || sra.start_ea != ea )
    return;

  if ( sra.val == BADSEL )
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s %s is unknown", SCOLOR_ASMDIR),
                   ash.cmnt, ph.reg_names[DPSEG]);
  else
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s %s = %0*a", SCOLOR_ASMDIR),
                   ash.cmnt, ph.reg_names[DPSEG], 8, got + sra.val);
}

//--------------------------------------------------------------------------
void idaapi hppa_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi hppa_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL);
}

//--------------------------------------------------------------------------
void hppa_t::hppa_footer(outctx_t &ctx) const
{
  qstring nbuf = get_colored_name(inf_get_start_ea());
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == nullptr )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                   ash.end, ash.cmnt, name);
}

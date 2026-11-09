/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2020 by Ilfak Guilfanov, <ig@datarescue.com>
 *      ALL RIGHTS RESERVED.
 *
 *      AMIGA hunk file loader
 *
 */


#include "../idaldr.h"
#include "amiga.hpp"

#define SkipLong(Longs) do { if ( qlseek(li, 4 * qoff64_t(Longs), SEEK_CUR) == -1 ) goto TRUNCATED_INPUT; } while ( 0 )
#define SkipWord(Words) do { if ( qlseek(li, 2 * qoff64_t(Words), SEEK_CUR) == -1 ) goto TRUNCATED_INPUT; } while ( 0 )
#define SkipByte(Bytes) do { if ( qlseek(li, 1 * qoff64_t(Bytes), SEEK_CUR) == -1 ) goto TRUNCATED_INPUT; } while ( 0 )

//------------------------------------------------------------------------------
static void ask_for_help(void)
{
  ask_for_feedback("This file contains some untested records");
}

//------------------------------------------------------------------------------
static char *read_name(linput_t *li, char *buf, size_t bufsize, int Longs)
{
  if ( ssize_t(bufsize) > 0 )
  {
    size_t sz = Longs;
    if ( sz != 0 )
    {
      sz *= 4;
      if ( sz >= bufsize )
        sz = bufsize-1;
      lread(li, buf, sz);
    }
    buf[sz] = '\0';
  }
  return buf;
}

//------------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*_neflags*/, const char * /*fileformatname*/)
{
  set_processor_type("68040", SETPROC_LOADER);

  uint32 Type, Data, i;
  int nums;
  char NameString[MAXSTR];
  bool has_header = false;
  bool shortreloc = false;
  ea_t start = to_ea(inf_get_baseaddr(), 0);
  ea_t end = start;

//
//      The first pass
//
  qoff64_t fsize = qlsize(li);
  qlseek(li, 0);
  while ( true )
  {
    i = (uint32)qlread(li, &Type, sizeof(Type));
    if ( i != sizeof(Type) )
    {
      if ( i != 0 )
        warning("There %s %u extra byte%s at end of file.",
                i == 1 ? "is" : "are",
                i,
                i == 1 ? "" : "s");
      break;
    }
    Type = swap32(Type);

    if ( Type == HUNK_DREL32 && has_header )
      Type = HUNK_DREL32EXE;

    switch ( Type & 0xFFFF )
    {
      case HUNK_UNIT:
        read_name(li, NameString, sizeof(NameString), mf_readlong(li));
        break;
      case HUNK_NAME:
        read_name(li, NameString, sizeof(NameString), mf_readlong(li));
        break;
      case HUNK_LIB:
        SkipLong(1);
        break;
      case HUNK_INDEX:
        SkipLong(mf_readlong(li));
        break;
      case HUNK_CODE:
      case HUNK_PPC_CODE:
      case HUNK_DATA:
      case HUNK_BSS:
        {
          Data = mf_readlong(li);
          Data <<= 2;
          Data &= 0x7FFFFFFF;
          start = find_free_chunk(end, Data, 0xF);
          end = start + Data;
          if ( end < start )
            loader_failure("Segment address overlow: %a..%a", start, end);
          const char *sname = nullptr;
          sel_t sel = get_segm_qty() + 1;
          set_selector(sel, 0);
          switch ( Type & 0xFFFF )
          {
            case HUNK_PPC_CODE:
              set_processor_type("ppc", SETPROC_LOADER);
              sname = "PPC_CODE";
              break;
            case HUNK_CODE:
              sname = "CODE";
              if ( inf_get_start_cs() == BADSEL )
              {
                inf_set_start_cs(sel);
                inf_set_start_ip(start);
              }
              break;
            case HUNK_DATA:
              sname = "DATA";
              break;
            case HUNK_BSS:
              sname = "BSS";
              break;
          }
          if ( (Type & 0xFFFF) != HUNK_BSS )
          {
            uint64 rest = fsize - qltell(li);
            if ( end-start > rest )
              loader_failure("Too big segment %a..%a", start, end);
            file2base(li, qltell(li), start, end, FILEREG_PATCHABLE);
          }
          segment_t s;
          s.sel     = setup_selector(sel);
          s.start_ea = start;
          s.end_ea   = end;
          s.align   = saRelByte;
          s.comb    = scPub;
          s.bitness = 1; // 32-bit
          add_segm_ex(&s, sname, sname, ADDSEG_NOSREG|ADDSEG_SPARSE);
        }
        break;
      case HUNK_RELOC32SHORT:
      case HUNK_DREL32EXE:
        shortreloc = true;
        // no break
      case HUNK_RELRELOC32:
      case HUNK_ABSRELOC16:
      case HUNK_RELRELOC26:
      case HUNK_RELOC32:
      case HUNK_RELOC16:
      case HUNK_RELOC8:
      case HUNK_DREL32:
      case HUNK_DREL16:
      case HUNK_DREL8:
        nums = 0;
        while ( true )
        {
          if ( qltell(li) >= fsize )
TRUNCATED_INPUT:
            loader_failure("Truncated file");
          Data = shortreloc ? mf_readshort(li) : mf_readlong(li);
          if ( Data == 0 )
            break;
          shortreloc ? mf_readshort(li) : mf_readlong(li);
          if ( shortreloc )
            SkipWord(Data);
          else
            SkipLong(Data);
          nums += Data;
        }
        if ( (nums & 1) == 0 && shortreloc )
          SkipWord(1);
        shortreloc = false;
        break;
      case HUNK_EXT:
        while ( true )
        {
          if ( qltell(li) >= fsize )
            goto TRUNCATED_INPUT;
          Data = mf_readlong(li);
          if ( Data == 0 )
            break;
          /* Is it followed by a symbol name? */
          if ( Data & 0xFFFFFF )
            read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);

          /* Remember extension type. */
          int32 exttype = (Data >> 24) & 0xFF;

          /* Display value of symbol. */
          if ( exttype == EXT_DEF || exttype == EXT_ABS || exttype == EXT_RES )
            mf_readlong(li);

          /* Skip relocation information. */
          if ( exttype == EXT_REF32
            || exttype == EXT_REF16
            || exttype == EXT_REF8
//            || exttype == EXT_DEXT32
//            || exttype == EXT_DEXT16
//            || exttype == EXT_DEXT8
//            || exttype == EXT_RELREF32
            || exttype == EXT_RELREF26 )
          {
            SkipLong(mf_readlong(li));
          }

          /* Display size of common block. */
          if ( exttype == EXT_COMMON )
          {
            mf_readlong(li);
            SkipLong(mf_readlong(li));
          }
        }
        break;
      case HUNK_SYMBOL:
        while ( true )
        {
          if ( qltell(li) >= fsize )
            goto TRUNCATED_INPUT;
          Data = mf_readlong(li);
          if ( Data == 0 )
            break;
          read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);
          mf_readlong(li);
        }
        break;
      case HUNK_DEBUG:
        SkipLong(mf_readlong(li));
        break;
      case HUNK_END:
        break;
      case HUNK_HEADER:
        {
          has_header = true;
          while ( true )
          {
            if ( qltell(li) >= fsize )
              goto TRUNCATED_INPUT;
            Data = mf_readlong(li);
            if ( Data == 0 )
              break;
            read_name(li, NameString, sizeof(NameString), Data);
          }
          mf_readlong(li);
          int32 From = mf_readlong(li);
          int32 To = mf_readlong(li);
          SkipLong(To-From+1);
        }
        break;
      case HUNK_OVERLAY:
        {
          int32 TabSize = mf_readlong(li);
          if ( TabSize )
          {
            mf_readlong(li);
            SkipLong(TabSize);
          }
          int32 hunktype = mf_readlong(li);
          if ( TabSize && hunktype >= HUNK_UNIT && hunktype <= HUNK_ABSRELOC16 )
            qlseek(li, -4, SEEK_CUR);
        }
        break;
      case HUNK_BREAK:
        break;
      default:
        warning("Unknown hunk type %04X - Aborting!", Type & 0xFFFF);
        return;
    }
  }

//
//      The second pass
//
  qlseek(li, 0);
  int nseg = 0;
  while ( true )
  {
    i = (uint32)qlread(li, &Type, sizeof(Type));
    if ( i != sizeof(Type) )
      break;
    Type = swap32(Type);

    if ( Type == HUNK_DREL32 && has_header )
      Type = HUNK_DREL32EXE;

    switch ( Type & 0xFFFF )
    {
      case HUNK_UNIT:
        read_name(li, NameString, sizeof(NameString), mf_readlong(li));
        add_pgm_cmt("Unit: %s", NameString);
        break;
      case HUNK_NAME:
        read_name(li, NameString, sizeof(NameString), mf_readlong(li));
        add_pgm_cmt("Title: %s", NameString);
        break;
      case HUNK_LIB:
        mf_readlong(li);
        break;
      case HUNK_INDEX:
        SkipLong(mf_readlong(li));
        break;
      case HUNK_CODE:
      case HUNK_PPC_CODE:
      case HUNK_DATA:
      case HUNK_BSS:
        Data = mf_readlong(li);
        Data <<= 2;
        Data &= 0x7FFFFFFF;
        if ( (Type & 0xFFFF) != HUNK_BSS )
          SkipByte(Data);
        nseg++;
        break;
      case HUNK_RELOC32SHORT:
      case HUNK_DREL32EXE:
        shortreloc = true;
        // no break
      case HUNK_RELRELOC32:
      case HUNK_ABSRELOC16:
      case HUNK_RELRELOC26:
      case HUNK_RELOC32:
      case HUNK_RELOC16:
      case HUNK_RELOC8:
      case HUNK_DREL32:
      case HUNK_DREL16:
      case HUNK_DREL8:
        nums = 0;
        while ( (Data=(shortreloc ? mf_readshort(li) : mf_readlong(li))) != 0 )
        {
          uint32 dat2 = shortreloc ? mf_readshort(li) : mf_readlong(li);
          segment_t *s = get_segm_by_sel(dat2+1);
          segment_t *ssrc = get_segm_by_sel(nseg);
          ea_t base = BADADDR;
          if ( ssrc != nullptr )
            base = ssrc->start_ea;
          else
            s = nullptr;
          int elsize = shortreloc ? 2 : 4;
          validate_array_count_or_die(li, Data, elsize, "Number of relocations");
          for ( uint32 dat3 = Data; dat3; --dat3 )
          {
            uint32 off = shortreloc ? mf_readshort(li) : mf_readlong(li);
            if ( s != nullptr )
            {
              ea_t src = base + off;
              ea_t dst = s->start_ea;
              ea_t target = BADADDR;
              fixup_type_t fd_type = 0;
              switch ( Type & 0xFFFF )
              {
                case HUNK_RELRELOC32:
                case HUNK_RELOC32:
                case HUNK_DREL32:
                case HUNK_RELOC32SHORT:
                case HUNK_DREL32EXE:
                  target = get_dword(src)+dst;
                  put_dword(src, target);
                  fd_type = FIXUP_OFF32;
                  break;
                case HUNK_ABSRELOC16:
                case HUNK_RELRELOC26:
                case HUNK_RELOC16:
                case HUNK_DREL16:
                  target = get_word(src)+dst;
                  put_word(src, target);
                  fd_type = FIXUP_OFF16;
                  break;
                case HUNK_RELOC8:
                case HUNK_DREL8:
                  target = get_byte(src)+dst;
                  put_byte(src, (uint32)target);
                  fd_type = FIXUP_OFF8;
                  break;
              }
              if ( fd_type != 0 )
              {
                fixup_data_t fd(fd_type);
                fd.sel = dat2 + 1;
                fd.off = target;
                fd.set(src);
              }
            }
            else
            {
              ask_for_help();
            }
          }
          nums += Data;
        }
        if ( (nums & 1) == 0 && shortreloc )
          SkipWord(1);
        shortreloc = false;
        break;
      case HUNK_EXT:
        ask_for_help();
        while ( (Data=mf_readlong(li)) != 0 )
        {
          switch ( (Data >> 24) & 0xFF )
          {
            case EXT_DEF:       msg("  EXT_DEF"); break;
            case EXT_ABS:       msg("  EXT_ABS"); break;
            case EXT_RES:       msg("  EXT_RES"); break;
            case EXT_REF32:     msg("  EXT_REF32"); break;
            case EXT_COMMON:    msg("  EXT_COMMON"); break;
            case EXT_REF16:     msg("  EXT_REF16"); break;
            case EXT_REF8:      msg("  EXT_REF8"); break;
//          case EXT_DEXT32:    msg("  EXT_DEXT32"); break;
//          case EXT_DEXT16:    msg("  EXT_DEXT16"); break;
//          case EXT_DEXT8:     msg("  EXT_DEXT8"); break;
//          case EXT_RELREF32:  msg("  EXT_RELREF32"); break;
//          case EXT_RELREF26:  msg("  EXT_RELREF26"); break;
//          case EXT_RELCOMMON: msg("  EXT_RELCOMMON"); break;
            default: msg("  EXT_??? (%02x)\n",(Data >> 24) & 0xFF); break;
          }

          /* Is it followed by a symbol name? */

          if ( Data & 0xFFFFFF )
          {
            read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);
            msg(" %s", NameString);
          }

          /* Remember extension type. */
          int32 exttype = (Data >> 24) & 0xFF;

          /* Display value of symbol. */
          if ( exttype == EXT_DEF || exttype == EXT_ABS || exttype == EXT_RES )
          {
            if ( !(Data & 0xFFFFFF) )
              msg(" ???");

            Data = mf_readlong(li);
            msg("%08X", Data);
          }

          /* Skip relocation information. */
          if ( exttype == EXT_REF32
            || exttype == EXT_REF16
            || exttype == EXT_REF8
//            || exttype == EXT_DEXT32
//            || exttype == EXT_DEXT16
//            || exttype == EXT_DEXT8
//            || exttype == EXT_RELREF32
            || exttype == EXT_RELREF26 )
          {
            Data = mf_readlong(li);
            msg("= %u entr%s", Data, Data == 1 ? "y" : "ies");
            SkipLong(Data);
          }

          /* Display size of common block. */
          if ( exttype == EXT_COMMON )
          {
            Data = mf_readlong(li);

            msg(" Size = %u bytes", Data << 2);
            Data = mf_readlong(li);
            SkipLong(Data);
          }
          msg("\n");
        }
        break;
      case HUNK_SYMBOL:
        while ( (Data=mf_readlong(li)) != 0 )
        {
          /* Display name. */
          read_name(li, NameString, sizeof(NameString), Data & 0xFFFFFF);

          /* Display value. */
          Data = mf_readlong(li);

          segment_t *ssrc = get_segm_by_sel(nseg);
          if ( ssrc == nullptr )
            ask_for_help();
          else
            set_name(ssrc->start_ea+Data, NameString, SN_NOCHECK | SN_NOWARN | SN_IDBENC);
        }
        break;
      case HUNK_DEBUG:
        SkipLong(mf_readlong(li));
        break;
      case HUNK_END:
        break;
      case HUNK_HEADER:
        {
          has_header = true;
          while ( (Data=mf_readlong(li)) != 0 )
            read_name(li, NameString, sizeof(NameString), Data);
          mf_readlong(li);
          int32 From = mf_readlong(li);
          int32 To = mf_readlong(li);
          SkipLong(To-From+1);
        }
        break;
      case HUNK_OVERLAY:
        {
          int32 TabSize = mf_readlong(li);
          if ( TabSize )
          {
            mf_readlong(li);
            SkipLong(TabSize);
          }
          int32 hunktype = mf_readlong(li);
          if ( TabSize && hunktype >= HUNK_UNIT && hunktype <= HUNK_ABSRELOC16 )
            qlseek(li, -4, SEEK_CUR);
        }
        break;
      case HUNK_BREAK:
        break;
      default:
        warning("Unknown hunk type %04X - Aborting!", Type & 0xFFFF);
        return;
    }
  }

  create_filename_cmt();
}

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  qlseek(li, 0);
  uint32 type;
  if ( qlread(li, &type, sizeof(uint32)) == sizeof(uint32)
    && swap32(type) == HUNK_HEADER )
  {
    *fileformatname = "Amiga hunk file";
    *processor      = "68040";
    return 1;
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi move_segm_relocs(ea_t from, ea_t to, asize_t size, const char *fileformatname)
{
  qnotused(size);
  qnotused(fileformatname);
  if ( from == BADADDR )
  {
    // The entire program is being rebased.
    // In this case, 'to' actually contains a delta value; the number of bytes
    // forward (positive) or backward (negative) that the whole database is
    // being moved.
    ea_t delta = to;

    // fix up relocations
    fixup_data_t fd;

    for ( ea_t xEA = get_first_fixup_ea(); xEA != BADADDR; xEA = get_next_fixup_ea(xEA) )
    {
      show_addr(xEA);

      get_fixup(&fd, xEA);
      fd.off += delta;

      switch ( fd.get_type() )
      {
        case FIXUP_OFF8:
          put_byte(xEA, fd.off);
          break;
        case FIXUP_OFF16:
          put_word(xEA, fd.off);
          break;
        case FIXUP_OFF32:
          put_dword(xEA, fd.off);
          break;
      }

      set_fixup(xEA, fd);
    }

    // Record the new image base address.
    inf_set_baseaddr(inf_get_baseaddr() + delta);
    // set_imagebase(new_base);
  }

  return 1;
}

//--------------------------------------------------------------------------
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
  move_segm_relocs,
  nullptr,
};

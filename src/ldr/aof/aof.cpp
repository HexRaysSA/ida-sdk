/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-97 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *      ARM Object File Loader
 *      ----------------------
 *      This module allows IDA to load ARM object files into
 *      its database and to disassemble them correctly.
 *
 *      NOTE 1: for the moment only B/BL instruction relocations are
 *      supported. I cannot find other relocation examples so
 *      they are not implemented yet.
 *
 *      NOTE 2: Thumb modules are not supported.
 *
 *      This module automatically detects the byte sex and sets inf.mf
 *      variable accrodingly.
 *
 *
 */

#include "../idaldr.h"
#include "aof.h"

//--------------------------------------------------------------------------
NORETURN static void nomem(void)
{
  nomem("AOF loader");
}

//--------------------------------------------------------------------------
static void *read_chunk(linput_t *li, const chunk_entry_t &ce)
{
  void *chunk = qalloc_array<char>(ce.size);
  if ( chunk == nullptr )
    nomem();
  qlseek(li, ce.file_offset);
  lread(li, chunk, ce.size);
  return chunk;
}

//--------------------------------------------------------------------------
static void check_chunk_ptr(
        const chunk_entry_t &ce,
        const void *chunkstart,
        const void *chunkptr,
        size_t ptrsize)
{
  const char *p0 = (const char*)chunkstart;
  const char *p1 = (const char*)chunkptr;
  if ( p1 < p0 || p1 + ptrsize < p0 || (p1 + ptrsize - p0) > ce.size )
    loader_failure("Corrupted file");
}

//--------------------------------------------------------------------------
static void check_chunk_str(
        const chunk_entry_t &ce,
        const void *chunkstart,
        const void *chunkptr)
{
  const char *p0 = (const char*)chunkstart;
  const char *p1 = (const char*)chunkptr;
  if ( p1 >= p0 )
  {
    const char *chunk_end = p0 + ce.size;
    while ( p1 < chunk_end )
    {
      if ( *p1 == '\0' )
        return;
      ++p1;
    }
  }
  loader_failure("Corrupted file");
}

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
  chunk_header_t hd;
  if ( qlread(li, &hd, sizeof(hd)) != sizeof(hd) )
    return 0;
  if ( hd.ChunkFileId != AOF_MAGIC && hd.ChunkFileId != AOF_MAGIC_B )
    return 0;
  if ( hd.num_chunks > hd.max_chunks )
    return 0;

  *fileformatname = "ARM Object File";
  *processor      = "arm";
  return 1;
}

//--------------------------------------------------------------------------
static void create32(
        sel_t sel,
        ea_t start_ea,
        ea_t end_ea,
        const char *name,
        const char *classname)
{
  set_selector(sel, 0);

  segment_t s;
  s.sel     = sel;
  s.start_ea = start_ea;
  s.end_ea   = end_ea;
  s.align   = saRelByte;
  s.comb    = scPub;
  s.bitness = 1; // 32-bit

  if ( !add_segm_ex(&s, name, classname, ADDSEG_NOSREG|ADDSEG_SPARSE) )
    loader_failure();
}

//--------------------------------------------------------------------------
static ea_t get_area_base(int idx)
{
  segment_t *s = get_segm_by_sel(idx+1);
  if ( s == nullptr )
    return BADADDR;
  return s->start_ea;
}

//--------------------------------------------------------------------------
static ea_t find_area(
        const chunk_entry_t &ce,
        const area_header_t *ah,
        int maxarea,
        const char *strings,
        const char *areaname)
{
  for ( int i=0; i < maxarea; i++, ah++ )
  {
    const char *name = strings + size_t(ah->name);
    check_chunk_str(ce, strings, name);
    if ( streq(name, areaname) )
      return get_area_base(i);
  }
  return BADADDR;
}

//--------------------------------------------------------------------------
static ea_t create_spec_seg(
        int *nsegs,
        int nelem,
        const char *name,
        uchar seg_type)
{
  ea_t ea = BADADDR;
  if ( nelem != 0 )
  {
    nelem *= 4;
    ea = find_free_chunk(inf_get_max_ea(), nelem, 0xFFF);
    (*nsegs)++;
    create32(*nsegs, ea, ea+nelem, name, CLASS_DATA);
    segment_t *s = getseg(ea);
    s->type = seg_type;
    s->update();
    set_arm_segm_flags(s->start_ea, 2 << SEGFL_SHIFT); // alignment
  }
  return ea;
}

//--------------------------------------------------------------------------
static void process_name(ea_t ea, const char *name, uint32 flags, bool iscode)
{
  // ignore aux names -- they hinder data creation
  if ( strstr(name, "$litpool_e$") != nullptr )
    return;
  if ( flags & SF_PUB )
  {
    add_entry(ea, ea, name, iscode, AEF_IDBENC);
    make_name_public(ea);
  }
  else
  {
    force_name(ea, name, SN_IDBENC);
  }
  if ( flags & SF_WEAK )
    make_name_weak(ea);
  if ( flags & SF_ICASE )
    add_extra_cmt(ea, true, "Case-insensitive label");
  if ( flags & SF_STRNG )
    add_extra_cmt(ea, true, "Strong name");
}

//--------------------------------------------------------------------------
static void reloc_insn(ea_t ea, uint32 rvalue, uint32 type)
{
  uint32 code = get_dword(ea);
  switch ( (code >> 24) & 0xF )
  {
    case 0x0A:  // B
    case 0x0B:  // BL
      {
        int32 off = code & 0x00FFFFFF;
        if ( off & 0x00800000 )
          off |= ~0x00FFFFFF; // extend sign
        off <<= 2;
        off += rvalue;
        off >>= 2;
        off &= 0xFFFFFF;
        code &= 0xFF000000;
        code |= off;
        put_dword(ea, code);
      }
      break;
    default:
      warning("This relocation type is not implemented yet\n"
              "\3%a: reloc insn rvalue=%x, rt=%x", ea, rvalue,
              type & RF_II);
      break;
  }
}

//--------------------------------------------------------------------------
inline void swap_chunk_entry(chunk_entry_t *ce)
{
  ce->file_offset = swap32(ce->file_offset);
  ce->size        = swap32(ce->size);
}

//--------------------------------------------------------------------------
static void swap_aof_header(aof_header_t *ahd)
{
  ahd->obj_file_type = swap32(ahd->obj_file_type);
  ahd->version       = swap32(ahd->version);
  ahd->num_areas     = swap32(ahd->num_areas);
  ahd->num_syms      = swap32(ahd->num_syms);
  ahd->entry_area    = swap32(ahd->entry_area);
  ahd->entry_offset  = swap32(ahd->entry_offset);
}

//--------------------------------------------------------------------------
static void swap_area_header(area_header_t *ah)
{
  ah->name           = swap32(ah->name);
  ah->flags          = swap32(ah->flags);
  ah->size           = swap32(ah->size);
  ah->num_relocs     = swap32(ah->num_relocs);
  ah->baseaddr       = swap32(ah->baseaddr);
}

//--------------------------------------------------------------------------
static void swap_sym(sym_t *s)
{
  s->name            = swap32(s->name);
  s->flags           = swap32(s->flags);
  s->value           = swap32(s->value);
  s->area            = swap32(s->area);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  int i;
  chunk_header_t hd;
  inf_set_app_bitness(32);
  set_processor_type("arm", SETPROC_LOADER);
  lread(li, &hd, sizeof(hd));
  if ( hd.ChunkFileId == AOF_MAGIC_B )             // BIG ENDIAN
  {
    inf_set_be(true);
    hd.max_chunks = swap32(hd.max_chunks);
    hd.num_chunks = swap32(hd.num_chunks);
  }

  validate_array_count_or_die(li, hd.max_chunks, sizeof(chunk_entry_t), "Number of chunks");
  chunk_entry_t *ce = qalloc_array<chunk_entry_t>(size_t(hd.max_chunks));
  if ( ce == nullptr )
    nomem();
  lread(li, ce, sizeof(chunk_entry_t)*size_t(hd.max_chunks));
  if ( inf_is_be() )
    for ( i=0; i < hd.max_chunks; i++ )
      swap_chunk_entry(ce+i);

  int head = -1; // AOF Header
  int area = -1; // Areas
  int idfn = -1; // Identification
  int symt = -1; // Symbol Table
  int strt = -1; // String Table

  for ( i=0; i < hd.max_chunks; i++ )
  {
    if ( ce[i].file_offset == 0 )
      continue;
    if ( strneq(ce[i].chunkId, OBJ_HEAD, sizeof(ce[i].chunkId)) )
      head = i;
    if ( strneq(ce[i].chunkId, OBJ_AREA, sizeof(ce[i].chunkId)) )
      area = i;
    if ( strneq(ce[i].chunkId, OBJ_IDFN, sizeof(ce[i].chunkId)) )
      idfn = i;
    if ( strneq(ce[i].chunkId, OBJ_SYMT, sizeof(ce[i].chunkId)) )
      symt = i;
    if ( strneq(ce[i].chunkId, OBJ_STRT, sizeof(ce[i].chunkId)) )
      strt = i;
  }
  if ( head == -1 || area == -1 || strt == -1 || symt == -1 || idfn == -1 )
  {
    qfree(ce);
    loader_failure("One of required chunks is missing");
  }

  char *strings = (char *)read_chunk(li, ce[strt]);
  aof_header_t *ahd = (aof_header_t *)read_chunk(li, ce[head]);
  check_chunk_ptr(ce[head], ahd, ahd, sizeof(aof_header_t));
  if ( inf_is_be() )
    swap_aof_header(ahd);

//
//      Areas
//

  area_header_t *ah = (area_header_t *)(ahd + 1);
  if ( inf_is_be() )
  {
    for ( i=0; i < ahd->num_areas; i++ )
    {
      check_chunk_ptr(ce[head], ahd, ah+i, sizeof(area_header_t));
      swap_area_header(ah+i);
    }
  }
  qoff64_t offset = ce[area].file_offset;
  inf_set_specsegs(inf_is_64bit() ? 8 : 4);
  ea_t ea = to_ea(inf_get_baseaddr(), 0);
  for ( i=0; i < ahd->num_areas; i++, ah++ )
  {
    check_chunk_ptr(ce[head], ahd, ah, sizeof(area_header_t));
    if ( ah->flags & AREA_DEBUG )
    {
      offset += ah->size;
      offset += qoff64_t(ah->num_relocs) * sizeof(reloc_t);
      continue;
    }
    if ( ah->flags & AREA_ABS )
    {
      ea = ah->baseaddr;
      if ( find_free_chunk(ea, ah->size, 1) != ea )
        error("Cannot allocate area at %a", ea);
    }
    else
    {
      ea = find_free_chunk(ea, ah->size, 0xFFF);
    }
    if ( (ah->flags & AREA_BSS) == 0 )
    {
      ea_t end = ea + ah->size;
      uint64 fsize = qlsize(li);
      if ( offset > fsize
        || fsize-offset < ah->size
        || end < ea )
      {
        loader_failure("Corrupted file");
      }
      file2base(li, offset, ea, end, FILEREG_PATCHABLE);
      offset += ah->size;
    }
    const char *name = strings + size_t(ah->name);
    check_chunk_str(ce[strt], strings, name);
    const char *classname;
    if ( ah->flags & AREA_CODE )
      classname = CLASS_CODE;
    else if ( ah->flags & (AREA_BSS|AREA_COMREF) )
      classname = CLASS_BSS;
    else
      classname = CLASS_DATA;
    create32(i+1, ea, ea+ah->size, name, classname);

    segment_t *s = getseg(ea);
    ushort sflags = (ah->flags & 0x1F) << SEGFL_SHIFT;       // alignment
    if ( ah->flags & AREA_BASED )
      sflags |= (SEGFL_BASED|ah->get_based_reg());
    if ( ah->flags & AREA_PIC )
      sflags |= SEGFL_PIC;
    if ( ah->flags & AREA_REENTR )
      sflags |= SEGFL_REENTR;
    if ( ah->flags & AREA_HALFW )
      sflags |= SEGFL_HALFW;
    if ( ah->flags & AREA_INTER )
      sflags |= SEGFL_INTER;
    if ( ah->flags & AREA_COMMON )
      sflags |= SEGFL_COMDEF;
    if ( ah->flags & (AREA_COMMON|AREA_COMREF) )
      s->comb = scCommon;
    if ( ah->flags & AREA_RDONLY )
      s->perm = SEGPERM_READ;
    if ( ah->flags & AREA_ABS )
      s->align = saAbs;
    s->update();
    set_arm_segm_flags(s->start_ea, sflags);

    if ( i == 0 )
    {
      create_filename_cmt();
      char *id = (char *)read_chunk(li, ce[idfn]);
      check_chunk_str(ce[idfn], id, id);
      add_pgm_cmt("Translator  : %s", id);
      qfree(id);
    }

    if ( ah->flags & AREA_CODE )
    {
      if ( (ah->flags & AREA_32BIT) == 0 )
        add_pgm_cmt("The 26-bit area");
      if ( (ah->flags & AREA_EXTFP) != 0 )
        add_pgm_cmt("Extended FP instructions are used");
      if ( (ah->flags & AREA_NOCHK) != 0 )
        add_pgm_cmt("No Software Stack Check");
      if ( (ah->flags & AREA_THUMB) != 0 )
        add_pgm_cmt("Thumb code area");
    }
    else
    {
      if ( (ah->flags & AREA_SHARED) != 0 )
        add_pgm_cmt("Shared Library Stub Data");
    }
    ea += ah->size;
    offset += qoff64_t(ah->num_relocs) * sizeof(reloc_t);
  }
  int nsegs = i;

//
//      Symbol Table
//

  ah = (area_header_t *)(ahd + 1);
  uint32 *delta = qalloc_array<uint32>(size_t(ahd->num_syms));
  if ( delta == nullptr )
    nomem();
  memset(delta, 0, sizeof(uint32)*size_t(ahd->num_syms));
  sym_t *syms = (sym_t *)read_chunk(li, ce[symt]);
  if ( inf_is_be() )
  {
    for ( i=0; i < ahd->num_syms; i++ )
    {
      check_chunk_ptr(ce[symt], syms, syms+i, sizeof(sym_t));
      swap_sym(syms+i);
    }
  }
  int n_undef = 0;
  int n_abs   = 0;
  int n_comm  = 0;

  for ( i=0; i < ahd->num_syms; i++ )
  {
    sym_t *s = syms + i;
    check_chunk_ptr(ce[symt], syms, syms+i, sizeof(sym_t));
    if ( s->flags & SF_DEF )
    {
      if ( s->flags & SF_ABS )
      {
        n_abs++;
      }
      else
      {
        const char *areaname = strings + size_t(s->area);
        check_chunk_str(ce[strt], strings, areaname);
        ea_t areabase = find_area(ce[strt], ah, size_t(ahd->num_areas), strings, areaname);
        delta[i] = (uint32)areabase;
        ea_t symea = areabase + s->value;
        const char *name = strings + size_t(s->name);
        check_chunk_str(ce[strt], strings, name);
        if ( s->value == 0 && strcmp(areaname, name) == 0 )
          continue; // HACK!
        process_name(symea, name, s->flags, segtype(areabase) == SEG_CODE);
      }
    }
    else
    {
      if ( (s->flags & SF_PUB) && (s->flags & SF_COMM) )   // ref to common
        n_comm++;
      else
        n_undef++;
    }
  }

  ea_t abs_ea   = create_spec_seg(&nsegs, n_abs,   NAME_ABS,    SEG_ABSSYM);
  ea_t undef_ea = create_spec_seg(&nsegs, n_undef, NAME_UNDEF,  SEG_XTRN);
  ea_t comm_ea  = create_spec_seg(&nsegs, n_comm,  NAME_COMMON, SEG_COMM);
  if ( n_abs+n_undef+n_comm != 0 )
  {
    for ( i=0; i < ahd->num_syms; i++ )
    {
      sym_t *s = syms + i;
      const char *name = strings + size_t(s->name);
      check_chunk_str(ce[strt], strings, name);
      if ( s->flags & SF_DEF )
      {
        if ( s->flags & SF_ABS )
        {
          if ( inf_get_specsegs() == 8 )
          {
            put_qword(abs_ea, s->value);
            create_qword(abs_ea, 8);
          }
          else
          {
            put_dword(abs_ea, s->value);
            create_dword(abs_ea, 4);
          }
          process_name(abs_ea, name, s->flags, false);
          delta[i] = s->value;
          s->value = uint32(abs_ea - delta[i]);
          abs_ea += inf_get_specsegs();
        }
      }
      else
      {
        if ( (s->flags & SF_PUB) && (s->flags & SF_COMM) )   // ref to common
        {
          if ( inf_get_specsegs() == 8 )
            put_qword(comm_ea, s->value);
          else
            put_dword(comm_ea, s->value);
          process_name(comm_ea, name, s->flags, false);
          delta[i] = (uint32)comm_ea;
          comm_ea += inf_get_specsegs();
        }
        else
        {
          put_dword(undef_ea, 0xE1A0F00E);       // RET
          process_name(undef_ea, name, s->flags, false);
          delta[i] = (uint32)undef_ea;
          undef_ea += inf_get_specsegs();
        }
        s->value = 0;
      }
    }
  }

//
//      Relocations
//

  offset = ce[area].file_offset;
  for ( i=0; i < ahd->num_areas; i++, ah++ )
  {
    if ( ah->flags & AREA_DEBUG )
    {
      offset += ah->size;
      offset += qoff64_t(ah->num_relocs) * sizeof(reloc_t);
      continue;
    }
    if ( (ah->flags & AREA_BSS) == 0 )
      offset += ah->size;
    qlseek(li, offset);
    ea_t base = get_area_base(i);
    validate_array_count(li, &ah->num_relocs, sizeof(reloc_t), "Number of relocs", offset);
    for ( int j=0; j < ah->num_relocs; j++ )
    {
      reloc_t r;
      lread(li, &r, sizeof(reloc_t));
      if ( inf_is_be() )
      {
        r.type   = swap32(r.type);
        r.offset = swap32(r.offset);
      }
      size_t sid = r.sid();
      ea_t rvalue;
      ea_t target;
      fixup_data_t fd;
      if ( r.type & RF_A )
      {
        if ( sid >= ahd->num_syms )
          loader_failure("Bad relocation record at file offset %" FMT_64 "x", qltell(li)-sizeof(reloc_t));
        rvalue = delta[sid];
        target = syms[sid].value + rvalue;
        fd.set_extdef();
      }
      else
      {
        rvalue = get_area_base((int)sid);
        target = rvalue;
        if ( rvalue == BADADDR )
          loader_failure("Bad reference to area %" FMT_Z " at file offset %" FMT_64 "x", sid, qltell(li)-sizeof(reloc_t));
      }
      segment_t *s = getseg(target);
      if ( s == nullptr )
        loader_failure("Can't find area for relocation target %a at %" FMT_64 "x", target, qltell(li)-sizeof(reloc_t));
      fd.sel = s->sel;
      fd.off = target - get_segm_base(s);
      if ( (r.type & RF_R) != 0 )
      {
        if ( (r.type & RF_A) != 0 )
        {
                // R=1 B=0 or R=1 B=1
                // This specifies PC-relative relocation: to the subject field
                // is added the difference between the relocation value and
                // the base of the area containing the subject field.
                // In pseudo C:
                //   subject_field = subject_field +
                //                    (relocation_value -
                //                  base_of_area_containing(subject_field))
          rvalue -= base;
        }
        else
        {
                //
                // As a special case, if A is 0, and the relocation value is
                // specified as the base of the area containing the subject
                // field, it is not added and:
                //   subject_field = subject_field -
                //                  base_of_area_containing(subject_field)
                // This caters for relocatable PC-relative branches to fixed
                // target addresses. If R is 1, B is usually 0. A B value of 1
                // is used to denote that the inter-link-unit value of a
                // branch destination is to be used, rather than the more
                // usual intra-link-unit value.
          rvalue = 0-base;
        }
      }
      else
      {
        if ( (r.type & RF_B) != 0 )
        {       // R=0 B=1
                // This specifies based area relocation. The relocation value
                // must be an address within a based data area. The subject
                // field is incremented by the difference between this value
                // and the base address of the consolidated based area group
                // (the linker consolidates all areas based on the same base
                // register into a single, contiguous region of the output
                // image). In pseudo C:
                //   subject_field = subject_field +
                //                      (relocation_value -
                //           base_of_area_group_containing(relocation_value))
                // For example, when generating re-entrant code, the C
                // compiler places address constants in an adcon area based
                // on register sb, and loads them using sb relative LDRs.
                // At link time, separate adcon areas will be merged and sb
                // will no longer point where presumed at compile time. B
                // type relocation of the LDR instructions corrects for this.
          rvalue -= get_area_base((int)sid);
        }
        else
        {       // R=0 B=0
                // This specifies plain additive relocation: the relocation
                // value is added to the subject field. In pseudo C:
                //      subject_field = subject_field + relocation_value
          /* nothing to do */;
        }
      }
      ea_t relea = base + r.offset;
      switch ( r.type & RF_FT )
      {
        case RF_FT_BYTE: // 00 the field to be relocated is a byte
          fd.set_type(FIXUP_OFF8);
          fd.displacement = get_byte(relea);
          add_byte(relea, (uint32)rvalue);
          break;
        case RF_FT_HALF: // 01 the field to be relocated is a halfword (two bytes)
          fd.set_type(FIXUP_OFF16);
          fd.displacement = get_word(relea);
          add_word(relea, rvalue);
          break;
        case RF_FT_WORD: // 10 the field to be relocated is a word (four bytes)
          fd.set_type(FIXUP_OFF32);
          fd.displacement = get_dword(relea);
          add_dword(relea, rvalue);
          break;
        case RF_FT_INSN: // 11 the field to be relocated is an instruction or instruction sequence
          reloc_insn(relea, (uint32)rvalue, r.type);
          break;
      }
      fd.set(relea);
    }
    offset += qoff64_t(ah->num_relocs) * sizeof(reloc_t);
  }

  if ( ahd->entry_area != 0 )
  {
    inf_set_start_cs(ahd->entry_area);
    inf_set_start_ip(ahd->entry_offset);
    inf_set_start_ea(ahd->entry_offset);
  }

  qfree(syms);
  qfree(delta);
  qfree(ahd);
  qfree(strings);
  qfree(ce);
  inf_set_baseaddr(0);
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

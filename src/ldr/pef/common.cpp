//----------------------------------------------------------------------
static void swap_pef(pef_t &pef)
{
#if __MF__
  qnotused(pef);
#else
  pef.formatVersion    = swap32(pef.formatVersion);
  pef.dateTimeStamp    = swap32(pef.dateTimeStamp);
  pef.oldDefVersion    = swap32(pef.oldDefVersion);
  pef.oldImpVersion    = swap32(pef.oldImpVersion);
  pef.currentVersion   = swap32(pef.currentVersion);
  pef.reservedA        = swap32(pef.reservedA);
  pef.sectionCount     = swap16(pef.sectionCount);
  pef.instSectionCount = swap16(pef.instSectionCount);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_section(pef_section_t &ps)
{
#if __MF__
  qnotused(ps);
#else
  ps.nameOffset        = swap32(ps.nameOffset);
  ps.defaultAddress    = swap32(ps.defaultAddress);
  ps.totalSize         = swap32(ps.totalSize);
  ps.unpackedSize      = swap32(ps.unpackedSize);
  ps.packedSize        = swap32(ps.packedSize);
  ps.containerOffset   = swap32(ps.containerOffset);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_loader(pef_loader_t &pl)
{
#if __MF__
  qnotused(pl);
#else
  pl.mainSection              = swap32(pl.mainSection);
  pl.mainOffset               = swap32(pl.mainOffset);
  pl.initSection              = swap32(pl.initSection);
  pl.initOffset               = swap32(pl.initOffset);
  pl.termSection              = swap32(pl.termSection);
  pl.termOffset               = swap32(pl.termOffset);
  pl.importLibraryCount       = swap32(pl.importLibraryCount);
  pl.totalImportedSymbolCount = swap32(pl.totalImportedSymbolCount);
  pl.relocSectionCount        = swap32(pl.relocSectionCount);
  pl.relocInstrOffset         = swap32(pl.relocInstrOffset);
  pl.loaderStringsOffset      = swap32(pl.loaderStringsOffset);
  pl.exportHashOffset         = swap32(pl.exportHashOffset);
  pl.exportHashTablePower     = swap32(pl.exportHashTablePower);
  pl.exportedSymbolCount      = swap32(pl.exportedSymbolCount);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_library(pef_library_t &pil)
{
#if __MF__
  qnotused(pil);
#else
  pil.nameOffset          = swap32(pil.nameOffset);
  pil.oldImpVersion       = swap32(pil.oldImpVersion);
  pil.currentVersion      = swap32(pil.currentVersion);
  pil.importedSymbolCount = swap32(pil.importedSymbolCount);
  pil.firstImportedSymbol = swap32(pil.firstImportedSymbol);
  pil.reservedB           = swap16(pil.reservedB);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_reloc_header(pef_reloc_header_t &prh)
{
#if __MF__
  qnotused(prh);
#else
  prh.sectionIndex     = swap16(prh.sectionIndex);
  prh.reservedA        = swap16(prh.reservedA);
  prh.relocCount       = swap32(prh.relocCount);
  prh.firstRelocOffset = swap32(prh.firstRelocOffset);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_export(pef_export_t &pe)
{
#if __MF__
  qnotused(pe);
#else
  pe.classAndName = swap32(pe.classAndName);
  pe.symbolValue  = swap32(pe.symbolValue);
  pe.sectionIndex = swap16(pe.sectionIndex);
#endif
}

//----------------------------------------------------------------------
const char *get_pef_processor(const pef_t &pef)
{
  if ( strneq(pef.architecture, PEF_ARCH_PPC, 4) ) // PowerPC
    return "ppc";
  if ( strneq(pef.architecture, PEF_ARCH_68K, 4) ) // or 68K
    return "68000";
  return nullptr;
}

//----------------------------------------------------------------------
const char *get_pef_processor(linput_t *li)
{
  pef_t pef;
  if ( qlread(li, &pef, sizeof(pef_t)) != sizeof(pef_t) )
    return nullptr;
  swap_pef(pef);
  if ( !strneq(pef.tag1, PEF_TAG_1, 4)    // Joy!
    || !strneq(pef.tag2, PEF_TAG_2, 4)    // peff
    || pef.formatVersion != PEF_VERSION ) // 1
  {
    return nullptr;
  }
  return get_pef_processor(pef);
}

//----------------------------------------------------------------------
bool is_pef_file(linput_t *li)
{
  const char *proc = get_pef_processor(li);
  return proc != nullptr;
}

//----------------------------------------------------------------------
static char *get_string(
        linput_t *li,
        qoff64_t snames_table,
        int32 off,
        char *buf,
        size_t bufsize)
{
  if ( ssize_t(bufsize) <= 0 )
    return nullptr;

  if ( off == -1 )
  {
    buf[0] = '\0';
    return nullptr;
  }
  qlseek(li, snames_table+off);
  lread(li, buf, bufsize);
  buf[bufsize-1] = '\0';
  return buf;
}

//----------------------------------------------------------------------
inline const char *get_impsym_name(
        const char *stable,
        const void *end,
        const uint32 *impsym,
        int i)
{
  size_t off = mflong(impsym[i]) & 0xFFFFFF;
  if ( stable + off >= end )
    return nullptr;
  return stable + off;
}

//----------------------------------------------------------------------
inline size_t get_expsym_name_length(const uint32 *keytable, int i)
{
  return mflong(keytable[i]) >> 16;
}

//----------------------------------------------------------------------
static bool get_expsym_name(
        const char *stable,
        const uint32 *keytable,
        const pef_export_t *pe,
        int i,
        const void *end,
        char *buf,
        size_t bufsize)
{
  pe += i;
  size_t off = pe->classAndName & 0xFFFFFF;
  size_t len = get_expsym_name_length(keytable, i);
  if ( len >= bufsize )
    len = bufsize-1;
  if ( stable+off+len >= end )
    return false;
  memcpy(buf, stable+off, len);
  buf[len] = 0;
  return true;
}

//----------------------------------------------------------------------
// is data pointed by [ptr, end) completely inside vector?
static bool inside(const bytevec_t &vec, const void *ptr, size_t nelems, size_t elsize)
{
  if ( !is_mul_ok(nelems, elsize) )
    return false;

  const uchar *p = (const uchar *)ptr;
  const uchar *e = p + nelems * elsize;
  return p >= vec.begin()
      && p <= vec.end()
      && e >= p
      && e <= vec.end();
}

//----------------------------------------------------------------------
struct pef_loader_data_t
{
  pef_loader_t pl;
  pef_library_t *pil;
  uint32 *impsym;
  pef_reloc_header_t *prh;
  const char *stable;
  const uint16 *relptr;
  const uint32 *hash;
  const uint32 *keytable;
  pef_export_t *pe;
  pef_loader_data_t(void) { memset(this, 0, sizeof(*this)); }
  ~pef_loader_data_t(void)
  {
    qfree(pil);
    qfree(prh);
    qfree(pe);
    qfree(impsym);
  }
};

enum elderr_t
{
  ELDERR_OK,            // loader data ok
  ELDERR_SHORT,         // too short (not enough data even for the header)
  ELDERR_IMPLIBS,       // wrong imported library info
  ELDERR_IMPSYMS,       // wrong imported symbols
  ELDERR_RELHDRS,       // wrong relocation headers
  ELDERR_STABLE,        // wrong symbol table
  ELDERR_RELOCS,        // wrong relocation instructions
  ELDERR_KEYTABLE,      // wrong keytable
  ELDERR_EXPSYMS,       // wrong exported symbols
  ELDERR_VECTORS,       // wrong term/init/main vectors
  ELDERR_LAST,
};

static elderr_t extract_loader_data(
        pef_loader_data_t *pd,
        const bytevec_t &ldrdata,
        const qvector<pef_section_t> &sec)
{
  if ( ldrdata.size() < sizeof(pef_loader_t) )
    return ELDERR_SHORT;
  pd->pl = *(pef_loader_t *)ldrdata.begin();
  pef_loader_t &pl = pd->pl;
  swap_pef_loader(pl);
  const pef_library_t *pil = (pef_library_t *)(ldrdata.begin() + sizeof(pl));
  const uint32 *impsym = (uint32 *)(pil + pl.importLibraryCount);
  const pef_reloc_header_t *prh =
                (pef_reloc_header_t *)(impsym + pl.totalImportedSymbolCount);
  const char *stable = (char *)(ldrdata.begin() + pl.loaderStringsOffset);
  const uint16 *relptr = (uint16 *)(ldrdata.begin() + pl.relocInstrOffset);
  const uint32 *hash = (uint32 *)(ldrdata.begin() + pl.exportHashOffset);
  const uint32 hashsize = (1 << pl.exportHashTablePower);
  const uint32 *keytable = hash + hashsize;
  const pef_export_t *pe = (pef_export_t *)(keytable + pl.exportedSymbolCount);

  if ( !inside(ldrdata, pil, pl.importLibraryCount, sizeof(*pil)) )
    return ELDERR_IMPLIBS;
  if ( !inside(ldrdata, impsym, pl.totalImportedSymbolCount, sizeof(*impsym)) )
    return ELDERR_IMPSYMS;
  if ( !inside(ldrdata, prh, pl.relocSectionCount, sizeof(*prh)) )
    return ELDERR_RELHDRS;
  if ( !inside(ldrdata, stable, 0, 0) )
    return ELDERR_STABLE;
  if ( !inside(ldrdata, relptr, 0, 0) )
    return ELDERR_RELOCS;
  if ( !inside(ldrdata, pe, pl.exportedSymbolCount, sizeof(*pe)) )
    return ELDERR_EXPSYMS;
  if ( !inside(ldrdata, keytable, pl.exportedSymbolCount, sizeof(*keytable)) )
    return ELDERR_KEYTABLE;
  // x < -1 || x >= nsecs  =>  unsigned(x+1) > nsecs
  size_t nsecs = sec.size();
  if ( pl.termSection+1 > nsecs
    || pl.initSection+1 > nsecs
    || pl.mainSection+1 > nsecs )
  {
    return ELDERR_VECTORS;
  }
  { // malicious input file may have overlapping structures that may
    // lead too all kinds of problems when we swap their contents.
    // we simply make a copy and modify copies to ensure that there is
    // no interference between different structures.
    pd->pil = qalloc_array<pef_library_t>(pl.importLibraryCount);
    memmove(pd->pil, pil, pl.importLibraryCount*sizeof(*pil));
    pd->prh = qalloc_array<pef_reloc_header_t>(pl.relocSectionCount);
    memmove(pd->prh, prh, pl.relocSectionCount*sizeof(*prh));
    pd->pe = qalloc_array<pef_export_t>(pl.exportedSymbolCount);
    memmove(pd->pe, pe, pl.exportedSymbolCount*sizeof(*pe));
    pd->impsym = qalloc_array<uint32>(pl.totalImportedSymbolCount);
    memmove(pd->impsym, impsym, pl.totalImportedSymbolCount*sizeof(*impsym));
  }
#if !__MF__
  for ( int i=0; i < pl.importLibraryCount; i++ )
    swap_pef_library(pd->pil[i]);
  for ( int i=0; i < pl.relocSectionCount; i++ )
    swap_pef_reloc_header(pd->prh[i]);
  for ( int i=0; i < pl.exportedSymbolCount; i++ )
    swap_pef_export(pd->pe[i]);
#endif
  pd->stable   = stable;
  pd->relptr   = relptr;
  pd->hash     = hash;
  pd->keytable = keytable;
  return ELDERR_OK;
}

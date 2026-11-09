
static const uint32 magic1[] = { ZERO_CODE1 };
static const uint32 magic2[] = { ZERO_CODE2 };
static const uint32 *const magics[] = { magic1, magic2 };

//--------------------------------------------------------------------------
static void swap_header(aif_header_t *hd)
{
  uint32 *ptr = (uint32 *)hd;
  const int size = sizeof(aif_header_t) / sizeof(uint32);
  for ( size_t i=0; i < size; i++, ptr++ )
    *ptr = swap32(*ptr);
}

//--------------------------------------------------------------------------
// 0-failed, 1-little endian, 2-big endian
static int match_zero_code(aif_header_t *hd)
{
  int mostfirst = 0;
  for ( int i=0; i < qnumber(magics); i++ )
  {
    if ( memcmp(hd->zero_code, magics[i], sizeof(hd->zero_code)) == 0 )
      return mostfirst+1;
    swap_header(hd);
    mostfirst = !mostfirst;
    if ( memcmp(hd->zero_code, magics[i], sizeof(hd->zero_code)) == 0 )
      return mostfirst+1;
  }
  return 0;
}

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      otherwise return 0
//
bool is_aif_file(linput_t *li)
{
  aif_header_t hd;
  qlseek(li, 0);
  if ( qlread(li, &hd, sizeof(hd)) != sizeof(hd) )
    return false;
  return match_zero_code(&hd) != 0;
}

//--------------------------------------------------------------------------
static void swap_section(section_t *s)
{
  s->codestart = swap32(s->codestart);
  s->datastart = swap32(s->datastart);
  s->codesize  = swap32(s->codesize);
  s->datasize  = swap32(s->datasize);
  s->fileinfo  = swap32(s->fileinfo);
  s->debugsize = swap32(s->debugsize);
  s->name      = swap32(s->name);
}

//--------------------------------------------------------------------------
static void swap_dsym(dsym_t *s)
{
  s->sym   = swap32(s->sym);
  s->value = swap32(s->value);
}

//--------------------------------------------------------------------------
// returns true - debug info with pascal symbols
static bool swap_symbols(dsym_t *ds, char *str, uchar *end, size_t nsyms)
{
  int npascal = 0;          // number of pascal strings
  int nc = 0;               // number of c strings
  for ( int i=0; i < nsyms; i++,ds++ )
  {
    if ( is_mf() )
      swap_dsym(ds);
    if ( ds->sym & ASD_16BITSYM )
      continue;
    size_t off = size_t(ds->sym & ASD_SYMOFF);
    char *name = str + off;
    if ( name >= (char *)end )
      continue;
    if ( name[0] == strlen(name)-1 )
      npascal++;
    else
      nc++;
  }
  return npascal > nc;
}


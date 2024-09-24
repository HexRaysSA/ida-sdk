
// Written by Yury Haron yjh@styx.cabel.net

#include <windows.h>

#include <ida.hpp>
#include <prodir.h>
#include <idp.hpp>
#include <bytes.hpp>
#include "uunp.hpp"

//--------------------------------------------------------------------------
#pragma pack(push, 1)
struct rhdr_beg_t
{
  uint32 DataSize;
  uint32 HeaderSize;
};

#if 0
struct reshdr_t
{
  rhdr_beg_t  rb;
  rhdr_name_t Type;
  rhdr_name_t Name;
  rhdr_end_t  re;
};
#endif
#pragma pack()

// resources are always aligned to sizeof(uint32)

//---------------------------------------------------------------------------
void uunp_ctx_t::store(const void *Data, uint32 size)
{
  static const uint32 zero4 = 0;

  rhdr_beg_t rh;
  size_t len = sizeof(rh) + sizeof(re);

  if ( Names[0].len != 0 )
    len += Names[0].len;
  else
    len += sizeof(zname);

  if ( Names[1].len != 0 )
    len += Names[1].len;
  else
    len += sizeof(zname);

  rh.HeaderSize = (uint32)len;
  rh.DataSize   = size;
  re.LanguageId = Names[2].Id;
  qfwrite(fr, &rh, sizeof(rh));

  if ( Names[0].len != 0 )
  {
    qfwrite(fr, Names[0].name, Names[0].len);
  }
  else
  {
    zname.Id = Names[0].Id;
    qfwrite(fr, &zname, sizeof(zname));
  }

  if ( Names[1].len != 0 )
  {
    qfwrite(fr, Names[1].name, Names[1].len);
  }
  else
  {
    zname.Id = Names[1].Id;
    qfwrite(fr, &zname, sizeof(zname));
  }

  qfwrite(fr, &re, sizeof(re));
  if ( Data )  // for 'primary' header
  {
    qfwrite(fr, Data, size);
    len += size;
  }
  if ( len & 3 )
    qfwrite(fr, &zero4, 4 - (len & 3));
}

//---------------------------------------------------------------------------
static bool initPtrs(uunp_ctx_t &ctx, const char *fname)
{
  IMAGE_DATA_DIRECTORY res;
  ea_t nth;

  nth = get_dword(ctx.curmod.start_ea + 0x3C) + ctx.curmod.start_ea;

  size_t off;
  if ( inf_is_64bit() )
  {
    off = offsetof(IMAGE_NT_HEADERS64,
                   OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
  }
  else
  {
    off = offsetof(IMAGE_NT_HEADERS32,
                   OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
  }

  if ( get_bytes(&res, sizeof(res), nth + off) != sizeof(res)
    || !res.VirtualAddress
    || !res.Size )
  {
    msg("There are no resources in the module\n");
    return false;
  }

  ctx.ResBase = ctx.curmod.start_ea + res.VirtualAddress;
  ctx.ResTop  = res.Size;
  ctx.ImgSize = ctx.curmod.end_ea - ctx.curmod.start_ea;

  int minres = 2*sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)+3*sizeof(IMAGE_RESOURCE_DIRECTORY);
  if ( (res.Size & 3) != 0
    || res.Size <= minres
    || res.VirtualAddress >= ctx.ImgSize
    || res.Size >= ctx.ImgSize
    || res.Size + res.VirtualAddress > ctx.ImgSize )
  {
    msg("Invalid resource descriptor\n");
    return false;
  }

  ctx.fr = qfopen(fname, "wb");
  if ( ctx.fr == nullptr )
  {
    msg("Cannot create the output file '%s' for the resources\n", fname);
    return false;
  }

  return true;
}

//---------------------------------------------------------------------------
static bool extractData(uunp_ctx_t &ctx, uint32 off)
{
  IMAGE_RESOURCE_DATA_ENTRY rd;

  if ( off + sizeof(rd) > ctx.ResTop )
    return false;
  if ( get_bytes(&rd, sizeof(rd), ctx.ResBase + off) != sizeof(rd) )
    return false;

  if ( rd.OffsetToData >= ctx.ImgSize
    || rd.Size > ctx.ImgSize
    || rd.OffsetToData + rd.Size > ctx.ImgSize )
  {
    return false;
  }
  void *data = qalloc(rd.Size);
  if ( data == nullptr )
  {
    msg("Not enough memory for resources\n");
    return false;
  }
  bool res = false;
  if ( get_bytes(data, rd.Size, ctx.curmod.start_ea + rd.OffsetToData) == rd.Size )
  {
    ctx.store(data, rd.Size);
    res = true;
  }
  qfree(data);
  return res;
}

//---------------------------------------------------------------------------
static bool extractDirectory(uunp_ctx_t &ctx, uint32 off, int level);

static bool extractEntry(uunp_ctx_t &ctx, uint32 off, int level, bool named)
{
  IMAGE_RESOURCE_DIRECTORY_ENTRY rde;

  if ( off + sizeof(rde) >= ctx.ResTop )
    return false;
  if ( get_bytes(&rde, sizeof(rde), ctx.ResBase + off) != sizeof(rde) )
    return false;

  if ( (bool)rde.NameIsString != named )
    return false;

  if ( (bool)rde.DataIsDirectory != (level != 2) )
    return false;

  off += sizeof(rde);

  if ( !named )
  {
    ctx.Names[level].Id = rde.Id;
  }
  else
  {
    ea_t npos = rde.NameOffset;
    if ( npos < off || npos + 2 >= ctx.ResTop )
      return false;
    uint32 nlen = get_word(npos + ctx.ResBase)*sizeof(wchar_t);
    if ( !nlen || npos + nlen > ctx.ResTop )
      return false;
    wchar_t *p = (wchar_t *)qalloc(nlen + sizeof(wchar_t));
    if ( p == nullptr )
    {
      msg("Not enough memory for resource names\n");
      return false;
    }
    if ( get_bytes(p, nlen, npos + sizeof(uint16) + ctx.ResBase) != nlen )
    {
bad_name:
      qfree(p);
      return false;
    }
    p[nlen/sizeof(wchar_t)] = 0;
    size_t wlen = wcslen(p);
    if ( !wlen || wlen < nlen/2-1 )
      goto bad_name;
    ctx.Names[level].name = p;
    ctx.Names[level].len = uint32((wlen+1)*sizeof(wchar_t));
  }

  if ( level != 2 )
  {
    bool res = false;
    if ( rde.OffsetToDirectory >= off )
      res = extractDirectory(ctx, rde.OffsetToDirectory, level+1);

    if ( ctx.Names[level].len )
      qfree(ctx.Names[level].name);
    ctx.Names[level].name = nullptr;
    ctx.Names[level].len  = 0;
    return res;
  }

  if ( rde.OffsetToData < off )
    return false;

  return extractData(ctx, rde.OffsetToData);
}

//---------------------------------------------------------------------------
static bool extractDirectory(uunp_ctx_t &ctx, uint32 off, int level)
{
  IMAGE_RESOURCE_DIRECTORY rd;

  if ( off + sizeof(rd) >= ctx.ResTop )
    return false;
  if ( get_bytes(&rd, sizeof(rd), ctx.ResBase + off) != sizeof(rd) )
    return false;

  off += sizeof(rd);
  if ( rd.NumberOfNamedEntries != 0 )
  {
    if ( level == 2 )           // language must be ONLY numbered
      return false;
    do
    {
      if ( !extractEntry(ctx, off, level, true) )
        return false;
      off += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    } while ( --rd.NumberOfNamedEntries );
  }
  if ( rd.NumberOfIdEntries != 0 )
  {
    do
    {
      if ( !extractEntry(ctx, off, level, false) )
        return false;
      off += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    } while ( --rd.NumberOfIdEntries );
  }
  return true;
}

//---------------------------------------------------------------------------
void uunp_ctx_t::extract_resource(const char *fname)
{
  if ( !initPtrs(*this, fname) )
    return;

  store(nullptr, 0); // zero-resource header

  bool wrerr = false;
  bool res = extractDirectory(*this, 0, 0);
  if ( !res )
  {
    msg("Can't extract resource (possible it is invalid)\n");
  }
  else
  {
    qflush(fr);
    if ( ferror(fr) || feof(fr) )
      wrerr = true;
  }
  if ( qfclose(fr) )
    wrerr = true;
  fr = nullptr; // just in case
  if ( res && wrerr )
    msg("Error writing resource file\n");

  if ( !res || wrerr )
    qunlink(fname);
  else
    msg("Resources have been extracted and stored in '%s'\n", fname);
}


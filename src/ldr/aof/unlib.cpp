/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-97 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *      ARM Object Librarian (Unpacker)
 *
 *      This program unpacks a library. It extracts all the modules
 *      from the input library and puts them into separate files.
 *
 */

#include <pro.h>
#include <fpro.h>
#include "aof.h"

#define LIB_DIRY "LIB_DIRY"     // Directory
#define LIB_TIME "LIB_TIME"     // Time stamp
#define LIB_VRSN "LIB_VRSN"     // Version
#define LIB_DATA "LIB_DATA"     // Data
#define OFL_SYMT "OFL_SYMT"     // Symbol table
#define OFL_TIME "OFL_TIME"     // Time stamp

static FILE *outfp = nullptr;
static char outfile[QMAXPATH] = "";
static char infile[QMAXPATH] = "";
static char modname[MAXSTR] = "";
static int mf = 0;

//-----------------------------------------------------------------------
static void fatal(const char *format, ...)
{
  if ( infile[0] != '\0' && modname[0] != '\0' )
    qeprintf("Fatal [%s] (%s): ",infile,modname);
  va_list va;
  va_start(va,format);
  qveprintf(format,va);
  va_end(va);
  qeprintf("\n");
  qfclose(outfp);
  unlink(outfile);
//  qeprintf("press enter to exit.\n");
//  getchar();
  qexit(1);
}

void warning(const char *format, ...)
{
  qeprintf("Warning [%s] (%s): ",infile,modname);
  va_list va;
  va_start(va,format);
  qveprintf(format,va);
  va_end(va);
  qeprintf("\n");
}

static void nomem(const char *format, ...)
{
  char buf[512];
  va_list va;
  va_start(va,format);
  qvsnprintf(buf, sizeof(buf), format, va);
  va_end(va);
  fatal("No memory: %s",buf);
}

//--------------------------------------------------------------------------
static void *read_chunk(FILE *fp, chunk_entry_t *ce, int32 i)
{
  size_t idx = size_t(i);
  void *chunk = qalloc_array<char>(ce[idx].size);
  if ( chunk == nullptr )
    nomem("chunk size %d",size_t(ce[idx].size));
  qfseek(fp,ce[idx].file_offset,SEEK_SET);
  if ( qfread(fp,chunk,size_t(ce[idx].size)) != ce[idx].size )
    fatal("Chunk read error: %s",strerror(errno));
  return chunk;
}

//--------------------------------------------------------------------------
static uint32 swap(uint32 x)
{
  union
  {
    uint32 l;
    char c[4];
  } u;
  char chr;
  u.l = x;
  chr = u.c[3]; u.c[3] = u.c[0]; u.c[0] = chr;
  chr = u.c[2]; u.c[2] = u.c[1]; u.c[1] = chr;
  return u.l;
}

//--------------------------------------------------------------------------
inline void swap_chunk_entry(chunk_entry_t *ce)
{
  ce->file_offset = swap(ce->file_offset);
  ce->size        = swap(ce->size);
}

//--------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  int i;
  qeprintf("ARM Library unpacker. Copyright 1997 by Ilfak Guilfanov. Version 1.00\n");
  if ( argc < 2 )
    fatal("Usage: unlib libfile");
  qstrncpy(infile, argv[1], sizeof(infile));
  FILE *fp = qfopen(infile,"rb");
  if ( fp == nullptr )
    fatal("Can't open library %s",infile);
  chunk_header_t hd;
  if ( qfread(fp, &hd, sizeof(hd)) != sizeof(hd)
    || (hd.ChunkFileId != AOF_MAGIC && hd.ChunkFileId != AOF_MAGIC_B) )
  {
    fatal("Bad library format");
  }
  if ( hd.ChunkFileId == AOF_MAGIC_B )             // BIG ENDIAN
  {
    mf = 1;
    hd.max_chunks = swap(hd.max_chunks);
    hd.num_chunks = swap(hd.num_chunks);
  }

  chunk_entry_t *ce = qalloc_array<chunk_entry_t>(hd.max_chunks);
  if ( ce == nullptr )
    nomem("chunk entries (%d)",size_t(hd.max_chunks));
  qfread(fp, ce, sizeof(chunk_entry_t)*size_t(hd.max_chunks));
  if ( mf )
    for ( i=0; i < hd.max_chunks; i++ )
      swap_chunk_entry(ce+i);

  int vrsn = -1;
  int diry = -1;
  int data = 0;
  for ( i=0; i < hd.max_chunks; i++ )
  {
    if ( ce[i].file_offset == 0 )
      continue;
    if ( strncmp(ce[i].chunkId,LIB_DIRY,sizeof(ce[i].chunkId)) == 0 )
      diry = i;
    if ( strncmp(ce[i].chunkId,LIB_VRSN,sizeof(ce[i].chunkId)) == 0 )
      vrsn = i;
    if ( strncmp(ce[i].chunkId,LIB_DATA,sizeof(ce[i].chunkId)) == 0 )
      data++;
  }
  if ( diry == -1 )
    fatal("Can't find library directory!");
  if ( data == 0 )
    fatal("No modules in the library!");
  if ( vrsn == -1 )
    fatal("Can't determine library version!");
  uint32 *version = (uint32 *)read_chunk(fp,ce,vrsn);
  if ( mf )
    *version = swap(*version);
  if ( *version != 1 )
    fatal("Wrong library version (%ld)",*version);
  qfree(version);

  uint32 *dir = (uint32 *)read_chunk(fp,ce,diry);
  uint32 *end = dir + size_t(ce[diry].size/4);
  while ( dir < end )
  {
    uint32 idx = *dir++;
    /* uint32 elen = */ *dir++;
    uint32 dlen = *dir++;
    if ( mf )
    {
      idx = swap(idx);
      dlen = swap(dlen);
    }
    if ( idx != 0 )
    {
      printf("%d. %s\n",idx,dir);
      qstrncpy(modname,(char *)dir,sizeof(modname));
      modname[sizeof(modname)-1] = '\0';
      void *core = read_chunk(fp,ce,idx);
      outfp = qfopen(modname,"wb");
      if ( outfp == nullptr )
      {
        warning("Can't open output file %s",modname);
      }
      else
      {
        qfwrite(outfp,core,size_t(ce[size_t(idx)].size));
        qfclose(outfp);
      }
      qfree(core);
    }
    dir += size_t(dlen/4);
  }
  qfree(dir);

  qfclose(fp);
  return 0;
}

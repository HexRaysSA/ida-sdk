#ifndef __NLM_H__
#define __NLM_H__
#pragma pack(push, 1)

struct nlmexe_t
{
#define NLM_MAGIC_SIZE 0x18
  char magic[NLM_MAGIC_SIZE];
#define NLM_MAGIC "NetWare Loadable Module\x1A"
  uint32 version;     // file Version
#define NLM_COMPRESSED  0x00000080 // compressed NLM file
  char fnamelen;      // modulename length
  char fname[12+1];
  uint32 codeoff;     // offset to code segment
  uint32 codelen;     // length of code segment
  uint32 dataoff;     // offset to data segment
  uint32 datalen;     // length of data segment
  uint32 bssSize;     // Unitialized data size
  uint32 custoff;     // help off
  uint32 custlen;     // help length
  uint32 autoliboff;  // autoload library offset
  uint32 autolibnum;  // number of autoload libraries
  uint32 fixupoff;    // offset to fixups
  uint32 fixupnum;    // number of fixups
  uint32 impoff;      // offset to imported names
  uint32 impnum;      // number of imported names
  uint32 expoff;      // offset to exported names
  uint32 expnum;      // number of exported names
  uint32 puboff;      // offset to public names
  uint32 pubnum;      // number of public names
  uint32 startIP;     // entry point?
  uint32 endIP;       // terminate NLM
  uint32 auxIP;       // additional entry point
  uint32 modType;     // Module type
  uint32 flags;       // Module flags
};

#define NLM_MODNAMOFF 0x82  //sizeof

CASSERT(NLM_MODNAMOFF == sizeof(nlmexe_t));

#pragma pack(pop)
#endif

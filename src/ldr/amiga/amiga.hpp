/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov, <ig@datarescue.com>
 *      ALL RIGHTS RESERVED.
 *
 */

//
//      AMIGA hunk files
//

#ifndef AMIGA_HPP
#define AMIGA_HPP

#define HUNK_UNIT               999
#define HUNK_NAME              1000
#define HUNK_CODE              1001
#define HUNK_DATA              1002
#define HUNK_BSS               1003
#define HUNK_RELOC32           1004
#define HUNK_RELOC16           1005
#define HUNK_RELOC8            1006
#define HUNK_EXT               1007
#define HUNK_SYMBOL            1008
#define HUNK_DEBUG             1009
#define HUNK_END               1010
#define HUNK_HEADER            1011
#define HUNK_UNUSED            1012     // unused hunk number?
#define HUNK_OVERLAY           1013
#define HUNK_BREAK             1014
#define HUNK_DREL32            1015
#define HUNK_DREL16            1016
#define HUNK_DREL8             1017
#define HUNK_LIB               1018
#define HUNK_INDEX             1019
#define HUNK_RELOC32SHORT      1020
#define HUNK_RELRELOC32        1021
#define HUNK_ABSRELOC16        1022
#define HUNK_DREL32EXE         1023

#define HUNK_PPC_CODE          1257
#define HUNK_RELRELOC26        1260
#define EXT_RELREF26            229

// i don't know the values! (these symbols are used with HUNK_CODE, _DATA, _BSS)
#define HUNKF_CHIP              0x00000000
#define HUNKF_FAST              0x00000000
#define HUNKF_ADVISORY          0x00000000

#define EXT_SYMB    0
#define EXT_DEF     1
#define EXT_ABS     2
#define EXT_RES     3
#define EXT_REF32   129
#define EXT_COMMON  130
#define EXT_REF16   131
#define EXT_REF8    132

#endif // AMIGA_HPP

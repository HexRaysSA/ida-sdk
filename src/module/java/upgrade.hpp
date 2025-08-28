/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      JVM module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _UPGRADE_HPP_
#define _UPGRADE_HPP_
//----------------------------------------------------------------------
#define IDP_JDK12    19
#define IDP_JDK15   151
#define IDP_JDK16   161

//----------------------------------------------------------------------
#define UPG12_BADMASK   0x80000000
#define UPG12_EXTMASK   0x70000000
#define UPG12_CLRMASK   0xF03F0000
#define UPG12_EXTSET    0x80000000

//----------------------------------------------------------------------
#define CHP_MIN   ' '
#define CHP_MAX   0x7F
#define BLOB_TAG  'j'

uchar  set_exception_xref(SegInfo *ps, Exception const & exc, ea_t ea);
char   *convert_clsname(char *buf);

//----------------------------------------------------------------------
#endif

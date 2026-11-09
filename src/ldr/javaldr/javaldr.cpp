/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *
 *      Java Virtual Machine pseudo-loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

/*
        L O A D E R  for Java-classFile
*/

#include "../idaldr.h"
#include "../../module/java/classfil.hpp"
#include "../../module/java/notify_codes.hpp"

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
  uint32 magic;
  uint16 min_ver, maj_ver;

  if ( lread4bytes(li, &magic, 1) != 0
    || magic != MAGICNUMBER
    || lread2bytes(li, &min_ver, 1) != 0
    || lread2bytes(li, &maj_ver, 1) != 0 )
  {
    goto BADFMT;
  }

  uchar jdk;
  if ( maj_ver <= JDK_MIN_MAJOR )
  {
    if ( maj_ver < JDK_MIN_MAJOR )
      goto BADFMT;
    jdk = maj_ver >= JDK_1_1_MINOR;   //-V547 'maj_ver >= 3' is always true
  }
  else if ( maj_ver > JDK_MAX_MAJOR )
  {
BADFMT:
    return 0;
  }
  else
  {
    jdk = (uchar)(maj_ver - (JDK_MIN_MAJOR-1));
  }

  fileformatname->sprnt("JavaVM Class File (JDK 1.%u%s)",
                        jdk,
                        jdk == 3 ? "/CLDC" : "");
  *processor = "java";
  return f_LOADER;
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
static void idaapi load_file(linput_t *li, ushort neflag, const char * /*fileformatname*/)
{
  set_processor_type("java", SETPROC_LOADER);

  if ( !java_module_t::load_file(li, (neflag & NEF_LOPT) != 0) )
    INTERR(20047);
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

/*

        Sample IDC loader: load BIOS image

        Feel free to improve it, this is just a sample

*/

#include <idc.idc>

//--------------------------------------------------------------------------
// Verify the input file format
//      li - loader_input_t object. it is positioned at the file start
// Returns: if the input file is not recognized
//              return 0
//          else
//              return object with 2 attributes:
//                 format: description of the file format
//                 options:1 or ACCEPT_FIRST. it is ok not to set this attribute.
//              or return a string designating the format name

static accept_file(li, filename)
{
  if ( li.size() > 0x10000 )    // we support max 64K images
    return 0;

  li.seek(-16, SEEK_END);
  if ( li.getc() != 0xEA ) // jmp?
    return 0;

  li.seek(-2, SEEK_END);
  if ( (li.getc() & 0xF0) != 0xF0 ) // reasonable computer type?
    return 0;

  auto buf;
  li.seek(-11, SEEK_END);
  li.read(&buf, 9);
  // 06/03/08
  if ( buf[2] != "/" || buf[5] != "/" || buf[8] != "\x00" )
    return 0;

  // accept the file
  auto res = object();
  res.format = "BIOS Image";    // description of the file format
  return res;
}

//--------------------------------------------------------------------------
// Load the file into the database
//      li      - loader_input_t object. it is positioned at the file start
//      neflags - combination of NEF_... bits describing how to load the file
//                probably NEF_MAN is the most interesting flag that can
//                be used to select manual loading
//      format  - description of the file format
// Returns: 1 - means success, 0 - failure
static load_file(li, neflags, format)
{
  set_processor_type("metapc", SETPROC_LOADER);
  set_flag(INF_LFLAGS, LFLG_PC_FLAT, 0); // 16bit only

  auto base = 0xF000;
  auto start = base << 4;
  auto size = li.size();

  // copy bytes to the database
  loadfile(li, 0, base<<4, size);

  // create a segment
  add_segm_ex(start, start+size, base, 0, saRelPara, scPub, ADDSEG_NOSREG);

  // set the entry registers
  set_inf_attr(INF_START_IP, size-16);
  set_inf_attr(INF_START_CS, base);
  return 1;
}

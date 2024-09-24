/*
        Android specific functions.
*/

// r_brk():
// B0003050 70 47 BX LR
static const uchar bxlr_thumb[] = { 0x70, 0x47 };

#define LINKER "/system/bin/linker"

//--------------------------------------------------------------------------
// on android /system/bin/linker comes without any symbols.
// Since there is no other way, we scan the data segment for
//     dcd 1, ?, r_brk, 0, 0
// r_debug is located very close to the beginning of the data segment,
// we should find it fine. In any case, we check only the first 4KB.
bool linux_debmod_t::add_android_shlib_bpt(const meminfo_vec_t &miv, bool attaching)
{
  // find read/writable linker memory range
  meminfo_vec_t::const_iterator p;
  ea_t linker_base = BADADDR;
  for ( p=miv.begin(); p != miv.end(); ++p )
  {
    if ( p->name == LINKER )
    {
      if ( linker_base == BADADDR )
        linker_base = p->start_ea;
      // assume the data segment to be readable and writable
      if ( (p->perm & 6) == 6 )
        break;
    }
  }
  if ( p == miv.end() )
  {
    msg("Failed to find data segment of " LINKER "\n");
    return false;
  }

  // read max 2KB
  uint32 buf[2048];
  int nbytes = qmin(p->size(), sizeof(buf));
  ea_t dataseg = p->start_ea;
  nbytes = dbg_read_memory(dataseg, buf, nbytes, nullptr);

  uint32 *ptr = buf;
  for ( int i=0; i < nbytes/4-5; i++, ptr++ )
  {
    if ( ptr[0] == 1                           // version
      && (attaching || ptr[1] == 0)            // r_map, 0 at the beginning
      && (ptr[2] & 1) != 0 && ptr[2] < dataseg // r_brk (Thumb pointer)
      && (attaching || ptr[3] == 0)            // r_state: RT_CONSISTENT
      && ptr[4] == 0 )                         // linker baseaddr: always zero?
    {
      ea_t r_brk = ptr[2] & ~1;
      // check if linker is not relocated yet
      if ( r_brk < linker_base )
        r_brk += linker_base; // adjust address
      uchar opcode[2];
      if ( dbg_read_memory(r_brk, opcode, 2, nullptr) == 2
        && memcmp(opcode, bxlr_thumb, 2) == 0 )
      {
        // found it!
        if ( add_internal_bp(shlib_bpt, r_brk+1) )
        {
          dmsg("found r_debug (r_brk=%a)\n", r_brk);
          return true;
        }
      }
    }
  }
  msg("Failed to find r_debug in " LINKER "\n");
  return false;
}

//--------------------------------------------------------------------------
// Android reports shared objects without any path. Try to find full path.
void linux_debmod_t::make_android_abspath(qstring *in_out_path)
{
  if ( qisabspath(in_out_path->c_str()) )
    return;

  // Apparently /proc didn't return an absolute path. Check /system/lib.
  // Normally we should not arrive here, this is just for safety.
  char path[QMAXPATH];
  qmakepath(path, sizeof(path), "/system/lib", in_out_path->c_str(), nullptr);
  if ( qfileexist(path) )
    *in_out_path = path;
}

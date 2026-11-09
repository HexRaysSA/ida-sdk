#ifndef __DBG_RPC_HANDLER_IOCTLS__
#define __DBG_RPC_HANDLER_IOCTLS__

// Note: the dbg_rpc_handler_t implementation will consider all
// IOCTL IDs >= 0x01000000 as being server IOCTLs, and those will
// consequently *not* be passed to the debugger module.
#define MIN_SERVER_IOCTL 0x01000000

#define DWARF_RPCSRV_IOCTL_OK 0
#define DWARF_RPCSRV_IOCTL_ERROR -1

enum rpcsrv_ioctl_t
{
  // Get DWARF sections information.
  //
  // client->server
  //   (unpacked) char *         : file_path (on the server's disk.)
  //   (packed)   uint32         : processor ID (as in: ph.id)
  // server->client
  //   (unpacked) byte           : DWARF info found
  //   (packed)   uint32         : is_64 (0 - no, !=0 - yes)
  //   (packed)   uint32         : is_msb (0 - no, !=0 - yes)
  //   (packed)   uint64         : declared load address
  //   (packed)   uint32         : number of DWARF section infos.
  //   (packed)   sec info       : DWARF section info, N times.
  // Returns: 0   - ok
  //          !=0 - error (text in output buffer.)
  //
  // The structure of a "sec info" is:
  //   (packed)   uint64 address_in_memory
  //   (packed)   uint64 size (in bytes)
  //   (packed)   uint16 section_index
  //   (unpacked) char * section_name
  rpcsrv_ioctl_dwarf_secinfo = MIN_SERVER_IOCTL + 1,

  // Get DWARF section data.
  //
  // client->server
  //   (unpacked) char *         : file_path (on the server's disk.)
  //   (packed)   uint32         : processor ID (as in: ph.id)
  //   (packed)   uint16         : DWARF section index (as returned by 'rpcsrv_ioctl_dwarf_secinfo')
  // server->client
  //   (unpacked) byte *         : DWARF section data.
  // Returns: 0   - ok
  //          !=0 - error
  rpcsrv_ioctl_dwarf_secdata,

#if defined(TESTABLE_BUILD)
  // Set path to look for ELF/DWARF companion files, per-PID
  //
  // This is strictly meant for testing, where tests can store
  // files in unusual places on the leasing debug server's volume.
  //
  // client->server
  //  (packed)   uint32          : the PID
  //  (unpacked) char *          : directory path (on the server's disk.)
  // server->client
  //  Nothing
  // Returns: 0    - ok
  //          != 0 - error
  rpcsrv_ioctl_set_elf_debug_file_directory_for_pid = 2 * MIN_SERVER_IOCTL + 1,
#endif
};

#if defined(TESTABLE_BUILD) && defined(__LINUX__)
void set_elf_debug_file_directory_for_pid(int pid, const char *path);
const char *get_elf_debug_file_directory_for_pid(int pid);
#endif

#endif // __DBG_RPC_HANDLER_IOCTLS__


#ifndef WIN32_RPC_H
#define WIN32_RPC_H

// IOCTL codes for the win32 debugger

#define WIN32_IOCTL_RDMSR    0 // read model specific register
#define WIN32_IOCTL_WRMSR    1 // write model specific register
#define WIN32_IOCTL_READFILE 2 // server->client: read bytes from the input file
                               //  uint64 offset;
                               //  uint32 length;
                               // returns: 1 - ok
                               //         -2 - error (text in output buffer)

// Open file for PDB retrieval.
//
// This operation will *typically* require that executable data
// be provided to the underlying MS PDB "DIA" dll. Therefore,
// there is _no_ way (currently) that this operation will
// immediately return something relevant. The client must
// poll for _OPERATION_COMPLETE-ness.
//
// client->server
//   (unpacked) compiler_info_t: compiler_info
//   (packed)   uint64         : base_address
//   (unpacked) char *         : input_file
//   (unpacked) char *         : user symbols path
// server->client
//   (packed)   uint32         : session handle
#define WIN32_IOCTL_PDB_OPEN               3

// Close PDB 'session', previously opened with _PDB_OPEN.
//
// client->server
//   (packed) uint32           : session handle
// server->client
//   void
#define WIN32_IOCTL_PDB_CLOSE              4

// Fetch the data for one symbol.
//
// Synchronous operation.
//
// client->server
//   (packed) uint32           : session handle
//   (packed) uint64           : symbol ID
// server->client
//       (unpacked) uint32: The integer value 1.
//       (serialized) data: Packed symbol data (once).
#define WIN32_IOCTL_PDB_FETCH_SYMBOL       5

// Fetch the data for the children of a symbol.
//
// Synchronous operation.
//
// client->server
//   (packed) uint32           : session handle
//   (packed) uint64           : symbol ID
//   (packed) uint32           : children type (a SymTagEnum)
// server->client
//       (unpacked) uint32: Number of symbols whose data
//                          has been fetched.
//       (serialized) data: Packed symbol data (N times).
#define WIN32_IOCTL_PDB_FETCH_CHILDREN     6

// Is the current operation complete?
//
// Depending on the type of the operation, the contents
// of the results will differ:
//  - _OPEN
//       (packed) uint64 : Global symbol ID.
//       (packed) uint32 : machine type.
//       (packed) uint32 : DIA version.
//
// NOTE: Currently, this IOCTL only makes sense to check
//       for completeness of operation _OPEN, but this
//       might change in the future.
//
// client->server
//   (packed) uint32           : session handle
// server->client
//   (packed) uint32           : See pdb_op_completion_t
// Depending on this first byte, the following will be come:
// pdb_op_not_complete:
//   nothing
// pdb_op_complete:
//   (packed) uint32           : global symbol ID
//   (packed) uint32           : machine type
//   (packed) uint32           : DIA version
//   (unpacked) str            : used file name
// pdb_op_failure:
//   (unpacked) str            : error message

#define WIN32_IOCTL_PDB_OPERATION_COMPLETE 7

// Get lines by VA
//
// client->server
//   (packed) uint32           : session handle
//   (packed) ea_t             : VA
//   (packed) uint64           : length
// server->client
//   (packed) uint32           : the number of line-number objects
//   (packed) data             : the line-number objects (N times)
//
// Each of the line-number objects is transmitted like so:
//   (packed) ea_t             : VA
//   (packed) uint32           : length
//   (packed) uint32           : columnNumber
//   (packed) uint32           : columnNumberEnd
//   (packed) uint32           : lineNumber
//   (packed) uint32           : lineNumberEnd
//   (packed) uint32           : file_id
//   (unpacked) byte           : statement
#define WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_VA 8

// Get lines by coordinates
//
// client->server
//   (packed) uint32           : session handle
//   (packed) uint32           : file ID
//   (packed) uint32           : lnnum
//   (packed) uint32           : colnum
// server->client
//   same as WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_VA
#define WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_COORDS 9

// Get symbols at EA
//
// client->server
//   (packed) uint32           : session handle
//   (packed) ea_t             : VA
//   (packed) uint64           : length
//   (packed) uint32           : children type (a SymTagEnum)
// server->client
//       (unpacked) uint32: Number of symbols whose data
//                          has been fetched.
//       (serialized) data: Packed symbol data (N times).
#define WIN32_IOCTL_PDB_SIP_FETCH_SYMBOLS_AT_VA 10

// Get compilands for file
//
// client->server
//   (packed) uint32           : session handle
//   (packed) uint32           : file ID
// server->client
//       (unpacked) uint32: Number of symbols whose data
//                          has been fetched.
//       (serialized) data: Packed symbol data (N times).
#define WIN32_IOCTL_PDB_SIP_FETCH_FILE_COMPILANDS 11

// Get path for file ID
//
// client->server
//   (packed) uint32           : session handle
//   (packed) uint32           : file ID
// server->client
//       (unpacked) str        : the path
#define WIN32_IOCTL_PDB_SIP_FETCH_FILE_PATH 12

// Get files IDs for files corresponding to symbol
//
// client->server
//   (packed) uint32           : session handle
//   (packed) uint64           : symbol ID
// server->client
//   (packed) uint32           : the number of IDs
//   (packed) uint32           : file ID (N times).
#define WIN32_IOCTL_PDB_SIP_FETCH_SYMBOL_FILES 13

// Get files IDs for files whose name matches
//
// client->server
//   (packed) uint32           : session handle
//   (unpacked) str            : the file name
// server->client
//   (packed) uint32           : the number of IDs
//   (packed) uint32           : file ID (N times).
#define WIN32_IOCTL_PDB_SIP_FIND_FILES 14

enum ioctl_pdb_code_t
{
  pdb_ok = 1,
  pdb_error = -2,
};

enum pdb_op_completion_t
{
  pdb_op_not_complete = 0,
  pdb_op_complete = 1,
  pdb_op_failure = -1,
};


// WIN32_IOCTL_WRMSR uses this structure:
struct win32_wrmsr_t
{
  uint32 reg;
  uint64 value;
};


#endif // WIN32_RPC_H

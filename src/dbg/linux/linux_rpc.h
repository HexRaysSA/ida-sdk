
#ifndef LINUX_RPC_H
#define LINUX_RPC_H

// IOCTL code for the linux debugger

// int sent_ioctl( int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
// return 0: unknown function

#define LINUX_IOCTL_LIBUNWIND_PATH    1 // pass the libunwind path to the remote debugger
  // used only for communication between ida64 and linux_server64
  // returns:
  //   - 1: libunwind path correctly copied on the server
  //   - otherwise: not supported
  // buf: either an absolute path to libunwind, or just the name of the libunwind to load in the regular 'ld' path

#endif // LINUX_RPC_H

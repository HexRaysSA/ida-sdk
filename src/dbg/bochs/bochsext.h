/*
 *      Interactive disassembler (IDA).
 *      ALL RIGHTS RESERVED.
 *      Copyright (c) 1990-2024 Hex-Rays
 *
 *
 *      This file defines the Bochs Debugger module extension functions.
 *      Use debugger_t->get_debmod_extensions() to retrieve this structure.
 *
 */

#ifndef __BOCHSEXT__
#define __BOCHSEXT__

#define BOCHSEXT_VER 1

struct bochsext_t
{
  // the structure version
  uint32 version;

  // Sends an arbitrary command to Bochs internal debugger
  //      cmd - command to send
  //      out - pointer to qstring that will hold the output of the command
  // Returns: true if ok; false if failed to send command to bochs or receive
  //          a reply
  bool (idaapi *send_command)(const char *cmd, qstring *out);
};

#endif

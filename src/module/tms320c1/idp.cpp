// $Id: idp.cpp,v 1.9 2000/11/06 22:11:16 jeremy Exp $
//
// Copyright (c) 2000 Jeremy Cooper.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//    This product includes software developed by Jeremy Cooper.
// 4. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//
// IDA TMS320C1X processor module.
//     IDP module entry structure
//
#include "../idaidp.hpp"
#include "tms320c1.hpp"
#include "ana.hpp"
#include "reg.hpp"
#include "out.hpp"
#include "ins.hpp"
#include "asms.hpp"

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(new tms320c1_t);
  return 0;
}

//
// This function is the entry point that is called to notify the processor
// module of an important event.
//
ssize_t idaapi tms320c1_t::on_event(ssize_t msgid, va_list va)
{
  int code = 1;
  switch ( msgid )
  {
    case processor_t::ev_init:
      //
      // Initialize the processor module.
      //
      tms320c1x_Init();
      break;
    case processor_t::ev_newfile:
      //
      // Prepare for decoding of the file that has just been
      // loaded.
      //
      tms320c1x_NewFile();
      break;
    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        outHeader(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        outFooter(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        outSegStart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out_ins = va_arg(va, insn_t *);
        return ana(out_ins);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    default:
      code = 0;
      break;
  }
  return code;
}

//
// tms320c1x_Init()
//
// Initialize the processor module.
//
// (Called from on_event()).
//
void tms320c1_t::tms320c1x_Init() const
{
  //
  // Have the IDA kernel interpret the data within the virtual
  // address space in a big-endian manner.
  //
  inf_set_be(true);
}

//
// tms320c1x_NewFile()
//
// Make any preparations needed to interpret the file that has
// just been loaded.
//
// (Called from on_event()).
//
void tms320c1_t::tms320c1x_NewFile()
{
  ea_t      data_start;
  segment_t dpage0, dpage1;

  //
  // There are no known executable file formats for TMS320C1X executables.
  // Therefore, we will assume in this processor module that the user
  // has loaded a program ROM image into IDA.  This image lacks any
  // definitions for data RAM, so we must create an area in IDA's virtual
  // address space to represent this RAM, thus enabling us to make
  // and track cross-references made to data RAM by TMS320C1X instructions.
  //
  // The TMS320C1X accesses data RAM in two discrete ways, the first of
  // which has a major impact on the strategy we must use to represent
  // data RAM.
  //
  // The first kind of access occurs during the execution of instructions
  // with immediate address operands.  The 7-bit immediate address operand
  // is combined with the current data page pointer bit in the processor
  // status register to give an 8-bit final address.  We will simulate this
  // behavior by keeping track of the data page pointer bit from instruction
  // to instruction, in effect acting as though it were a segment register.
  // We will then treat the 7-bit immediate address operand in each
  // instruction as though it were an offset into one of two data RAM
  // segments, depending on the current value of the data page pointer bit.
  // To do this, we need to create and define those two data segments here.
  //
  // The second manner in which the TMS320C1X access data RAM is during the
  // execution of instructions with indirect address operands.  An indirect
  // address operand is one which identifies a location in data RAM
  // indirectly through the current value in one of the accumulator or
  // auxiliary registers.  These memory references are fully qualified
  // since all three of these registers are spacious enough to hold all
  // 8-bits of addressing information.  Therefore, we needn't do anything
  // special here to accomodate these instructions.
  //

  //
  // Find a suitable place in IDA's virtual address space to place
  // the TMS320C1X's data RAM.  Make sure it is aligned on a 16 byte
  // boundary.
  //
  data_start = find_free_chunk(0, TMS320C1X_DATA_RAM_SIZE, 15);

  ////
  //// Create the first data segment, otherwise known as 'data page 0'.
  ////

  //
  // Define its start and ending virtual address.
  //
  dpage0.start_ea = data_start;
  dpage0.end_ea   = data_start + (TMS320C1X_DATA_RAM_SIZE / 2);
  //
  // Assign it a unique selector value.
  //
  dpage0.sel     = allocate_selector(dpage0.start_ea >> 4);
  //
  // Let the kernel know that it is a DATA segment.
  //
  dpage0.type    = SEG_DATA;
  //
  // Create the segment in the address space.
  //
  add_segm_ex(&dpage0, "dp0", nullptr, ADDSEG_OR_DIE);

  ////
  //// Create the second data segment, otherwise known as 'data page 1'.
  ////

  //
  // Define its start and ending virtual address.
  //
  dpage1.start_ea = data_start + (TMS320C1X_DATA_RAM_SIZE / 2);
  dpage1.end_ea   = data_start + TMS320C1X_DATA_RAM_SIZE;
  //
  // Assign it a unique selector value.
  //
  dpage1.sel     = allocate_selector(dpage1.start_ea >> 4);
  //
  // Let the kernel know that it is a DATA segment.
  //
  dpage1.type    = SEG_DATA;
  //
  // Create the segment in the address space.
  //
  add_segm_ex(&dpage1, "dp1", nullptr, ADDSEG_OR_DIE);

  //
  // Store the selectors of these two data segments in the global
  // variables tms320c1x_dpage0 and tms320c1x_dpage1.
  //
  tms320c1x_dpage0 = dpage0.sel;
  tms320c1x_dpage1 = dpage1.sel;
}


//
// Short supported processor names.
//
// [ This array is named in our processor_t.psnames member ]
//
static const char *const shnames[] =
{
  "tms320c1x",
  nullptr
};

//
// Descriptive supported processor names.
//
// [ This array is named in our processor_t.plnames member ]
//
#define FAMILY "TMS320C1X Series:"
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C1X DSP",
  nullptr
};

//
// Array of opcode streams that represent a function return
// instruction.
//
// [ This array is named in our processor_t.retcodes member ]
//
const bytes_t tms320c1x_retCodes[] =
{
  { 0, 0 }
};

//////////////////////////////////////////////////////////////////////////////
// PROCESSOR MODULE DEFINITION
//////////////////////////////////////////////////////////////////////////////
processor_t LPH =
{
  IDP_INTERFACE_VERSION,// version
  PLFM_TMS320C1X,       // id
                        // flag
                        //
                        // processor module capablilty flags:
                        //
    PR_RNAMESOK         // A register name can be used to name a location
  | PR_BINMEM           // The module creates segments for binary files
  | PR_SEGS,            // We'd like to use the segment register tracking
                        // features of IDA.
                        // flag2
  0,
                        //
  16,                   // Bits in a byte for code segments
  16,                   // Bits in a byte for other segments
  shnames,              // Array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor
                        // selection menu type
  tms320c1x_Assemblers, // array of target assemblers

  notify,               // Callback function for kernel event notification

  registerNames,        // Regsiter names
  nregisterNames,       // Number of registers

  IREG_VCS,             // First segment-register number
  IREG_VDS,             // Last segment-register number
  1,                    // size of a segment register
  IREG_VCS,             // CS segment-register number
  IREG_VDS,             // DS segment-register number

  nullptr,                 // Known code start sequences
  tms320c1x_retCodes,   // Known return opcodes

  I__FIRST,             // First instruction number
  I__LAST,              // Last instruction number
  Instructions,         // instruc
};

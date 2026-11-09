// $Id: out.cpp,v 1.7 2000/11/06 22:11:16 jeremy Exp $
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
//     Instruction display routines
//
#include "../idaidp.hpp"

#include <segregs.hpp>

#include "ins.hpp"
#include "out.hpp"
#include "reg.hpp"

//
// outSegStart()
//
// [ This function is named in our processor_t.segstart member ]
//
// Generate assembly text before the start of a segment.
//
void idaapi outSegStart(outctx_t &ctx, segment_t *)
{
  ctx.gen_cmt_line("A segment starts here.");
}

//
// outSegEnd()
//
// [ This function is named in our processor_t.segend member ]
//
// Generate assembly text after the end of a segment.
//
void idaapi outSegEnd(outctx_t &ctx, segment_t *)
{
  ctx.gen_cmt_line("A segment ends here.");
}

//
// outHeader()
//
// [ This function is named in our processor_t.header member ]
//
// Generate an assembly header for the top of the file.
//
void idaapi outHeader(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_AND_ASM);
}

//
// outFooter()
//
// [ This function is named in our processor_t.footer member ]
//
// Generate an assembly footer for the bottom of the file.
//
void idaapi outFooter(outctx_t &ctx)
{
  ctx.gen_cmt_line("End of file");
}

////////////////////////////////////////////////////////////////////////////
//
// DISASSEMBLY OPERAND HELPER FUNCTIONS
//
////////////////////////////////////////////////////////////////////////////

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_tms320c1_t)

//
// outPhrase(phrase)
// Output a TMS320C1X-specific operand phrase.
//
void out_tms320c1_t::outPhrase(int phrase)
{
  //
  // Complex phrase operand.
  // (Processor specific)
  //
  switch ( phrase )
  {
    case IPH_AR:
      //
      // Current address register, indirect.
      //
      out_symbol('*');
      break;
    case IPH_AR_INCR:
      //
      // Current address register, indirect, post-increment.
      //
      out_symbol('*');
      out_symbol('+');
      break;
    case IPH_AR_DECR:
      //
      // Current address register, indirect, post-decrement.
      //
      out_symbol('*');
      out_symbol('-');
      break;
  }
}

//
// outNear(operand)
//
// Display an operand that is known to reference another piece of
// of code.
//
void out_tms320c1_t::outNear(const op_t &op)
{
  //
  // Calculate the effective address of this code reference.
  //
  ea_t ea = to_ea(insn.cs, op.addr);

  //
  // Find or create a name for the code address that this operand
  // references so that we can output that name in the operand's
  // place.
  //
  if ( !out_name_expr(op, ea, op.addr) )
    //
    // The code address didn't have a name.  Default to
    // displaying the address as a number.
    //
    out_value(op, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN);

  //
  // Let the user know that he or she should look at this
  // instruction and attempt to name the address that it
  // references.
  //
  remember_problem(PR_NONAME, insn.ea);
}


//
// outNear(operand)
//
// Display an operand that is known to reference data RAM.
//
void out_tms320c1_t::outMem(const op_t &op)
{
  //
  // Ask the IDA kernel for the value of the current data page
  // pointer for execution of this instruction.
  //
  sel_t data_selector = get_sreg(insn.ea, IREG_VDS);

  //
  // Is it known?
  //
  if ( data_selector == BADSEL )
  {
    //
    // The current data page pointer is not known.
    //
    //
    // Display the current operand as a regular number and
    // return.
    //
    out_value(op, OOF_ADDR);
    return;
  }

  //
  // The current data page pointer is known.  Use it to calculate the
  // effective address of the memory being referenced by this
  // operand.
  //
  ea_t ea = sel2ea(data_selector) + op.addr;

  //
  // Find or create a name for the data address that this operand
  // references so that we can output that name in the operand's
  // place.
  //
  if ( !out_name_expr(op, ea, op.addr) )
  {
    //
    // No name was found and no name was created.
    // Display the current operand as a regular number.
    //
    out_value(op, OOF_ADDR);

    //
    // Let the user know that he or she should look at this
    // instruction and attempt to name the address that it
    // references.
    //
    remember_problem(PR_NONAME, insn.ea);
  }
}

bool out_tms320c1_t::out_operand(const op_t &op)
{
  switch ( op.type )
  {
    case o_reg:
      //
      // Register operand.
      //
      outreg(op.reg);
      break;
    case o_phrase:
      //
      // Complex phrase.
      // (Processor specific)
      //
      outPhrase(op.phrase);
      break;
    case o_imm:
      //
      // Immediate value.
      //
      out_value(op, 0);
      break;
    case o_near:
      //
      // Code reference.
      //
      outNear(op);
      break;
    case o_mem:
      //
      // Data memory reference.
      //
      outMem(op);
      break;
    default:
      break;
  }
  return 1;
}

void out_tms320c1_t::out_insn()
{
  //
  // An unseen parameter to this function is the 'insn' structure
  // which holds all the information about the instruction that we
  // are being asked to display.
  //

  // This call to out_mnemonic() is a helper function in the IDA kernel that
  // displays an instruction mnemonic for the current instruction.
  // It does so by taking the integer value in insn.itype and using it
  // as an index into the array that we named in this processor module's
  // processor_t.instruc member. From this indexed element comes the
  // instruction mnemonic to be displayed.
  //
  out_mnemonic();

  //
  // If the current instruction has a non-empty first operand,
  // then display it.
  //
  if ( insn.Op1.type != o_void )
  {
    //
    // This call to out_one_operand() is another IDA kernel function that
    // is mandatory for a properly behaved processor module.
    //
    // Normally, this helper function turns around and calls the function
    // named in our processor_t.u_outop member with a reference to
    // the current instruction's operand numbered in the first argument.
    // However, if through the course of interacting with the
    // disassembly the user chooses to manually override the specified
    // operand in this instruction, the IDA kernel will forego the call
    // to u_outop() -- instead calling an internal IDA routine to
    // display the user's manually entered operand.
    //
    out_one_operand(0);
  }
  //
  // Display the second operand, if non-empty.
  //
  if ( insn.Op2.type != o_void )
  {
    //
    // This call to out_symbol() is another helper function in the
    // IDA kernel.  It writes the specified character to the current
    // buffer, using the user-configurable 'symbol' color.
    //
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }
  //
  // Finally, display the third operand, if non-empty.
  //
  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);
  }

  //
  // Tell IDA to display our constructed line.
  //
  flush_outbuf();
}

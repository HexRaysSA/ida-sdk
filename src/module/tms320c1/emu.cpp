// $Id: emu.cpp,v 1.6 2000/11/06 22:11:16 jeremy Exp $
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
// TMS320C1X Processor module
//       Instruction emulation.
//
#include "../idaidp.hpp"
#include <segregs.hpp>

#include "tms320c1.hpp"
#include "ins.hpp"
#include "reg.hpp"

int tms320c1_t::emu(const insn_t &insn) const
{
  //
  // Determine the current instruction's features.
  //
  int features = insn.get_canon_feature(ph);
  bool flow = (features & CF_STOP) == 0;

  //
  // Examine each operand and determine what effect, if any,
  // it makes on the environment.
  //
  // Operands that are read
  if ( features & CF_USE1 )
    flow &= handle_operand(insn, insn.Op1, hop_READ);
  if ( features & CF_USE2 )
    flow &= handle_operand(insn, insn.Op2, hop_READ);
  if ( features & CF_USE3 )
    flow &= handle_operand(insn, insn.Op3, hop_READ);
  // Operands that are written
  if ( features & CF_CHG1 )
    flow &= handle_operand(insn, insn.Op1, hop_WRITE);
  if ( features & CF_CHG2 )
    flow &= handle_operand(insn, insn.Op2, hop_WRITE);
  if ( features & CF_CHG3 )
    flow &= handle_operand(insn, insn.Op3, hop_WRITE);

  //
  // Determine whether the instruction stops the execution flow.
  //
  if ( flow )
  {
    //
    // This instruction doesn't stop execution flow.
    // Add a cross reference to the next instrction.
    //
    add_cref(insn.ea, insn.ea+insn.size, fl_F);
  }

  //
  // If the instruction makes a branch, let the IDA kernel
  // know.
  //
  if ( features & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  return 1;
}

bool tms320c1_t::handle_operand(const insn_t &insn, const op_t &op, opRefType ref_type) const
{
  ea_t ea;
  sel_t data_selector;
  bool flow = true;

  switch ( op.type )
  {
    case o_reg:
      //
      // Register operand.
      //
      //
      // Nothing needs to be calculated or examined for this
      // operand.
      //
      break;
    case o_imm:
      //
      // Immediate operand.
      //
      // Make sure that this operand reference isn't a write reference.
      // (Writing to an immediate value is not allowed and is a sure
      // sign of a badly decoded instruction).
      //
      if ( ref_type == hop_WRITE )
      {
        //
        // Attempt to write to an immediate value.
        // Error.
        //
        warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), op.n, op.type);
        break;
      }
      //
      // SPECIAL INSTRUCTION CASE:
      //
      // The LDPK instruction is decoded by ana() to have an immediate
      // value as an operand.  However, this immediate value is to be
      // the new data page pointer, which we must track for proper
      // memory referencing.
      //
      if ( insn.itype == I_LDPK )
      {
        //
        // This is an LDPK instruction.  Let the kernel know that
        // we are changing the current data page pointer.  We track
        // this bit as though it were a virtual segment register named
        // I_VDS, although it is not a true register in the CPU.
        //
        // Determine into which data page the instruction is attempting
        // to point.
        //
        if ( op.value == 0 )
        {
          //
          // Data page 0 is being loaded.
          //
          data_selector = tms320c1x_dpage0;
        }
        else
        {
          //
          // Data page 1 is being loaded.
          //
          data_selector = tms320c1x_dpage1;
        }
        //
        // Notify the IDA kernel of the change.
        //
        split_sreg_range(
                insn.ea,          // The current instruction's address
                IREG_VDS,        // The segment register being modified
                data_selector,   // The new selector value being loaded
                SR_auto);        // How the new value was determined
      }
      //
      // Let the kernel know that the instruction's address should
      // be marked with a 'has immediate value' flag.
      // (Useful during search?)
      //
      set_immd(insn.ea);
      break;
    case o_phrase:
      //
      // Processor-specific phrase.
      //
      // These operands have no currently trackable side effect.
      //
      break;
    case o_mem:
      //
      // Direct memory reference.
      //

      //
      // Ask the IDA kernel for the current data page pointer selector.
      //
      data_selector = get_sreg(insn.ea, IREG_VDS);

      //
      // Is it known?
      //
      if ( data_selector == BADSEL )
      {
        //
        // The current data page pointer is unknown.
        // There is nothing to do.
        //
      }
      else
      {
        //
        // The current data page pointer is known.
        // Calculate the full effective address being referenced
        // by this operand.
        //
        ea = sel2ea(data_selector) + op.addr;

        //
        // Generate a data cross reference from this instruction
        // to the target address.
        //
        insn.add_dref(ea, op.offb, ref_type == hop_READ ? dr_R : dr_W);
      }

      //
      // TODO: DMOV, ...
      // These instructions read from the address in their operands
      // and write to the address ADJACENT to it.
      //
      break;
    case o_near:
      //
      // Code reference in current segment.
      //
      //
      // Determine the effective address of the reference.
      //
      ea = to_ea(insn.cs, op.addr);

      //
      // Is this a 'CALL' type reference, or a branch type reference?
      //
      if ( has_insn_feature(insn.itype, CF_CALL) )
      {
        //
        // This is a CALL type reference.  Make a cross reference
        // that notes it.
        //
        insn.add_cref(ea, op.offb, fl_CN);
        if ( !func_does_return(ea) )
          flow = false;
      }
      else
      {
        //
        // This is a branch type reference.  Make a cross reference
        // that notes it.
        //
        insn.add_cref(ea, op.offb, fl_JN);
      }
      break;
    default:
      //
      // Unhandled operand type.
      // Error.
      //
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), op.n, op.type);
      break;
  }
  return flow;
}

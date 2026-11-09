// $Id: out.hpp,v 1.4 2000/11/06 22:11:17 jeremy Exp $
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
#ifndef _IDP_TMS320C1X_OUT_H
#define _IDP_TMS320C1X_OUT_H

void idaapi outSegStart(outctx_t &, segment_t *);
void idaapi outSegEnd(outctx_t &, segment_t *);
void idaapi outHeader(outctx_t &);
void idaapi outFooter(outctx_t &);
bool idaapi outOp(outctx_t &ctx, const op_t &op);
void idaapi out(outctx_t &ctx);

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_tms320c1_t : public outctx_t
{
  out_tms320c1_t(void) = delete; // not used
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
  void outreg(int r) { out_register(ph.reg_names[r]); }
  void outPhrase(int phrase);
  void outNear(const op_t &op);
  void outMem(const op_t &op);
};
CASSERT(sizeof(out_tms320c1_t) == sizeof(outctx_t));


#endif  // _IDP_TMS320C1X_OUT_H





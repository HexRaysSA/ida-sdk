
#ifndef __BACKTRACK_HPP__
#define __BACKTRACK_HPP__

#include <pro.h>
#include <idp.hpp>

enum btsource_t
{
  BT_NONE = 0,
  BT_STACK,
  BT_A,
  BT_X,
  BT_Y,
  BT_DP
};


/**
 * Walk instructions up, and try and determine what's the
 * (size * 8)-bits value we're looking for.
 *
 * For example, let's assume we have the following sequence
 * of instructions:
 *   .05:8001                 PHK
 *   .05:8002                 PLB
 * We'll call:
 *   backtrack_value(0x58002, 1, BT_STACK).
 *
 * A more complex example is this:
 *   .C0:0024 A2 00 00                    LDX     #0
 *   .C0:0027 DA                          PHX
 *   .C0:0028 2B                          PLD
 *   .C0:0029 7B                          TDC
 *   .C0:002A 48                          PHA
 *   .C0:002B AB                          PLB
 * We'll call:
 *   backtrack_value(0xc0002b, 1, BT_STACK), which will call
 *   backtrack_value(0xc0002a, 1, BT_A),     which will call
 *   backtrack_value(0xc00029, 1, BT_D),     which will call
 *   backtrack_value(0xc00028, 2, BT_STACK), which will call
 *   backtrack_value(0xc00027, 2, BT_X),     which has an immediate value that we can use. Bingo.
 *
 * Backtracking will, of course, stop if we hit the top
 * of a function, as it doesn't make much sense to keep
 * moving up.
 *
 * from_ea : The address from which we'll be analyzing up.
 * size    : The size, in bytes, of the data we're looking for.
 * source  : The register/stack that holds the value.
 *
 * returns : The value.
 */
int32 backtrack_value(ea_t from_ea, uint8 size, btsource_t source);


/**
 * Walk instructions up, until an instruction with the given type
 * is found.
 *
 * Backtracking will, of course, stop if we hit the top
 * of a function, as it doesn't make much sense to keep
 * moving up.
 *
 * from_ea : The address from which we'll be analyzing up.
 * itype   : The instruction type.
 *
 * returns : The address of the found instruction, or BADADDR
 *           if not found.
 */
ea_t backtrack_prev_ins(ea_t from_ea, m65_itype_t itype);


#endif

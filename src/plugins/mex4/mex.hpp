/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */
#pragma once

/*! \file mex.hpp

  \brief An example how to implement IDA merge functionality

  In this case sample plugin stores its options in netnode blob.

  Usually blob data is displayed as a sequence of hexadecimal digits
  in merge chooser column.
  We show how to display blob contents in detail pane.

*/

//-------------------------------------------------------------------------
#define MEX_NUMBER QSTRINGIZE(MEX_N)

//-------------------------------------------------------------------------
// netnode to store plugin data
#define MEX_NODE_NAME "$ merge example" MEX_NUMBER
// user input
#define MEX_BLOB_TAG  'b'   // blob data netnode tag, from nodeidx 0

//-------------------------------------------------------------------------
struct mex_ctx_t;
/// we need an event listener to catch \ref processor_t::ev_create_merge_handlers
DECLARE_LISTENER(idp_listener_t, mex_ctx_t, ctx);

//-------------------------------------------------------------------------
struct mex_ctx_t : public plugmod_t
{
  idp_listener_t idp_listener;  ///< need to catch processor_t::ev_create_merge_handlers,
                                ///< and maybe others

  // regular plugin implementation below

  // user input
  ushort flags = 0;         ///< bit flags
  #define MEX_FLAGS_0 0x01
  #define MEX_FLAGS_1 0x02
  qstring ident;            ///< unique database ident

  mex_ctx_t();
  ~mex_ctx_t();

  virtual bool idaapi run(size_t arg) override;

  void restore_from_idb();
  void save_to_idb() const;
};
extern int data_id;

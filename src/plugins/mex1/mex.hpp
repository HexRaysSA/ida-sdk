/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */
#pragma once

/*! \file mex.hpp

  \brief An example how to implement IDA merge functionality

  This is a primitive plugin which asks user for some info and saves it for
  some addresses.

  We will add a merge functionality to plugin.

  An IDA plugin may have two kinds of data with permanent storage:
    1. Data common for entire database (e.g. the options).
       To describe them we will use the idbattr_info_t type.
    2. Data specific to a particular address.
       To describe them we will use the merge_node_info_t type.

*/

//-------------------------------------------------------------------------
// We will use this plugin to demonstrate several
// approaches to implement merge functionality.
// To distinguish between them let's use MEX_N defined in makefile.
#define MEX_NUMBER QSTRINGIZE(MEX_N)

//-------------------------------------------------------------------------
// netnode to store plugin data
#define MEX_NODE_NAME "$ merge example" MEX_NUMBER
// user input
#define MEX_OPTION_FLAGS_IDX  -1   // atag
#define MEX_OPTION_IDENT_IDX  -2   // stag
// EA marks
static constexpr char ea_tag = 'm';

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

/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _NETNODE_BASE_HPP
#define _NETNODE_BASE_HPP

/*! \file netnode_base.hpp

  \brief Defines the base class of netnode. See netnode.hpp.
*/

/// Base class of netnode: holds the netnode number.
class netnode_internal_t
{
  friend class netnode;

  /// The netnode number.
  /// Usually this is the linear address that the netnode keeps information about.
  nodeidx_t netnodenumber;
};

#endif // _NETNODE_BASE_HPP

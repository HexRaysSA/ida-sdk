/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      This file contains the CVT64 examples.
 *      It includes a regular plugin functionality and boilerplate code.
 *
 *      Steps:
 *      1. Build and install plugin
 *      2. Open or create with IDA the database.idb
 *      3. Run plugin to fill data
 *      4. Run plugin one more time to check the stored data
 *      5. Save database.idb
 *      6. Convert database.idb:
 *         ida64 --cvt64 database.idb
 *      7. Run plugin to check the converted data
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <cvt64.hpp>         // CVT64 helpers

//-------------------------------------------------------------------------
struct cvt64_ctx_t;
// we need an event listener to catch processor_t::ev_cvt64_supval and processor_t::ev_cvt64_hashval
DECLARE_LISTENER(idp_listener_t, cvt64_ctx_t, ctx);

//-------------------------------------------------------------------------
struct cvt64_ctx_t : public plugmod_t
{
  idp_listener_t idp_listener;

  cvt64_ctx_t() : idp_listener(*this)
  {
    // Hook an event listener, to catch the merge-related event(s).
    // Listeners are uninstalled automatically when the owner module is unloaded.
    hook_event_listener(HT_IDP, &idp_listener);
  }

  // plugin database store:
  //   supstr(-1)      - device name
  //   altval(-1)      - idpflags
  //   easet(ea, atag) - references
  //   hashval("Comment")
  //   hashval("Address")
  netnode helper;
#define SAMPLE_NETNODE_NAME "$ cvt64 sample netnode"
#define DEVICE_INDEX   (-1)
#define IDPFLAGS_INDEX (-1)
#define HASH_COMMENT "Comment"
#define HASH_ADDRESS "Address"

  bool idaapi run(size_t) override
  {
    helper = netnode(SAMPLE_NETNODE_NAME);
    if ( helper == BADADDR )
    {
#ifndef __EA64__
      // plugin or processor module saved somehow own data into database
      helper.create(SAMPLE_NETNODE_NAME);

      // string value, usually saved as supstr()
      qstring device = "cvt64 sample device";
      helper.supset(DEVICE_INDEX, device.c_str());

      // flags, usually saved as altval()
      uint32 idpflags = 0x42;
      helper.altset(IDPFLAGS_INDEX, idpflags);

      // values indexed by EA
      static const range_t refs[2] =
      {
        { 0x1000, 0x1500 },
        { 0x1200, BADADDR },
      };
      for ( const auto &ref : refs )
        helper.easet(ref.start_ea, ref.end_ea, atag);

      // hash values
      helper.hashset(HASH_ADDRESS, BADNODE);
      helper.hashset(HASH_COMMENT, "BADADDR = ");

      msg("CVT64 sample: data are ready\n");
#endif
    }
    else
    {
      msg("CVT64 sample:\n");

      qstring device;
      helper.supstr(&device, DEVICE_INDEX);
      msg("  %s\n", device.c_str());

      uint32 idpflags = helper.altval(IDPFLAGS_INDEX);
      msg("  %X\n", idpflags);

      for ( nodeidx_t idx=helper.supfirst(atag);
            idx != BADNODE;
            idx=helper.supnext(idx, atag) )
      {
        ea_t from_ea = node2ea(idx);
        ea_t to_ea = helper.eaget(from_ea, atag);
        if ( to_ea != BADADDR )
          msg("  %a -> %a\n", from_ea, to_ea);
        else
          msg("  %a -> BADADDR\n", from_ea);
      }

      qstring comment;
      helper.hashstr(&comment, HASH_COMMENT);
      ea_t address = helper.hashval_long(HASH_ADDRESS);
      msg("  %s%a\n", comment.c_str(), address);
    }
    return true;
  }
};

//-------------------------------------------------------------------------
ssize_t idaapi idp_listener_t::on_event(ssize_t code, va_list va)
{
  qnotused(code);
  qnotused(va);
#ifdef CVT64
  switch ( code )
  {
    case processor_t::ev_cvt64_supval:
                                ///< perform 32-64 conversion for a netnode array element
                                ///< \param node   (::nodeidx_t)
                                ///< \param tag    (::uchar)
                                ///< \param idx    (::nodeidx_t)
                                ///< \param data   (const ::uchar *)
                                ///< \param datlen (::size_t)
                                ///< \param errbuf (::qstring *) - a error message will be returned here (can be nullptr)
                                ///< \return 0 nothing was done
                                ///< \return 1 converted successfully
                                ///< \return -1 error (and message in errbuf)
      {
        netnode helper = netnode(SAMPLE_NETNODE_NAME);
        // see cvt64.hpp for struct cvt64_node_tag_t and cvt64_node_supval_for_event() documentation.
        // To serve the ev_cvt64_supval event we need to prepare descriptors
        // and all other work cvt64_node_supval_for_event() helper will done.
        static const cvt64_node_tag_t node_info[] =
        {
          CVT64_NODE_DEVICE,
          CVT64_NODE_IDP_FLAGS,
          {
            helper,                               // netnode with the converted data
            atag | NETMAP_VAL | NETMAP_VAL_NDX,   // tag with data,
                                                  // specify that data value is ea_t size and ea_t nature
            0                                     // no specific netnode index (alt),
                                                  // process all values
          }
        };
        // call helper to perform conversion
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
        // if you need to perform the specific unusual conversion
        // use the following pattern:
        // if ( cvt64_node_supval_for_event(va, node_info, qnumber(node_info)) == 1 )
        //   return 1;
        // ... specific conversion, return 1 if succeced -1 if error 0 otherwise
      }
      break;

    case processor_t::ev_cvt64_hashval:
                                ///< perform 32-64 conversion for a hash value
                                ///< \param node   (::nodeidx_t)
                                ///< \param tag    (::uchar)
                                ///< \param name   (const ::char *)
                                ///< \param data   (const ::uchar *)
                                ///< \param datlen (::size_t)
                                ///< \param errbuf (::qstring *) - a error message will be returned here (can be nullptr)
                                ///< \return 0 nothing was done
                                ///< \return 1 converted successfully
                                ///< \return -1 error (and message in errbuf)
      {
        netnode helper = netnode(SAMPLE_NETNODE_NAME);
        nodeidx_t node = va_arg(va, nodeidx_t);
        uchar tag = va_argi(va, uchar);
        // at first need to check netnode and tag
        if ( helper == node && tag == htag )
        {
          const char *name = va_arg(va, const char *);
          if ( streq(name, HASH_COMMENT) )
          {
            qstring comment;
            // read hash value from IDB
            helper.hashstr(&comment, name);
            // write hash value to I64
            helper.hashset(name, comment.c_str());
            return 1; // handled
          }
          else if ( streq(name, HASH_ADDRESS) )
          {
            // read hash value from IDB
            ea_t address = helper.hashval_long(name);
            // need to convert ea32 to ea64
            if ( address == BADADDR32 )
              address = BADADDR;
            // write hash value to I64
            helper.hashset(name, address);
            return 1; // handled
          }
        }
      }
      break;
  }
#endif
  return 0;
}

//-------------------------------------------------------------------------
// Create a plugin context and return it to the kernel.
static plugmod_t *idaapi init()
{
  return new cvt64_ctx_t;
}

//-------------------------------------------------------------------------
static const char comment[] = "An example how to implement CVT64 functionality";
static const char wanted_name[] = "CVT64 sample";
static const char wanted_hotkey[] = "";

//-------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI          // Can work with multiple databases. A must for the plugins
                        // that support IDA Teams. Such plugins must keep all
                        // their data in the plugin context (global data variables
                        // cannot be used because they are not database dependent).
 |PLUGIN_MOD,           // Plugin may modify the database.
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

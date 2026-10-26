#pragma once

#include <functional>
#include <pro.h>
#include <loader.hpp>

/*! \file uefi.h

  \brief UEFI analysis API

  The UEFI plugin analyzes UEFI modules: a single PE/TE image, or the
  modules of a firmware image loaded by the UEFI firmware loader.

  * it resolves the global variables holding the service tables
    (`gBS`, `gRT`, `gST`, `gSmst`, ...), types and names them;
  * it finds the protocol events: installations, uninstallations,
    locates and notification registrations, with the GUIDs involved;
  * it types the protocol interfaces and records them, so the calls
    through a protocol member can be linked to the functions
    implementing that member, across the modules of a firmware image.

  # Key concepts

  * modules: the PE32/PE32+ or TE images of the database (drivers,
    applications, PEIMs, ...). A firmware image will have multiple,
    a single extracted executable will have one.
  * protocol events: the calls that install, uninstall, locate or
    register a notification for a protocol (`InstallProtocolInterface`,
    `LocateProtocol`, `RegisterProtocolNotify`, ...), see uefi_protocol_t.
  * interfaces: the protocol interface structures installed by the
    modules (a global variable of the interface structure type).
  * protocol structures: the structure type of a protocol's interfaces,
    from the type libraries or, when they have none, synthesized by the
    plugin. Edits to it survive a new analysis;
    uefi_svc_t::set_protocol_struct() replaces it.
  * members: a protocol member is identified by its structure name
    and its byte offset in the structure. The plugin identifies
    calls through a member and the functions implementing it.

  GUIDs are exchanged as uefi_guid_t, laid out as EFI_GUID; its text
  form is the registry format (`01234567-89AB-CDEF-0123-456789ABCDEF`).

  # API

  * Use `get_uefi_svc()` to retrieve the API interface,
  * The plugin analyzes the database automatically, when the
    autoanalysis finishes; uefi_svc_t::analyze() runs it again.

  # Compatibility

  A plugin built with this header keeps working with later versions of
  the UEFI plugin.

*/

/// Version of this API. It is incremented when methods are added to
/// uefi_svc_t; uefi_svc_t::get_version() returns the version implemented
/// by the plugin.
#define UEFI_API_VERSION 1

//-------------------------------------------------------------------------
struct uefi_svc_t;
struct uefi_ctx_t;

//-------------------------------------------------------------------------
class uefi_req_t
{
  friend uefi_ctx_t;

protected:
  enum code_t
  {
    urc_unknown = 10,
    urc_get_uefi_svc,
  };

private:
  code_t code = urc_unknown;
  int version = UEFI_API_VERSION;   // of the header the caller was built with

protected:
  uefi_req_t(code_t _code)
    : code(_code) {}

  bool _perform()
  {
    return load_and_run_plugin("uefi", size_t(this));
  }
};

//-------------------------------------------------------------------------
class uefi_svc_req_t : public uefi_req_t
{
  friend uefi_ctx_t;

  uefi_svc_t *svc = nullptr;

public:
  uefi_svc_req_t()
    : uefi_req_t(urc_get_uefi_svc) {}

  uefi_svc_t *perform()
  {
    _perform();
    return svc;
  }
};

//-------------------------------------------------------------------------
/// A GUID, laid out as EFI_GUID. The zero GUID stands for "no GUID".
struct uefi_guid_t
{
  uint32 data1 = 0;     ///< the first 8 hex digits
  uint16 data2 = 0;     ///< the next 4 hex digits
  uint16 data3 = 0;     ///< the next 4 hex digits
  uchar data4[8] = {};  ///< the last 16 hex digits, in text order

  /// Is this the zero GUID?
  bool empty() const
  {
    if ( data1 != 0 || data2 != 0 || data3 != 0 )
      return false;
    for ( uchar b : data4 )
    {
      if ( b != 0 )
        return false;
    }
    return true;
  }

  DECLARE_COMPARISONS(uefi_guid_t)
  {
    if ( data1 != r.data1 )
      return data1 < r.data1 ? -1 : 1;
    if ( data2 != r.data2 )
      return data2 < r.data2 ? -1 : 1;
    if ( data3 != r.data3 )
      return data3 < r.data3 ? -1 : 1;
    return memcmp(data4, r.data4, sizeof(data4));
  }

  /// Format the GUID in the registry format, upper case
  /// (`01234567-89AB-CDEF-0123-456789ABCDEF`).
  qstring to_str() const
  {
    qstring out;
    out.sprnt("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              data1, data2, data3,
              data4[0], data4[1], data4[2], data4[3],
              data4[4], data4[5], data4[6], data4[7]);
    return out;
  }

  /// Parse a GUID in the registry format. Both lower case and upper case
  /// is accepted and enclosing braces are optional.
  /// \param text  the text
  /// \return false if \p text could not be parsed
  bool from_str(const char *text)
  {
    if ( text == nullptr )
      return false;
    bool braced = *text == '{';
    if ( braced )
      ++text;
    uchar b[16];
    int n = 0;
    for ( int i = 0; i < 36; ++i )
    {
      char c = text[i];
      if ( i == 8 || i == 13 || i == 18 || i == 23 )
      {
        if ( c != '-' )
          return false;
        continue;
      }
      int d = c >= '0' && c <= '9' ? c - '0'
            : c >= 'a' && c <= 'f' ? c - 'a' + 10
            : c >= 'A' && c <= 'F' ? c - 'A' + 10
            : -1;
      if ( d < 0 )
        return false;
      if ( (n & 1) == 0 )
        b[n/2] = uchar(d << 4);
      else
        b[n/2] |= uchar(d);
      ++n;
    }
    const char *end = text + 36;
    if ( braced && *end++ != '}' )
      return false;
    if ( *end != '\0' )
      return false;
    data1 = (uint32(b[0]) << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    data2 = uint16((b[4] << 8) | b[5]);
    data3 = uint16((b[6] << 8) | b[7]);
    memcpy(data4, b + 8, sizeof(data4));
    return true;
  }
};
DECLARE_TYPE_AS_MOVABLE(uefi_guid_t);

//-------------------------------------------------------------------------
/// A module of the database
struct uefi_module_t
{
  qstring name;          ///< UI name of the module (`PcdDxe`), or its file GUID
  uefi_guid_t guid;      ///< FFS file GUID; zero in a database of a single
                         ///< module
  qstring kind;          ///< FFS file type (`DXE_DRIVER`, `PEIM`, `MM`, ...);
                         ///< empty in a database of a single module
  ea_t start = BADADDR;  ///< first address of the module
  ea_t end = BADADDR;    ///< last address of the module + 1
  ea_t entry = BADADDR;  ///< entry point
  int ffs_type = 0;      ///< FFS file type number (PI specification, volume 3);
                         ///< 0 in a database of a single module
  uint32 flags = 0;      ///< \ref UEFI_MF_
/// \defgroup UEFI_MF_ Module flags
/// used by uefi_module_t::flags; new flags may be added
///@{
#define UEFI_MF_64BIT 0x00000001 ///< 64-bit code
///@}
  bool is64() const { return (flags & UEFI_MF_64BIT) != 0; }

  bool contains(ea_t ea) const { return start <= ea && ea < end; }

  bool operator==(const uefi_module_t &r) const
  {
    return name == r.name
        && guid == r.guid
        && kind == r.kind
        && start == r.start
        && end == r.end
        && entry == r.entry
        && ffs_type == r.ffs_type
        && flags == r.flags;
  }
  bool operator!=(const uefi_module_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(uefi_module_t);
typedef qvector<uefi_module_t> uefi_module_vec_t;

/// Visitor of the modules, see uefi_svc_t::for_each_module()
/// \return 0 to continue, any other value stops the enumeration
typedef std::function<int(const uefi_module_t &mod)>
        uefi_module_visitor_t;

//-------------------------------------------------------------------------
/// Kinds of protocol events. The PEI services produce the same events
/// for the PPIs, one per entry of the descriptor list.
enum uefi_proto_kind_t
{
  UEFI_PK_INSTALL,      ///< (Re)InstallProtocolInterface,
                        ///< InstallMultipleProtocolInterfaces;
                        ///< InstallPpi, ReInstallPpi
  UEFI_PK_UNINSTALL,    ///< UninstallProtocolInterface,
                        ///< UninstallMultipleProtocolInterfaces
  UEFI_PK_LOCATE,       ///< LocateProtocol, HandleProtocol, OpenProtocol,
                        ///< LocateHandle(Buffer); LocatePpi
  UEFI_PK_NOTIFY,       ///< RegisterProtocolNotify; NotifyPpi
};

/// What is known about the GUID of a protocol event
enum uefi_guid_state_t
{
  UEFI_GS_UNKNOWN,      ///< the GUID could not be determined
  UEFI_GS_KNOWN,        ///< uefi_protocol_t::guid holds the GUID
  UEFI_GS_NULL,         ///< a NULL GUID pointer (LocateHandle(AllHandles))
};

//-------------------------------------------------------------------------
/// A protocol event: a call installing, uninstalling, locating or
/// watching a protocol (see #kind).
/// One call may produce several events (InstallMultipleProtocolInterfaces,
/// a GUID taking several values).
struct uefi_protocol_t
{
  ea_t call_ea = BADADDR;          ///< address of the call
  ea_t iface = BADADDR;            ///< the interface variable, if it is a
                                   ///< global; BADADDR otherwise
  uefi_proto_kind_t kind = UEFI_PK_INSTALL; ///< kind of event
  uefi_guid_state_t guid_state = UEFI_GS_UNKNOWN; ///< see #guid
  uefi_guid_t guid;                ///< the GUID (if #guid_state is
                                   ///< UEFI_GS_KNOWN)
  qstring name;                    ///< name of the GUID (`EfiPcdProtocolGuid`),
                                   ///< empty if not in the GUID database
  qstring service;                 ///< the service called
                                   ///< (`gBS->InstallProtocolInterface`,
                                   ///< `(*PeiServices)->InstallPpi`, or a
                                   ///< PeiServicesLib function:
                                   ///< `PeiServicesLocatePpi`)
  int module = -1;                 ///< index of the module making the call

  bool operator==(const uefi_protocol_t &r) const
  {
    return call_ea == r.call_ea
        && iface == r.iface
        && kind == r.kind
        && guid_state == r.guid_state
        && guid == r.guid
        && name == r.name
        && service == r.service
        && module == r.module;
  }
  bool operator!=(const uefi_protocol_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(uefi_protocol_t);
typedef qvector<uefi_protocol_t> uefi_protocol_vec_t;

/// Visitor of the protocol events, see uefi_svc_t::for_each_protocol()
/// \return 0 to continue, any other value stops the enumeration
typedef std::function<int(const uefi_protocol_t &protocol)>
        uefi_protocol_visitor_t;

//-------------------------------------------------------------------------
/// An installed protocol interface
struct uefi_interface_t
{
  ea_t ea = BADADDR;       ///< address of the interface variable
  qstring struct_name;     ///< its structure (`EFI_PCD_PROTOCOL`); empty if
                           ///< the structure was deleted
  uefi_guid_t guid;        ///< the protocol GUID; zero for a service table
                           ///< (`EFI_BOOT_SERVICES`, ...)
  int module = -1;         ///< index of the module containing it
  uint32 flags = 0;        ///< \ref UEFI_IF_
/// \defgroup UEFI_IF_ Interface flags
/// used by uefi_interface_t::flags; new flags may be added
///@{
#define UEFI_IF_SYNTHESIZED 0x00000001 ///< the structure was built by the
                                       ///< plugin from the installed
                                       ///< interface (no type in the type
                                       ///< libraries)
#define UEFI_IF_NO_TYPE_PROPAGATION 0x00000002 ///< the member types of the
                                       ///< structure are not applied to
                                       ///< the functions implementing the
                                       ///< members (they are only named):
                                       ///< the types are guesses. Set for
                                       ///< the synthesized structures.
///@}
  bool is_synthesized() const { return (flags & UEFI_IF_SYNTHESIZED) != 0; }
  bool no_type_propagation() const
  {
    return (flags & UEFI_IF_NO_TYPE_PROPAGATION) != 0;
  }

  bool operator==(const uefi_interface_t &r) const
  {
    return ea == r.ea
        && struct_name == r.struct_name
        && guid == r.guid
        && module == r.module
        && flags == r.flags;
  }
  bool operator!=(const uefi_interface_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(uefi_interface_t);
typedef qvector<uefi_interface_t> uefi_interface_vec_t;

/// Visitor of the installed interfaces, see uefi_svc_t::for_each_interface()
/// \return 0 to continue, any other value stops the enumeration
typedef std::function<int(const uefi_interface_t &iface)>
        uefi_interface_visitor_t;

//-------------------------------------------------------------------------
/// A function implementing a protocol member
struct uefi_member_impl_t
{
  ea_t func = BADADDR;     ///< the function
  ea_t iface = BADADDR;    ///< the installed interface holding it; BADADDR
                           ///< when the function is stored into the member
                           ///< at run time (`gRT->ConvertPointer = f`)
  int module = -1;         ///< index of the module containing the function

  bool operator==(const uefi_member_impl_t &r) const
  {
    return func == r.func && iface == r.iface && module == r.module;
  }
  bool operator!=(const uefi_member_impl_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(uefi_member_impl_t);
typedef qvector<uefi_member_impl_t> uefi_member_impl_vec_t;

/// Visitor of the functions implementing a protocol member, see
/// uefi_svc_t::for_each_member_impl()
/// \return 0 to continue, any other value stops the enumeration
typedef std::function<int(const uefi_member_impl_t &member_impl)>
        uefi_member_impl_visitor_t;

//-------------------------------------------------------------------------
/// IDA's UEFI API interface
///
/// Use get_uefi_svc() to retrieve an implementation.
struct uefi_svc_t
{
  virtual ~uefi_svc_t() {}

  /// Version of the API implemented by the plugin: the UEFI_API_VERSION
  /// it was built with
  virtual int get_version() const = 0;

  /// \name Modules
  //@{

  /// Return the number of modules in the database.
  /// A database of a single PE/TE image has one module.
  virtual int get_modules_count() const = 0;

  /// Enumerate the modules, by index.
  /// \param v  the visitor
  /// \return the value returned by the visitor that stopped the
  ///         enumeration, or 0
  virtual int for_each_module(const uefi_module_visitor_t &v) const = 0;

  /// Find the module containing an address.
  /// \param ea  effective address
  /// \return the module index, or -1 if \p ea is in no module
  virtual int get_module_index(ea_t ea) const = 0;

  /// Find a module by name (uefi_module_t::name) or by file GUID.
  /// \param name  module name, or file GUID as text
  /// \return the first module with that name, or -1
  virtual int find_module(const char *name) const = 0;

  //@}

  /// \name Analysis
  //@{

  /// Has the analysis of the database been performed?
  virtual bool is_analyzed() const = 0;

  /// Analyze the database again: all modules, then link the protocol
  /// calls. The results of the previous analysis are removed first: the
  /// protocol events, the interfaces, the member calls and
  /// implementations, and the cross-references added by
  /// link_protocol_calls(). The structures bound to the protocols (see
  /// set_protocol_struct()) are kept.
  /// Needs the decompiler and the UEFI type library.
  /// \param flags  reserved for options of later versions; must be 0
  /// \return success; false if \p flags is not 0
  virtual bool analyze(uint32 flags=0) = 0;

  /// Analyze one module again. The new results are added to the
  /// existing ones, none is removed (analyze() starts afresh); the
  /// protocol calls are not linked (see link_protocol_calls()).
  /// Needs the decompiler and the UEFI type library.
  /// \param module_index  module index
  /// \param flags         reserved for options of later versions; must be 0
  /// \return success; false if \p flags is not 0
  virtual bool analyze_module(int module_index, uint32 flags=0) = 0;

  /// Add code cross-references from the recorded calls through the
  /// protocol members to the functions implementing them. The
  /// cross-references added by the previous call are removed first, so
  /// calling it again is safe. Cross-references that already existed are
  /// left alone, and never removed. A cross-reference added by the user
  /// after this call, identical to one of ours, is removed with ours.
  /// \return the number of cross-references added
  virtual int link_protocol_calls() = 0;

  //@}

  /// \name Protocols
  //@{

  /// Enumerate the protocol events found by the analysis.
  /// \param v  the visitor
  /// \return the value returned by the visitor that stopped the
  ///         enumeration, or 0
  virtual int for_each_protocol(const uefi_protocol_visitor_t &v) const = 0;

  /// Enumerate the installed protocol interfaces.
  /// \param v  the visitor
  /// \return the value returned by the visitor that stopped the
  ///         enumeration, or 0
  virtual int for_each_interface(const uefi_interface_visitor_t &v) const = 0;

  /// Is a structure synthesized by the plugin from an installed
  /// interface? (see #UEFI_IF_SYNTHESIZED)
  /// \param struct_name  structure name
  virtual bool is_synthesized_struct(const char *struct_name) const = 0;

  /// Get the structure bound to a protocol.
  /// \param[out] out   receives the structure name
  /// \param      guid  the protocol GUID
  /// \return false if no structure is bound to the GUID (the protocol was
  ///         not seen by the analysis, or its structure was deleted)
  virtual bool get_protocol_struct(
        qstring *out,
        const uefi_guid_t &guid) const = 0;

  /// Bind a structure to a protocol, replacing the structure found or
  /// synthesized by the analysis. Takes effect at the next analysis
  /// (analyze(), analyze_module()): the interfaces and the protocol
  /// pointers are typed with it, the calls through its members are
  /// recorded under it.
  /// \param guid         the protocol GUID
  /// \param struct_name  a structure of the local types or of the type
  ///                     libraries; nullptr or empty to remove the
  ///                     binding, so that the analysis finds or
  ///                     synthesizes the structure again
  /// \return false if the GUID is zero or the structure does not exist
  virtual bool set_protocol_struct(
        const uefi_guid_t &guid,
        const char *struct_name) = 0;

  /// Get the offset of a member of a structure, for the member
  /// functions below.
  /// \param[out] out          receives the byte offset
  /// \param      struct_name  structure name (`EFI_PCD_PROTOCOL`)
  /// \param      member       member name (`GetBool`)
  /// \return true on success
  virtual bool get_member_offset(
        uint64 *out,
        const char *struct_name,
        const char *member) const = 0;

  /// Retrieve the recorded calls through a protocol member.
  /// \param[out] out          receives the call addresses
  /// \param      struct_name  structure name
  /// \param      offset       byte offset of the member
  virtual void get_member_calls(
        eavec_t *out,
        const char *struct_name,
        uint64 offset) const = 0;

  /// Enumerate the functions implementing a protocol member: the
  /// pointers held by the installed interfaces, and the functions stored
  /// into the member at run time.
  /// \param v            the visitor
  /// \param struct_name  structure name
  /// \param offset       byte offset of the member
  /// \return the value returned by the visitor that stopped the
  ///         enumeration, or 0
  virtual int for_each_member_impl(
        const uefi_member_impl_visitor_t &v,
        const char *struct_name,
        uint64 offset) const = 0;

  //@}

  /// \name GUIDs
  /// The GUID database: cfg/uefi_guids.json and cfg/uefi_guids.csv.
  //@{

  /// Get the name of a GUID.
  /// \param[out] out   receives the name (`EfiPcdProtocolGuid`)
  /// \param      guid  the GUID
  /// \return false if the GUID is not in the database
  virtual bool get_guid_name(qstring *out, const uefi_guid_t &guid) const = 0;

  /// Find a GUID by name.
  /// \param[out] out   receives the GUID
  /// \param      name  the name (`EfiPcdProtocolGuid`)
  /// \return false if the name is not in the database
  virtual bool find_guid(uefi_guid_t *out, const char *name) const = 0;

  /// Read a GUID from the database bytes.
  /// \param[out] out  receives the GUID
  /// \param      ea   address of the GUID (an EFI_GUID structure)
  /// \return false if the bytes are not loaded
  virtual bool read_guid(uefi_guid_t *out, ea_t ea) const = 0;

  //@}

  /// \name Helpers
  /// Copy the results into containers. These functions are inline: they
  /// are compiled with your own definitions of the result structures.
  //@{

  /// Retrieve a module.
  /// \param[out] out          receives the module
  /// \param      module_index module index
  /// \return false if there is no such module
  bool get_module(uefi_module_t *out, int module_index) const
  {
    if ( module_index < 0 )
      return false;
    int cur = 0;
    auto find = [&](const uefi_module_t &m)
    {
      if ( cur++ != module_index )
        return 0;
      *out = m;
      return 1;
    };
    return for_each_module(find) != 0;
  }

  /// Retrieve all modules.
  /// \param[out] out  receives the modules
  void get_modules(uefi_module_vec_t *out) const
  {
    out->clear();
    for_each_module([out](const uefi_module_t &x)
    {
      out->push_back(x);
      return 0;
    });
  }

  /// Retrieve the protocol events found by the analysis.
  /// \param[out] out  receives the events
  void get_protocols(uefi_protocol_vec_t *out) const
  {
    out->clear();
    for_each_protocol([out](const uefi_protocol_t &x)
    {
      out->push_back(x);
      return 0;
    });
  }

  /// Retrieve the installed protocol interfaces.
  /// \param[out] out  receives the interfaces
  void get_interfaces(uefi_interface_vec_t *out) const
  {
    out->clear();
    for_each_interface([out](const uefi_interface_t &x)
    {
      out->push_back(x);
      return 0;
    });
  }

  /// Retrieve the functions implementing a protocol member, see
  /// for_each_member_impl().
  /// \param[out] out          receives the implementations
  /// \param      struct_name  structure name
  /// \param      offset       byte offset of the member
  void get_member_impls(
        uefi_member_impl_vec_t *out,
        const char *struct_name,
        uint64 offset) const
  {
    out->clear();
    for_each_member_impl(
        [out](const uefi_member_impl_t &x)
        {
          out->push_back(x);
          return 0;
        },
        struct_name,
        offset);
  }

  //@}
};

//-------------------------------------------------------------------------
/// Retrieve the UEFI services.
///
/// The returned instance is shared, and must not be deleted.
/// This function returns `nullptr` when:
///
/// * the current database is not a UEFI one (a PE/TE image, or a
///   firmware image loaded by the UEFI firmware loader)
/// * the UEFI plugin is not available for the current processor, or
///   it is disabled in uefi.cfg
/// * the UEFI plugin is older than this header, or no longer supports it
///   (after an incompatible change of the API)
///
/// \return the services instance, or nullptr
inline uefi_svc_t *get_uefi_svc()
{
  uefi_svc_t *svc = uefi_svc_req_t().perform();
  // a plugin older than this header lacks some of the methods of uefi_svc_t
  if ( svc != nullptr && svc->get_version() < UEFI_API_VERSION )
    return nullptr;
  return svc;
}

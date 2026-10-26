/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef LICENSE_HPP
#define LICENSE_HPP

#include <pro.h>
#include <license_seam.hpp>

/*! \file license.hpp

  \brief Query and control the active IDA license

  A license is usable while its activation period is in effect.
  A floating license must in addition be held by this IDA instance:
  a borrowed license is usable until the end of the borrow period,
  a license checked out from a license server for as long as the
  server connection (or the grace period after losing it) lasts.

  Add-ons are identified by their product code, e.g. "HEXX64",
  "HEXARM64", "LUMINA", "TEAMS". Each add-on has its own activation
  period; an add-on is reported as valid only if the current time is
  within that period.

  Features are free-form strings attached to the license.

  Licenses come from a license source: a license file or a license
  server. The source, and which of its licenses is active, can be
  changed at run time. A floating license can also be borrowed for
  offline use and returned afterwards.
*/

//-------------------------------------------------------------------------
/// \cond

/// Split a packed list of strings into a vector.
/// \param out output vector
/// \param buf packed list
/// \param size number of bytes in the packed list
/// \return number of collected strings

inline size_t unpack_str_list(qstrvec_t *out, const char *buf, uint64 size)
{
  out->qclear();
  for ( const char *p = buf, *end = buf + size; p < end; p += strlen(p) + 1 )
    out->push_back(p);
  return out->size();
}


/// Get the product codes of all currently usable add-ons of the active license.
/// \param out output vector
/// \return number of collected add-ons; 0 if there is no usable license

inline size_t get_valid_add_ons(qstrvec_t *out)
{
  qstring buf;
  uint64 size = get_valid_add_ons_buf(nullptr, 0);
  if ( size > 0 )
  {
    buf.resize(size);
    // the list may have grown since the sizing call: never walk past buf
    size = qmin(size, get_valid_add_ons_buf(buf.begin(), size));
  }
  return unpack_str_list(out, buf.c_str(), size);
}


/// Get the features of the active license.
/// \param out output vector
/// \return number of collected features; 0 if there is no usable license

inline size_t get_valid_features(qstrvec_t *out)
{
  qstring buf;
  uint64 size = get_valid_features_buf(nullptr, 0);
  if ( size > 0 )
  {
    buf.resize(size);
    // the list may have grown since the sizing call: never walk past buf
    size = qmin(size, get_valid_features_buf(buf.begin(), size));
  }
  return unpack_str_list(out, buf.c_str(), size);
}


/// Get the ID of the active license, in the "XX-XXXX-XXXX-XX" form.
/// \param out output buffer
/// \return false if there is no license

inline bool get_license_id(qstring *out)
{
  uint64 size = get_license_id_buf(nullptr, 0);
  if ( size == 0 )
    return false;
  out->resize(size - 1);
  get_license_id_buf(out->begin(), size);
  // the id may have changed since the sizing call: trust the stored string
  out->resize(strlen(out->c_str()));
  return true;
}


/// Get the IDs of all licenses provided by the active license source.
/// \param out output vector
/// \return number of collected IDs; 0 if there is no license source

inline size_t get_license_ids(qstrvec_t *out)
{
  qstring buf;
  uint64 size = get_license_ids_buf(nullptr, 0);
  if ( size > 0 )
  {
    buf.resize(size);
    // the list may have grown since the sizing call: never walk past buf
    size = qmin(size, get_license_ids_buf(buf.begin(), size));
  }
  return unpack_str_list(out, buf.c_str(), size);
}

/// \endcond

//-------------------------------------------------------------------------
/// A License object lets a plugin check what the active license covers
/// and change which license IDA uses.
/// The object holds no state of its own: each query reports the current
/// state of the license.
/// An empty id() means there is no active license.
/// valid() tells whether the license is usable.
///
/// The queries are const. The remaining methods act on the license of the
/// whole IDA instance, not on the object they are called on: they replace
/// the license source or the active license for the entire application,
/// including the kernel and all other plugins.
class License
{
public:
  //-----------------------------------------------------------------------
  // Queries


  /// Check if there is a usable active license.
  /// A floating license is usable only while this IDA instance holds it
  /// (a checked out seat or an unexpired borrow).
  /// \return false if there is no license
  ///         or its activation period is not in effect
  bool valid() const { return is_license_valid(); }

  /// Check if the active license is usable, contains the given add-on,
  /// and the add-on activation period is in effect.
  /// A floating license is usable only while this IDA instance holds it
  /// (a checked out seat or an unexpired borrow).
  /// \param name add-on product code, e.g. "HEXX64", "LUMINA" (case sensitive)
  /// \return false if there is no usable license, the add-on is not part
  ///         of the license, or its activation period has not started
  ///         or has expired
  bool has_add_on(const char *name) const { return has_valid_add_on(name); }

  /// Get the product codes of all currently usable add-ons of the active
  /// license.
  /// A floating license is usable only while this IDA instance holds it
  /// (a checked out seat or an unexpired borrow).
  /// \return empty if there is no usable license
  qstrvec_t add_ons() const
  {
    qstrvec_t out;
    get_valid_add_ons(&out);
    return out;
  }

  /// Check if the active license is usable and includes the given feature.
  /// A floating license is usable only while this IDA instance holds it
  /// (a checked out seat or an unexpired borrow).
  /// \param name feature name (case sensitive)
  /// \return false if there is no usable license
  ///         or the feature is not part of the license
  bool has_feature(const char *name) const { return has_valid_feature(name); }

  /// Get the features of the active license.
  /// A floating license is usable only while this IDA instance holds it
  /// (a checked out seat or an unexpired borrow).
  /// \return empty if there is no usable license
  qstrvec_t features() const
  {
    qstrvec_t out;
    get_valid_features(&out);
    return out;
  }

  /// Get the ID of the active license, in the "XX-XXXX-XXXX-XX" form.
  /// \return empty if there is no license
  qstring id() const
  {
    qstring out;
    get_license_id(&out);
    return out;
  }

  /// Get the IDs of all licenses provided by the active license source.
  /// A license file may contain several licenses; for a license server,
  /// the licenses listed when the seat was acquired are reported.
  /// The list is not filtered by validity.
  /// \return empty if there is no license source
  qstrvec_t source_ids() const
  {
    qstrvec_t out;
    get_license_ids(&out);
    return out;
  }

  /// Check if a decompiler is available for the current database.
  /// \return false if no database is open, there is no decompiler for it,
  ///         the decompiler add-on is not part of the license, or its
  ///         activation period has not started or has expired
  bool decompiler_available() const { return is_decompiler_available(); }

  /// Get the product of the active license, e.g. "IDAPRO", "IDAHOME".
  /// \return empty if there is no license
  qstring product() const { return qstring(get_license_product()); }

  /// Get the edition of the active license, e.g. "ida-pro", "ida-home-arm".
  /// The value is informational, for display purposes; use has_add_on()
  /// and has_feature() to check what the license covers.
  /// \return empty if there is no license
  qstring edition() const { return qstring(get_license_edition()); }

  /// Get the description of the active license.
  /// \return empty if there is no license or the license has no description
  qstring description() const { return qstring(get_license_description()); }

  /// Get the product version the active license is bound to,
  /// as major*100+minor (e.g. 904 for 9.4).
  /// \return 0 if there is no license or the license is not bound to a version
  int32 product_version() const { return get_license_product_version(); }

  /// Get the start of the activation period of the active license.
  /// \return seconds since the Epoch (UTC); 0 if there is no license
  int64 start() const { return get_license_start(); }

  /// Get the end of the activation period of the active license.
  /// The license remains usable during a grace period after this time.
  /// A borrowed floating license may stop being usable earlier,
  /// at the end of the borrow period.
  /// \return seconds since the Epoch (UTC);
  ///         0 if there is no license or the license never expires
  int64 end() const { return get_license_end(); }

  /// Get the time the active license was issued.
  /// \return seconds since the Epoch (UTC); 0 if there is no license
  int64 issued_on() const { return get_license_issued_on(); }

  /// Get the end of the activation period of an add-on of the active license.
  /// The add-on remains usable during a grace period after this time.
  /// \param name add-on product code, e.g. "HEXX64", "LUMINA" (case sensitive)
  /// \return seconds since the Epoch (UTC); 0 if there is no license,
  ///         the add-on is not part of it, or the add-on never expires
  int64 add_on_end(const char *name) const { return get_add_on_end(name); }

  /// Check if the active license is a floating license, served by a license
  /// server, rather than a named license.
  /// \return false if there is no license
  bool floating() const { return is_floating_license(); }

  //-----------------------------------------------------------------------
  // Selecting the license source and holding a floating license.
  // These methods change the license used by the whole IDA instance.

  /// Use a license file as the license source and activate its license
  /// for this product. The choice is not saved as the preferred license.
  /// \param path path of the license file
  /// \return false if the file does not exist, is not a valid license file,
  ///         or holds no usable license for this product
  bool set_file(const char *path) { return set_license_file(path); }

  /// Use a license server as the license source and check out a license
  /// for this product. The choice is not saved as the preferred license.
  /// \param host server host name or address
  /// \param port server port; 0 selects the default port
  /// \param use_tls connect over TLS
  /// \return false if the server cannot be reached
  ///         or no license could be checked out from it
  bool set_server(const char *host, int port, bool use_tls)
  {
    return set_license_server(host, port, use_tls);
  }

  /// Activate the given license of the current license source.
  /// With a license server, the current seat is checked in first.
  /// \param license_id license ID in the "XX-XXXX-XXXX-XX" form
  /// \return false if the ID is malformed, the current source does not
  ///         hold the license, or it could not be checked out
  bool checkout(const char *license_id)
  {
    return checkout_license(license_id);
  }

  /// Check the current seat back in to the license server.
  /// IDA keeps running without a license until one is activated again.
  /// \return false if the license source is a file, no seat is held,
  ///         or the current license is borrowed
  bool checkin() { return checkin_license(); }

  /// Borrow the current license from the license server for offline use.
  /// \param until end of the borrow period, in seconds since the Epoch (UTC)
  /// \return false if the license source is a file, no license is checked
  ///         out, the end time is not in the future, or the server refused
  ///         the borrow
  bool borrow(int64 until) { return borrow_license(until); }

  /// Return the borrowed license to the license server
  /// and check out a seat of it instead.
  /// \return false if the current license is not borrowed
  ///         or the server cannot be reached
  bool return_borrowed() { return return_borrowed_license(); }
};

#endif // LICENSE_HPP

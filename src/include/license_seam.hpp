/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef LICENSE_SEAM_HPP
#define LICENSE_SEAM_HPP

/*! \file license_seam.hpp

  \brief Query and control the active IDA license: low-level entry points

  These functions permit plugins to check what the active license
  covers, and to select where licenses come from, without exposing
  the license internals. Use the License class in license.hpp for
  license queries.

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

  Only fixed-width scalars, bool and const char * cross this boundary,
  so a caller never has to share a C++ type with IDA. license.hpp puts
  the C++ view on top of these functions; use that one from C++.

  A function that reports a list of strings fills a caller-provided
  buffer with the strings, one after another, each ending with a zero
  byte, and returns the number of bytes the complete list needs.
  Only strings that fit entirely are stored, so call the function with
  a zero size, then again with a buffer of the returned size.
*/

//-------------------------------------------------------------------------
//      F U N C T I O N S   F O R   T H E   K E R N E L
//-------------------------------------------------------------------------
// These functions are internal to IDA and may change without notice.

/// \cond

/// Check if there is a usable active license.
/// A floating license is usable only while this IDA instance holds it
/// (a checked out seat or an unexpired borrow).
/// \return false if there is no license
///         or its activation period is not in effect

idaman bool ida_export is_license_valid();


/// Check if the active license is usable, contains the given add-on,
/// and the add-on activation period is in effect.
/// A floating license is usable only while this IDA instance holds it
/// (a checked out seat or an unexpired borrow).
/// \param add_on add-on product code, e.g. "HEXX64", "LUMINA" (case sensitive)
/// \return false if there is no usable license, the add-on is not part
///         of the license, or its activation period has not started or has expired

idaman bool ida_export has_valid_add_on(const char *add_on);


/// Get the product codes of all currently usable add-ons of the active license.
/// A floating license is usable only while this IDA instance holds it
/// (a checked out seat or an unexpired borrow).
/// \param buf output buffer for the packed list
/// \param bufsize size of the output buffer, in bytes
/// \return number of bytes the complete list needs;
///         0 if there is no usable license

idaman uint64 ida_export get_valid_add_ons_buf(char *buf, uint64 bufsize);


/// Check if the active license is usable and includes the given feature.
/// A floating license is usable only while this IDA instance holds it
/// (a checked out seat or an unexpired borrow).
/// \param feature feature name (case sensitive)
/// \return false if there is no usable license
///         or the feature is not part of the license

idaman bool ida_export has_valid_feature(const char *feature);


/// Get the features of the active license.
/// A floating license is usable only while this IDA instance holds it
/// (a checked out seat or an unexpired borrow).
/// \param buf output buffer for the packed list
/// \param bufsize size of the output buffer, in bytes
/// \return number of bytes the complete list needs;
///         0 if there is no usable license

idaman uint64 ida_export get_valid_features_buf(char *buf, uint64 bufsize);


/// Get the ID of the active license, in the "XX-XXXX-XXXX-XX" form.
/// The ID is stored as a zero terminated string, truncated if it does not fit.
/// \param buf output buffer for the ID
/// \param bufsize size of the output buffer, in bytes
/// \return number of bytes the ID needs, including the terminating zero byte;
///         0 if there is no license

idaman uint64 ida_export get_license_id_buf(char *buf, uint64 bufsize);


/// Get the IDs of all licenses provided by the active license source.
/// A license file may contain several licenses; for a license server,
/// the licenses listed when the seat was acquired are reported.
/// The list is not filtered by validity.
/// \param buf output buffer for the packed list
/// \param bufsize size of the output buffer, in bytes
/// \return number of bytes the complete list needs;
///         0 if there is no license source

idaman uint64 ida_export get_license_ids_buf(char *buf, uint64 bufsize);


/// Get the product of the active license, e.g. "IDAPRO", "IDAHOME".
/// \return nullptr if there is no license

idaman const char *ida_export get_license_product();


/// Get the edition of the active license, e.g. "ida-pro", "ida-home-arm".
/// The value is informational, for display purposes; use has_valid_add_on()
/// and has_valid_feature() to check what the license covers.
/// \return nullptr if there is no license

idaman const char *ida_export get_license_edition();


/// Check if the active license is a floating license, served by a license
/// server, rather than a named license.
/// \return false if there is no license

idaman bool ida_export is_floating_license();


/// Get the product version the active license is bound to,
/// as major*100+minor (e.g. 904 for 9.4).
/// \return 0 if there is no license or the license is not bound to a version

idaman int32 ida_export get_license_product_version();


/// Get the description of the active license.
/// The returned string remains valid as long as the active license
/// does not change.
/// \return nullptr if there is no license;
///         an empty string if the license has no description

idaman const char *ida_export get_license_description();


/// Get the time the active license was issued.
/// \return seconds since the Epoch (UTC); 0 if there is no license

idaman int64 ida_export get_license_issued_on();


/// Get the start of the activation period of the active license.
/// \return seconds since the Epoch (UTC); 0 if there is no license

idaman int64 ida_export get_license_start();


/// Get the end of the activation period of the active license.
/// The license remains usable during a grace period after this time.
/// A borrowed floating license may stop being usable earlier,
/// at the end of the borrow period.
/// \return seconds since the Epoch (UTC);
///         0 if there is no license or the license never expires

idaman int64 ida_export get_license_end();


/// Get the end of the activation period of an add-on of the active license.
/// The add-on remains usable during a grace period after this time.
/// \param name add-on product code, e.g. "HEXX64", "LUMINA" (case sensitive)
/// \return seconds since the Epoch (UTC); 0 if there is no license,
///         the add-on is not part of it, or the add-on never expires

idaman int64 ida_export get_add_on_end(const char *name);


/// Check if a decompiler is available for the current database.
/// \return false if no database is open, there is no decompiler for it,
///         the decompiler add-on is not part of the license, or its
///         activation period has not started or has expired

idaman bool ida_export is_decompiler_available();


/// Use a license file as the license source and activate its license
/// for this product. The choice is not saved as the preferred license.
/// \param path path of the license file
/// \return false if the file does not exist, is not a valid license file,
///         or holds no usable license for this product

idaman bool ida_export set_license_file(const char *path);


/// Use a license server as the license source and check out a license
/// for this product. The choice is not saved as the preferred license.
/// \param host server host name or address
/// \param port server port; 0 selects the default port
/// \param use_tls connect over TLS
/// \return false if the server cannot be reached
///         or no license could be checked out from it

idaman bool ida_export set_license_server(
        const char *host,
        int port,
        bool use_tls);


/// Activate the given license of the current license source.
/// With a license server, the current seat is checked in first.
/// \param license_id license ID in the "XX-XXXX-XXXX-XX" form
/// \return false if the ID is malformed, the current source does not
///         hold the license, or it could not be checked out

idaman bool ida_export checkout_license(const char *license_id);


/// Check the current seat back in to the license server.
/// \return false if the license source is a file, no seat is held,
///         or the current license is borrowed

idaman bool ida_export checkin_license();


/// Borrow the current license from the license server for offline use.
/// \param until end of the borrow period, in seconds since the Epoch (UTC)
/// \return false if the license source is a file, no license is checked out,
///         the end time is not in the future, or the server refused the borrow

idaman bool ida_export borrow_license(int64 until);


/// Return the borrowed license to the license server
/// and check out a seat of it instead.
/// \return false if the current license is not borrowed
///         or the server cannot be reached

idaman bool ida_export return_borrowed_license();

/// \endcond

#endif // LICENSE_SEAM_HPP

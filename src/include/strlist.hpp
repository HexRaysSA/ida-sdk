/*
 *      The Interactive Disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _STRLIST_HPP
#define _STRLIST_HPP

/*! \file strlist.hpp

  \brief Functions that deal with the string list

  While the kernel keeps the string list, it does not update it.
  The string list is not used by the kernel because
  keeping it up-to-date would slow down IDA without any benefit.
  If the string list is not cleared using clear_strlist(), the list will be
  saved to the database and restored on the next startup.

  The users of this list should call build_strlist() if they need an
  up-to-date version.
*/

/// Structure to keep string list parameters
struct strwinsetup_t
{
  bytevec_t strtypes; // set of allowed string types
  sval_t minlen = -1;
  uchar display_only_existing_strings = 0;
  uchar only_7bit = 1;
  uchar ignore_heads = 0;
};


/// Information about one string from the string list
struct string_info_t
{
  ea_t ea;
  int length = 0; // in octets
  int type = 0;
  string_info_t(ea_t _ea=BADADDR) : ea(_ea) {}
  bool operator<(const string_info_t &r) const { return ea < r.ea; }
};
DECLARE_TYPE_AS_MOVABLE(string_info_t);

/// Same as string_info_t, plus the text of a string that does not exist in
/// the bytes and was reported by a provider: the decompiler reconstructing it
/// from a ctree, a plugin recovering it from immediates, ... The text is set
/// for every such string, see #STRTYPE_SYNTH.
struct string_info_ex_t : public string_info_t
{
  qstring synthetic_string; ///< the text of a synthetic string
  string_info_ex_t(ea_t _ea=BADADDR) : string_info_t(_ea) {}
};
DECLARE_TYPE_AS_MOVABLE(string_info_ex_t);


/// Get the static string list options

idaman const strwinsetup_t *ida_export get_strlist_options();


/// Rebuild the string list.

idaman void ida_export build_strlist();


/// Clear the string list.

idaman void ida_export clear_strlist();


/// Get number of elements in the string list.
/// The list will be loaded from the database (if saved) or
/// built from scratch.

idaman size_t ida_export get_strlist_qty(void);


/// Get nth element of the string list (n=0..get_strlist_qty()-1)

idaman bool ida_export get_strlist_item(string_info_t *si, size_t n);


/// Get nth element of the string list, including the text of a synthetic
/// string (see #STRTYPE_SYNTH).

idaman bool ida_export get_strlist_item_ex(string_info_ex_t *si, size_t n);


/*! \defgroup synth_strings Synthetic strings

  \brief Strings that the byte scan cannot find

  A string the code builds from immediates, or one that only the decompiler
  can see, does not exist in the bytes: no scan of the database finds it.
  Such strings are reported by a provider - the decompiler, or a plugin -
  and stored in the database with synth_string_provider_t::set() (or
  synth_string_set()). The string list and the comments of the
  disassembly are views of that store, so a string stays there until its
  provider says otherwise, also when the list is rebuilt or the database is
  reopened.

  A provider registers itself to give its strings a name in the "Type"
  column of the Strings window. The strings themselves do not depend on it:
  they are in the database and are listed even when nothing is registered
  for them.
*/
///@{

/// \defgroup SYNTHSTR_PROVIDER_ Synthetic string provider ids
/// The id of a provider is stored in the database with every string it
/// stores, and the string list shows it in the second byte of the string
/// type (see #STRTYPE_SYNTH). So it must be the same in every release: a
/// plugin picks one from the custom range, as for #PLFM_.
///@{
#define SYNTHSTR_PROVIDER_NONE       0    ///< no provider: not a valid id to
                                          ///< store or register strings with
#define SYNTHSTR_PROVIDER_DECOMPILER 1    ///< the decompiler
#define SYNTHSTR_PROVIDER_SWIFT      2    ///< Swift string literals
#define SYNTHSTR_PROVIDER_CUSTOM     0x80 ///< start of the custom provider ids
///@}


/// \defgroup SYNTHSTR_ Synthetic string flags
/// What a provider says about how its strings at an address are shown
///@{
#define SYNTHSTR_NOCMT 0x0001 ///< list them in the Strings window, but do not
                              ///< show them as a comment in the listing.
                              ///< Of the strings that may be shown there,
                              ///< the listing shows one: the first of the
                              ///< provider with the lowest id
#define SYNTHSTR_REPEATABLE 0x0002 ///< like a repeatable comment: the listing
                              ///< also shows them at the instructions that
                              ///< refer to the address (or into the item
                              ///< at it), as it does for a string literal.
                              ///< Of the repeatable strings at an address,
                              ///< the references show the first one of the
                              ///< provider with the lowest id
///@}

/// A stored synthetic string
struct synth_string_t
{
  ea_t ea = BADADDR;      ///< the address it was stored at
  qstring text;           ///< the string itself
  uint32 flags = 0;       ///< \ref SYNTHSTR_
  uchar provider = SYNTHSTR_PROVIDER_NONE; ///< \ref SYNTHSTR_PROVIDER_
};
DECLARE_TYPE_AS_MOVABLE(synth_string_t);
typedef qvector<synth_string_t> synth_strings_t; ///< synthetic strings


/// Store what the provider PROVIDER_ID knows about EA.
/// TEXTS replaces everything that provider said about that address before;
/// an empty TEXTS forgets it. Empty texts are ignored, a text repeated in
/// TEXTS is stored once. Storing what is already stored changes nothing in
/// the database.
/// A provider does not have to be registered to store strings; registration
/// only names them in the Strings window.
/// One address holds about one kilobyte of text, shared by all providers.
/// What does not fit is not lost entirely: TEXTS are stored in order, the
/// first one that does not fit is cut at a character boundary, and the ones
/// after it are dropped. What the other providers stored is kept intact.
/// \param flags  \ref SYNTHSTR_
/// \return false if TEXTS were cut or dropped, or if nothing could be stored
///         (PROVIDER_ID is #SYNTHSTR_PROVIDER_NONE, EA is BADADDR)

idaman bool ida_export synth_string_set(
        uchar provider_id,
        ea_t ea,
        const qstrvec_t &texts,
        uint32 flags=0);


/// Forget everything the provider PROVIDER_ID said in [ea1, ea2).

idaman void ida_export synth_string_forget(
        uchar provider_id,
        ea_t ea1,
        ea_t ea2);


/// Get the stored strings of every provider at EA.
/// OUT may be nullptr to only ask whether something is stored there.
/// \return false if there are none

idaman bool ida_export synth_string_get(synth_strings_t *out, ea_t ea);


/// Get the stored strings of every provider in [ea1, ea2).

idaman void ida_export synth_string_get_range(
        synth_strings_t *out,
        ea_t ea1,
        ea_t ea2);


/// Register a synthetic string provider for the current database.
/// NAME is copied; it is what the Strings window shows in the "Type" column
/// for the strings of ID. The registration ends with the database.
/// \return false if ID is #SYNTHSTR_PROVIDER_NONE or another provider is
///         registered with it

idaman bool ida_export synth_string_register_provider(
        uchar id,
        const char *name);


/// Unregister the provider ID. The strings it stored stay in the database.

idaman bool ida_export synth_string_unregister_provider(uchar id);


/// The name the provider ID registered with, or nullptr.

idaman const char *ida_export synth_string_provider_name(uchar id);


/// A provider of synthetic strings, for convenience: its id and its name.
/// A plain value, all it does is call the functions above; creating or
/// destroying one registers nothing and changes nothing in the database.
struct synth_string_provider_t
{
  qstring name;           ///< the "Type" column of the Strings window
  uchar id;               ///< \ref SYNTHSTR_PROVIDER_, never changes

  synth_string_provider_t(uchar _id, const char *_name)
    : name(_name), id(_id) {}

  /// Name the strings of this provider in the current database,
  /// see synth_string_register_provider()
  bool register_provider() const
    { return synth_string_register_provider(id, name.c_str()); }
  /// see synth_string_unregister_provider()
  bool unregister_provider() const
    { return synth_string_unregister_provider(id); }
  /// Replace what this provider says about EA, see synth_string_set().
  /// \return false if the texts did not fit in full
  bool set(ea_t ea, const qstrvec_t &texts, uint32 flags=0) const
    { return synth_string_set(id, ea, texts, flags); }
  /// What this provider said about EA, as it was passed to set().
  /// The strings of all providers, with their flags, are returned by
  /// synth_string_get().
  /// \return false if it said nothing there
  bool get(qstrvec_t *out, ea_t ea) const
  {
    synth_strings_t all;
    synth_string_get(&all, ea);
    out->clear();
    for ( const synth_string_t &s : all )
    {
      if ( s.provider == id )
        out->push_back(s.text);
    }
    return !out->empty();
  }
  /// Forget what this provider said in [ea1, ea2)
  void forget(ea_t ea1, ea_t ea2) const
    { synth_string_forget(id, ea1, ea2); }
};

///@}

#endif // _STRLIST_HPP

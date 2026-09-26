/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _LINES_HPP
#define _LINES_HPP

#include <ida.hpp>

/*! \file lines.hpp

  \brief High level functions that deal with the generation
  of the disassembled text lines.

  This file also contains definitions for the syntax highlighting.

  Finally there are functions that deal with anterior/posterior
  user-defined lines.
*/

struct range_t;
class idc_value_t;
class place_t;             // fwd (kernwin.hpp) -- listing_line_t uses it by pointer
struct lines_gen_range_t;  // fwd (kernwin.hpp) -- lines_gen_range_vec_t / export_listing_t use it
typedef qvector<lines_gen_range_t> lines_gen_range_vec_t;
struct dual_text_options_t;
struct simpleline_t;       // fwd (kernwin.hpp) -- export_listing_t::add_pseudocode
typedef qvector<simpleline_t> strvec_t;

//---------------------------------------------------------------------------
//      C O L O R   D E F I N I T I O N S
//---------------------------------------------------------------------------

/// \defgroup color_def Color definitions
///
/// Here we describe the structure of embedded escape sequences used to
/// implement syntax highlighting.
///
/// The processor module should insert appropriate escape characters into the
/// output lines as necessary.
///
/// A typical color sequence looks like this:
///
/// #COLOR_ON COLOR_xxx text #COLOR_OFF COLOR_xxx
///
/// The first 2 items turn color 'xxx' on, then the text follows,
/// and the color is turned off by two last items.
/// COLOR_INV and COLOR_ADDR does not have the closing COLOR_OFF part.
///
/// All non-space symbols must have a color code.
///
/// Color sequences may be nested.
///
/// Each instruction operand must have the COLOR_OPNDx color.
/// For example: COLOR_OPND1. These color codes are used by IDA to determine
/// the operand boundaries in the listing.
///
/// Example 1:
///   lwz       r28, FlexCan_rec.MB_ID(r3)
/// With color codes (multiple lines just for the convenience of reading):
///   [ON INSN]lwz[OFF INSN]       [ON OPND1][ON REG]r28[OFF REG][OFF OPND1]
///   [ON SYMBOL],[OFF SYMBOL] [ON OPND2][ON DNAME]FlexCan_rec.MB_ID[OFF DNAME]
///   [ON SYMBOL]([OFF SYMBOL][ON REG]r3[OFF REG][ON SYMBOL])[OFF SYMBOL][OFF OPND2]
///
/// Example 2:
///   bne       loc_A0DA8C
/// With color codes:
///   [ON INSN]bne[OFF INSN]       [ON OPND2][ON CODNAME]
///   [ON ADDR]0000000000A0DA8Cloc_A0DA8C[OFF CODNAME][OFF OPND2]
///
/// Normally you should not construct the escape sequences manually.
/// Use the helper functions like out_symbol(), out_long() or similar.
///@{

/// \defgroup color_esc Color escape characters
/// Initiate/Terminate a color tag
///@{
#define COLOR_ON        '\1'     ///< Escape character (ON).
                                 ///< Followed by a color code (::color_t).
#define COLOR_OFF       '\2'     ///< Escape character (OFF).
                                 ///< Followed by a color code (::color_t).
#define COLOR_ESC       '\3'     ///< Escape character (Quote next character).
                                 ///< This is needed to output '\1' and '\2'
                                 ///< characters.
#define COLOR_INV       '\4'     ///< Escape character (Inverse foreground and background colors).
                                 ///< This escape character has no corresponding #COLOR_OFF.
                                 ///< Its action continues until the next #COLOR_INV or end of line.

#define SCOLOR_ON       "\1"     ///< Escape character (ON)
#define SCOLOR_OFF      "\2"     ///< Escape character (OFF)
#define SCOLOR_ESC      "\3"     ///< Escape character (Quote next character)
#define SCOLOR_INV      "\4"     ///< Escape character (Inverse colors)

/// Is the given char a color escape character?
inline THREAD_SAFE bool requires_color_esc(char c) { return c >= COLOR_ON && c <= COLOR_INV; }
///@}

typedef uchar color_t;           ///< color tag - see \ref COLOR_
/// \defgroup COLOR_ Color tags
/// Specify a color for a syntax item
///@{
const color_t
  COLOR_DEFAULT  = 0x01,         ///< Default
  COLOR_REGCMT   = 0x02,         ///< Regular comment
  COLOR_RPTCMT   = 0x03,         ///< Repeatable comment (comment defined somewhere else)
  COLOR_AUTOCMT  = 0x04,         ///< Automatic comment
  COLOR_INSN     = 0x05,         ///< Instruction
  COLOR_DATNAME  = 0x06,         ///< Dummy Data Name
  COLOR_DNAME    = 0x07,         ///< Regular Data Name
  COLOR_DEMNAME  = 0x08,         ///< Demangled Name
  COLOR_SYMBOL   = 0x09,         ///< Punctuation
  COLOR_CHAR     = 0x0A,         ///< Char constant in instruction
  COLOR_STRING   = 0x0B,         ///< String constant in instruction
  COLOR_NUMBER   = 0x0C,         ///< Numeric constant in instruction
  COLOR_VOIDOP   = 0x0D,         ///< Void operand
  COLOR_CREF     = 0x0E,         ///< Code reference
  COLOR_DREF     = 0x0F,         ///< Data reference
  COLOR_CREFTAIL = 0x10,         ///< Code reference to tail byte
  COLOR_DREFTAIL = 0x11,         ///< Data reference to tail byte
  COLOR_ERROR    = 0x12,         ///< Error or problem
  COLOR_PREFIX   = 0x13,         ///< Line prefix
  COLOR_BINPREF  = 0x14,         ///< Binary line prefix bytes
  COLOR_EXTRA    = 0x15,         ///< Extra line
  COLOR_ALTOP    = 0x16,         ///< Alternative operand
  COLOR_HIDNAME  = 0x17,         ///< Hidden name
  COLOR_LIBNAME  = 0x18,         ///< Library function name
  COLOR_LOCNAME  = 0x19,         ///< Local variable name
  COLOR_CODNAME  = 0x1A,         ///< Dummy code name
  COLOR_ASMDIR   = 0x1B,         ///< Assembler directive
  COLOR_MACRO    = 0x1C,         ///< Macro
  COLOR_DSTR     = 0x1D,         ///< String constant in data directive
  COLOR_DCHAR    = 0x1E,         ///< Char constant in data directive
  COLOR_DNUM     = 0x1F,         ///< Numeric constant in data directive
  COLOR_KEYWORD  = 0x20,         ///< Keywords
  COLOR_REG      = 0x21,         ///< Register name
  COLOR_IMPNAME  = 0x22,         ///< Imported name
  COLOR_SEGNAME  = 0x23,         ///< Segment name
  COLOR_UNKNAME  = 0x24,         ///< Dummy unknown name
  COLOR_CNAME    = 0x25,         ///< Regular code name
  COLOR_UNAME    = 0x26,         ///< Regular unknown name
  COLOR_COLLAPSED= 0x27,         ///< Collapsed line
  COLOR_FG_MAX   = 0x28,         ///< Max color number

  // Fictive colors

  COLOR_ADDR     = COLOR_FG_MAX, ///< Hidden address marks.
                                 ///< the address is represented as 16-digit
                                 ///< hex number: 01234567ABCDEF00.
                                 ///< it doesn't have the #COLOR_OFF pair.

  COLOR_OPND1    = COLOR_ADDR+1, ///< Instruction operand 1
  COLOR_OPND2    = COLOR_ADDR+2, ///< Instruction operand 2
  COLOR_OPND3    = COLOR_ADDR+3, ///< Instruction operand 3
  COLOR_OPND4    = COLOR_ADDR+4, ///< Instruction operand 4
  COLOR_OPND5    = COLOR_ADDR+5, ///< Instruction operand 5
  COLOR_OPND6    = COLOR_ADDR+6, ///< Instruction operand 6
  COLOR_OPND7    = COLOR_ADDR+7, ///< Instruction operand 7
  COLOR_OPND8    = COLOR_ADDR+8, ///< Instruction operand 8


  COLOR_RESERVED1= COLOR_ADDR+11,///< This tag is reserved for internal IDA use
  COLOR_LUMINA   = COLOR_ADDR+12,///< Lumina-related, only for the navigation band

  COLOR_ADDR_EXPR = COLOR_ADDR+13,///< Wraps an "address expression" - possibly composed of sub-expressions

  COLOR_SEMSPAN   = COLOR_ADDR+14,///< Semantics-bearing span: groups together a
                                  ///< run of tagged text so it can be looked up
                                  ///< as a single span (like COLOR_ADDR_EXPR)
                                  ///< and says something about what that span
                                  ///< is, all without influencing rendering: no
                                  ///< associated style color key (\ref sck_)
                                  ///< exists. The #COLOR_ON side is followed by
                                  ///< a header, the #COLOR_OFF side by nothing:
                                  ///< #COLOR_ON #COLOR_SEMSPAN <kind> [<payload>] text #COLOR_OFF #COLOR_SEMSPAN
                                  ///< <kind> is a single byte telling what the
                                  ///< span represents: a \ref SCOLOR_ color code
                                  ///< (e.g. #COLOR_CNAME/#COLOR_LOCNAME = a
                                  ///< symbol name), or #COLOR_DEFAULT for "no
                                  ///< specific kind". It is never 0 (that would
                                  ///< terminate the string). Read it with
                                  ///< tag_get_semspan_kind().
                                  ///< <payload> is what <kind> bundles along.
                                  ///< Of *variable size* - empty for every kind
                                  ///< so far, but we reserve the right to grow
                                  ///< it - and never contains a 0 byte. Never
                                  ///< assume a size for the header: step over it
                                  ///< with tag_skipcode(), tag_skipcodes() or
                                  ///< tag_advance().
                                  ///< See tag_semspan().

  COLOR_GROUP     = COLOR_SEMSPAN;///< Old name of ::COLOR_SEMSPAN, kept for
                                  ///< sources written against IDA 9.4.
                                  ///< \deprecated Use ::COLOR_SEMSPAN
///@}

/// Size of a tagged address (see ::COLOR_ADDR)
#define COLOR_ADDR_SIZE (sizeof(ea_t)*2)

/// \defgroup SCOLOR_ Color string constants
/// These definitions are used with the #COLSTR macro
///@{
#define SCOLOR_DEFAULT   "\x01"  ///< Default
#define SCOLOR_REGCMT    "\x02"  ///< Regular comment
#define SCOLOR_RPTCMT    "\x03"  ///< Repeatable comment (defined not here)
#define SCOLOR_AUTOCMT   "\x04"  ///< Automatic comment
#define SCOLOR_INSN      "\x05"  ///< Instruction
#define SCOLOR_DATNAME   "\x06"  ///< Dummy Data Name
#define SCOLOR_DNAME     "\x07"  ///< Regular Data Name
#define SCOLOR_DEMNAME   "\x08"  ///< Demangled Name
#define SCOLOR_SYMBOL    "\x09"  ///< Punctuation
#define SCOLOR_CHAR      "\x0A"  ///< Char constant in instruction
#define SCOLOR_STRING    "\x0B"  ///< String constant in instruction
#define SCOLOR_NUMBER    "\x0C"  ///< Numeric constant in instruction
#define SCOLOR_VOIDOP    "\x0D"  ///< Void operand
#define SCOLOR_CREF      "\x0E"  ///< Code reference
#define SCOLOR_DREF      "\x0F"  ///< Data reference
#define SCOLOR_CREFTAIL  "\x10"  ///< Code reference to tail byte
#define SCOLOR_DREFTAIL  "\x11"  ///< Data reference to tail byte
#define SCOLOR_ERROR     "\x12"  ///< Error or problem
#define SCOLOR_PREFIX    "\x13"  ///< Line prefix
#define SCOLOR_BINPREF   "\x14"  ///< Binary line prefix bytes
#define SCOLOR_EXTRA     "\x15"  ///< Extra line
#define SCOLOR_ALTOP     "\x16"  ///< Alternative operand
#define SCOLOR_HIDNAME   "\x17"  ///< Hidden name
#define SCOLOR_LIBNAME   "\x18"  ///< Library function name
#define SCOLOR_LOCNAME   "\x19"  ///< Local variable name
#define SCOLOR_CODNAME   "\x1A"  ///< Dummy code name
#define SCOLOR_ASMDIR    "\x1B"  ///< Assembler directive
#define SCOLOR_MACRO     "\x1C"  ///< Macro
#define SCOLOR_DSTR      "\x1D"  ///< String constant in data directive
#define SCOLOR_DCHAR     "\x1E"  ///< Char constant in data directive
#define SCOLOR_DNUM      "\x1F"  ///< Numeric constant in data directive
#define SCOLOR_KEYWORD   "\x20"  ///< Keywords
#define SCOLOR_REG       "\x21"  ///< Register name
#define SCOLOR_IMPNAME   "\x22"  ///< Imported name
#define SCOLOR_SEGNAME   "\x23"  ///< Segment name
#define SCOLOR_UNKNAME   "\x24"  ///< Dummy unknown name
#define SCOLOR_CNAME     "\x25"  ///< Regular code name
#define SCOLOR_UNAME     "\x26"  ///< Regular unknown name
#define SCOLOR_COLLAPSED "\x27"  ///< Collapsed line
#define SCOLOR_ADDR      "\x28"  ///< Hidden address mark
#define SCOLOR_OPND1     "\x29"  ///< Instruction operand 1
#define SCOLOR_OPND2     "\x2A"  ///< Instruction operand 2
#define SCOLOR_OPND3     "\x2B"  ///< Instruction operand 3
#define SCOLOR_OPND4     "\x2C"  ///< Instruction operand 4
#define SCOLOR_OPND5     "\x2D"  ///< Instruction operand 5
#define SCOLOR_OPND6     "\x2E"  ///< Instruction operand 6
#define SCOLOR_OPND7     "\x2F"  ///< Instruction operand 7
#define SCOLOR_OPND8     "\x30"  ///< Instruction operand 8
#define SCOLOR_RESERVED1 "\x33"  ///< Reserved for internal IDA use
#define SCOLOR_LUMINA    "\x34"  ///< Lumina-related (navigation band only)
#define SCOLOR_ADDR_EXPR "\x35"  ///< Address expression
#define SCOLOR_SEMSPAN   "\x36"  ///< Semantics-bearing span (see ::COLOR_SEMSPAN)

///@}

//----------------- Line prefix colors --------------------------------------
/// \defgroup COLOR_PFX Line prefix colors
/// Note: line prefix colors are not used in processor modules
///@{
#define COLOR_DEFAULT    0x01   ///< Default
#define COLOR_SELECTED   0x02   ///< Selected
#define COLOR_LIBFUNC    0x03   ///< Library function
#define COLOR_REGFUNC    0x04   ///< Regular function
#define COLOR_CODE       0x05   ///< Single instruction
#define COLOR_DATA       0x06   ///< Data bytes
#define COLOR_UNKNOWN    0x07   ///< Unexplored byte
#define COLOR_EXTERN     0x08   ///< External name definition segment
#define COLOR_CURITEM    0x09   ///< Current item
#define COLOR_CURLINE    0x0A   ///< Current line
#define COLOR_HIDLINE    0x0B   ///< Hidden line
#define COLOR_LUMFUNC    0x0C   ///< Lumina function
#define COLOR_BG_MAX     0x0D   ///< Max color number

#define PALETTE_SIZE       (COLOR_FG_MAX+COLOR_BG_MAX)
///@}


/// This macro is used to build colored string constants (e.g. for format strings)
/// \param str string literal to surround with color tags
/// \param tag  one of SCOLOR_xxx constants
#define COLSTR(str,tag) SCOLOR_ON tag str SCOLOR_OFF tag

//----------------- Colors for tiplace_t ------------------------------------
/// \defgroup TIPLACE_COLORS Line colors to \ref tiplace_t
///@{
const color_t
  COLOR_NAME    = COLOR_CNAME,    ///< names      - blue
  COLOR_TYPE    = COLOR_HIDNAME,  ///< type names - gray
  COLOR_ATTR    = COLOR_HIDNAME,  ///< type attrs - gray
  COLOR_TNUM    = COLOR_LIBNAME,  ///< numbers    - light blue
  COLOR_CMT     = COLOR_NUMBER,   ///< comments   - green
  COLOR_ARGLOC  = COLOR_CREFTAIL, ///< arglocs    - red
  COLOR_ARGNAME = COLOR_REG,      ///< argnames   - dark blue
  COLOR_PRAGMA  = COLOR_MACRO;    ///< pragmas    - purple

#define SCOLOR_NAME    SCOLOR_CNAME
#define SCOLOR_TYPE    SCOLOR_HIDNAME
#define SCOLOR_ATTR    SCOLOR_HIDNAME
#define SCOLOR_TNUM    SCOLOR_LIBNAME
#define SCOLOR_CMT     SCOLOR_NUMBER
#define SCOLOR_ARGLOC  SCOLOR_CREFTAIL
#define SCOLOR_ARGNAME SCOLOR_REG
#define SCOLOR_PRAGMA  SCOLOR_MACRO
///@}


//------------------------------------------------------------------------

/// \defgroup color_conv Convenience functions
/// Higher level convenience functions are defined in ua.hpp.
/// Please use the following functions only if functions from ua.hpp
/// are not useful in your case.
///@{

/// Insert an address mark into a string.
/// \param buf  pointer to the output buffer; the tag will be appended or inserted into it
/// \param ea   address to include
/// \param ins  if true, the tag will be inserted at the beginning of the buffer

idaman THREAD_SAFE void ida_export tag_addr(qstring *buf, ea_t ea, bool ins=false);


/// Decode an address from an address mark.
/// \param line  points to sequence: COLOR_ON COLOR_ADDR ADDRESS
/// \return      the decoded address, or BADADDR on malformed input

idaman THREAD_SAFE ea_t ida_export tag_get_addr(const char *line);


/// Open a ::COLOR_SEMSPAN span with the given semantic kind.
/// Appends the span header: #COLOR_ON #COLOR_SEMSPAN <kind>.
/// Close the span with tag_semspan_off().
/// \param buf   output buffer to append to
/// \param kind  a \ref SCOLOR_ color code describing the span (e.g.
///              #COLOR_CNAME for a symbol name); #COLOR_DEFAULT = no specific
///              kind. Must not be 0.

idaman THREAD_SAFE void ida_export tag_semspan(qstring *buf, color_t kind=COLOR_DEFAULT);


/// Close a ::COLOR_SEMSPAN span opened with tag_semspan().
/// Appends #COLOR_OFF #COLOR_SEMSPAN (the closing side carries no header).

idaman THREAD_SAFE void ida_export tag_semspan_off(qstring *buf);


/// Decode the semantic kind of a ::COLOR_SEMSPAN span, and what it bundles.
/// \param at       points to the span header:
///                 COLOR_ON COLOR_SEMSPAN <kind> [<payload>]
/// \param payload  if non-nullptr, receives the payload, decoded according to
///                 the returned kind. Cleared first, and left cleared for a
///                 kind that bundles nothing - which is every kind so far.
///                 Only ever #VT_LONG, #VT_INT64 or #VT_STR.
///                 Pass nullptr if only the kind is wanted.
/// \return         the kind (a \ref SCOLOR_ code), or 0 on malformed input

idaman THREAD_SAFE color_t ida_export tag_get_semspan_kind(
        const char *at,
        idc_value_t *payload=nullptr);


/// Move pointer to a 'line' to 'cnt' positions right.
/// Take into account escape sequences.
/// \param line  pointer to string
/// \param cnt   number of positions to move right
/// \return moved pointer

idaman THREAD_SAFE const char *ida_export tag_advance(const char *line, int cnt);


/// Move the pointer past all color codes.
/// \param line  can't be nullptr
/// \return moved pointer, can't be nullptr

idaman THREAD_SAFE const char *ida_export tag_skipcodes(const char *line);


/// Skip one color code, including any payload it carries: this is the right way
/// to step over an entire ::COLOR_ADDR or ::COLOR_SEMSPAN header - whose size is
/// not something a caller may assume - starting from its #COLOR_ON byte.
/// This function should be used if you are interested in color codes
/// and want to analyze all of them.
/// Otherwise tag_skipcodes() function is better since it will skip all colors at once.
/// This function will skip the current color code if there is one.
/// If the current symbol is not a color code, it will return the input.
/// \return moved pointer

idaman THREAD_SAFE const char *ida_export tag_skipcode(const char *line);


/// Calculate length of a colored string
/// This function computes the length in unicode codepoints of a line
/// \return the number of codepoints in the line, or -1 on error

idaman THREAD_SAFE ssize_t ida_export tag_strlen(const char *line);


/// Remove color escape sequences from a string.
/// \param buf        output buffer with the string, cannot be nullptr.
/// \param str        input string, cannot be nullptr.
/// \param init_level used to verify that COLOR_ON and COLOR_OFF tags are balanced
/// \return length of resulting string, -1 if error

idaman THREAD_SAFE ssize_t ida_export tag_remove(qstring *buf, const char *str, int init_level=0);

inline THREAD_SAFE ssize_t idaapi tag_remove(qstring *buf, const qstring &str, int init_level=0)
{
  return tag_remove(buf, str.c_str(), init_level);
}

inline THREAD_SAFE ssize_t idaapi tag_remove(qstring *buf, int init_level=0)
{
  if ( buf->empty() )
    return 0;
  return tag_remove(buf, buf->begin(), init_level);
}

///@} color_conv

///@} color_def


/// Get prefix color for line at 'ea'
/// \return \ref COLOR_PFX
idaman color_t   ida_export calc_prefix_color(ea_t ea);

/// Get background color for line at 'ea'
/// \return RGB color
idaman bgcolor_t ida_export calc_bg_color(ea_t ea);


//------------------------------------------------------------------------
//      S O U R C E   F I L E S
//------------------------------------------------------------------------

/// \name Source files
/// IDA can keep information about source files used to create the program.
/// Each source file is represented by a range of addresses.
/// A source file may contain several address ranges.
///@{

/// Mark a range of address as belonging to a source file.
/// An address range may belong only to one source file.
/// A source file may be represented by several address ranges.
/// \param ea1       linear address of start of the address range
/// \param ea2       linear address of end of the address range (excluded)
/// \param filename  name of source file.
/// \return success

idaman bool ida_export add_sourcefile(ea_t ea1, ea_t ea2, const char *filename);


/// Get name of source file occupying the given address.
/// \deprecated Use get_sourcefile_by_ea() for safer access without pointer lifetime issues.
/// \param ea      linear address
/// \param bounds  pointer to the output buffer with the address range
///                for the current file. May be nullptr.
/// \return nullptr if source file information is not found,
///          otherwise returns pointer to file name

idaman DEPRECATED const char *ida_export get_sourcefile(ea_t ea, range_t *bounds=nullptr);


/// Get name of source file occupying the given address.
/// \param out     file name, may be nullptr
/// \param ea      linear address
/// \param bounds  pointer to the output buffer with the address range
///                for the current file. May be nullptr.
/// \return true if source file information is found, false otherwise

idaman bool ida_export get_sourcefile_by_ea(qstring *out, ea_t ea, range_t *bounds=nullptr);


/// Delete information about the source file.
/// \param ea  linear address
/// \return success

idaman bool ida_export del_sourcefile(ea_t ea);

/// Get number of source file ranges.
/// \return number of source file mapping entries

idaman size_t ida_export get_sourcefiles_qty(void);

/// Snapshot of a source file range (thread-safe, no pointer lifetime issues).

struct sourcefile_info_t
{
  range_t range;        ///< address range of the source file
  qstring filename;     ///< owned copy of the source file name
};

/// Get information about a source file range by its index.
/// \param out  pointer to output structure. Must not be nullptr.
/// \param n    index of the source file range (0..get_sourcefiles_qty()-1)
/// \return success

idaman bool ida_export getn_sourcefile(sourcefile_info_t *out, size_t n);

/// One source file range entry for the batch add_sourcefiles() API.
struct sourcefile_t : public range_t
{
  qstring filename;
};
typedef qvector<sourcefile_t> sourcefilevec_t;

/// Batch version of add_sourcefile(): insert all source file ranges at once
/// and perform a single save() at the end.
/// \param items  vector of source file ranges to insert
/// \return success
idaman bool ida_export add_sourcefiles(const sourcefilevec_t &items);
///@}

//------------------------------------------------------------------------
//      G E N E R A T I O N   O F   D I S A S S E M B L E D   T E X T
//------------------------------------------------------------------------

/// \name Generation of disassembled text
///@{

/// User-defined line-prefixes are displayed just after the autogenerated
/// line prefixes in the disassembly listing.
/// There is no need to call this function explicitly.
/// Use the user_defined_prefix_t class.
/// \param prefix_len prefixed length. if 0, then uninstall UDP
/// \param udp     object to generate user-defined prefix
/// \param owner   pointer to the plugin_t that owns UDP
///                if non-nullptr, then the object will be uninstalled and destroyed
///                when the plugin gets unloaded
idaman bool ida_export install_user_defined_prefix(
        size_t prefix_len,
        struct user_defined_prefix_t *udp,
        const void *owner);

/// Class to generate user-defined prefixes in the disassembly listing.
struct user_defined_prefix_t
{
  /// Creating a user-defined prefix object installs it.
  user_defined_prefix_t(size_t prefix_len, const void *owner)
  {
    install_user_defined_prefix(prefix_len, this, owner);
  }

  /// Destroying a user-defined prefix object uninstalls it.
  virtual idaapi ~user_defined_prefix_t()
  {
    install_user_defined_prefix(0, this, nullptr);
  }

  // Get a user-defined prefix.
  /// This callback must be overridden by the derived class.
  /// \param vout     the output buffer
  /// \param ea       the current address
  /// \param insn     the current instruction. if the current item is not
  ///                 an instruction, then insn.itype is zero.
  /// \param lnnum    number of the current line (each address may have several
  ///                 listing lines for it). 0 means the very first line for
  ///                 the current address.
  /// \param indent   see explanations for \ref gen_printf()
  /// \param line     the line to be generated.
  ///                 the line usually contains color tags.
  ///                 this argument can be examined to decide
  ///                 whether to generate the prefix.
  virtual void idaapi get_user_defined_prefix(
        qstring *vout,
        ea_t ea,
        const class insn_t &insn,
        int lnnum,
        int indent,
        const char *line) = 0;
};

///@}

//------------------------------------------------------------------------
//      A N T E R I O R / P O S T E R I O R   L I N E S
//------------------------------------------------------------------------

/// \name Anterior/Posterior lines
///@{

/// See higher level functions below

idaman AS_PRINTF(3, 0) bool ida_export vadd_extra_line(
        ea_t ea,
        int vel_flags,     // see VEL_...
        const char *format,
        va_list va);

#define VEL_POST 0x01      ///< append posterior line
#define VEL_CMT  0x02      ///< append comment line


/// Add anterior/posterior non-comment line(s).
/// \param ea      linear address
/// \param isprev  do we add anterior lines? (0-no, posterior)
/// \param format  printf() style format string. may contain \\n to denote new lines.
/// \return true if success

AS_PRINTF(3, 4) inline bool add_extra_line(ea_t ea, bool isprev, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  int vel_flags = (isprev ? 0 : VEL_POST);
  bool ok = vadd_extra_line(ea, vel_flags, format, va);
  va_end(va);
  return ok;
}


/// Add anterior/posterior comment line(s).
/// \param ea      linear address
/// \param isprev  do we add anterior lines? (0-no, posterior)
/// \param format  printf() style format string. may contain \\n to denote
///                new lines. The resulting string should not contain comment
///                characters (;), the kernel will add them automatically.
/// \return true if success

AS_PRINTF(3, 4) inline bool add_extra_cmt(ea_t ea, bool isprev, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  int vel_flags = (isprev ? 0 : VEL_POST) | VEL_CMT;
  bool ok = vadd_extra_line(ea, vel_flags, format, va);
  va_end(va);
  return ok;
}


/// Add anterior comment line(s) at the start of program.
/// \param format  printf() style format string. may contain \\n to denote
///                new lines. The resulting string should not contain comment
///                characters (;), the kernel will add them automatically.
/// \return true if success

AS_PRINTF(1, 2) inline bool add_pgm_cmt(const char *format, ...)
{
  va_list va;
  va_start(va,format);
  bool ok = vadd_extra_line(inf_get_min_ea(), VEL_CMT, format, va);
  va_end(va);
  return ok;
}

///@}

///---------------------------------------------------------------------\cond
///         The following functions are used in kernel only:

// Generate disassembly (many lines) and put them into a buffer
// Returns number of generated lines
idaman int ida_export generate_disassembly(
        qstrvec_t *out,         // buffer to hold generated lines
        int *lnnum,             // number of "the most interesting" line
        ea_t ea,                // address to generate disassembly for
        int maxsize,            // maximum number of lines
        int flags = 0);

#define GDISMF_AS_STACK (1 << 0) ///< Display undefined items as 2/4/8 bytes
#define GDISMF_ADDR_TAG (1 << 1) ///< generate an hidden addr tag at the beginning of the line
#define GDISMF_REMOVE_TAGS (1 << 2) ///< remove color tags from the output
#define GDISMF_UNHIDE   (1 << 3) ///< display hidden objects (segment, function, range)

// Generate one line of disassembly
// This function discards all "non-interesting" lines
// It is designed to generate one-line descriptions
// of addresses for lists, etc.
idaman bool ida_export generate_disasm_line(
        qstring *buf,           // output buffer
        ea_t ea,                // address to generate disassembly for
        int flags=0);
#define GENDSM_FORCE_CODE  (1 << 0)     ///< generate a disassembly line as if
                                        ///< there is an instruction at 'ea'
#define GENDSM_MULTI_LINE  (1 << 1)     ///< if the instruction consists of several lines,
                                        ///< produce all of them (useful for parallel instructions)
#define GENDSM_REMOVE_TAGS (1 << 2)     ///< remove color tags from the output buffer
#define GENDSM_UNHIDE      (1 << 3)     ///< display hidden objects (segment, function, range)

/// Get length of the line prefix that was used for the last generated line

idaman int ida_export get_last_pfxlen();


// Get pointer to the sequence of characters denoting 'close comment'
// empty string means no comment (the current assembler has no open-comment close-comment pairs)
// This function uses ash.cmnt2

idaman const char *ida_export closing_comment();


// Every anterior/posterior line has its number.
// Anterior  lines have numbers from E_PREV
// Posterior lines have numbers from E_NEXT

const int E_PREV = 1000; ///< Anterior line starting number
const int E_NEXT = 2000; ///< Posterior line starting number

idaman int ida_export get_first_free_extra_cmtidx(ea_t ea, int start);
idaman bool ida_export update_extra_cmt(ea_t ea, int what, const char *str);
idaman bool ida_export del_extra_cmt(ea_t ea, int what);
idaman ssize_t ida_export get_extra_cmt(qstring *buf, ea_t ea, int what);
idaman void ida_export delete_extra_cmts(ea_t ea, int what);

idaman ea_t ida_export align_down_to_stack(ea_t newea);
idaman ea_t ida_export align_up_to_stack(ea_t ea1, ea_t ea2=BADADDR);

// A helper class, to encode from UTF-8, -> into the target encoding.
// This is typically used when generating listings (or any kind of
// output file.)
struct encoder_t
{
  // whether or not a message should be printed, letting the
  // user know that some text couldn't be recoded properly
  enum notify_recerr_t
  {
    nr_none,
    nr_once,
  };

  virtual ~encoder_t() {}
  virtual bool idaapi get_bom(bytevec_t *out) const = 0;
  // returns true if conversion was entirely successful, false otherwise.
  // codepoints that couldn't be converted, will be output as C
  // literal-escaped UTF-8 sequences (e.g., "\xC3\xD9"), and if
  // 'nr_once' was passed at creation-time, a one-time notification
  // well be output in the messages window.
  virtual bool idaapi encode(qstring *s) const = 0;
  // encode()s the UTF-8 string composed by format + args, and
  // returns true if all the resulting bytes could be written to
  // the output file.
  AS_PRINTF(3, 4) virtual bool idaapi print(FILE *out, const char *format, ...) const = 0;
  // should a file be opened as binary, or should it rather be opened
  // in text mode? This will have an importance in how '\n' characters
  // are possibly converted into '\x0A\x0D' on windows, which is most
  // inappropriate when output'ing e.g., UTF-16, UTF-32..
  virtual bool idaapi requires_binary_mode() const = 0;
};

// Create the encoder with the given target encoding. If -1 is passed
// then the effective target encoding will be computed like so:
// if ( encidx < 0 )
// {
//   encidx = get_outfile_encoding_idx();
//   if ( encidx == STRENC_DEFAULT )
//     encidx = get_default_encoding_idx(BPU_1B);
// }
idaman encoder_t *ida_export create_encoding_helper(
        int encidx=-1,
        encoder_t::notify_recerr_t nr=encoder_t::nr_once);

/// Callback functions to output lines:
///@{
typedef int idaapi html_header_cb_t(FILE *fp);
typedef int idaapi html_footer_cb_t(FILE *fp);
typedef int idaapi html_line_cb_t(
        FILE *fp,
        const qstring &line,
        bgcolor_t prefix_color,
        bgcolor_t bg_color);
#define gen_outline_t html_line_cb_t
///@}

///-------------------------------------------------------------------\endcond

//-------------------------------------------------------------------------
// Listing generation: a streaming generator of a listing's lines, its line
// type, and the config an HTML-export template receives. Scripts/plugins and
// the UI (which implements the generator) both see these.

/// Listing text encoding; the low 8 bits of a listing flags word.
enum listing_format_t : uchar
{
  LLFMT_TAGGED,       ///< IDA color-tagged text (as gen_disasm_text produces)
  LLFMT_PLAIN,        ///< tags stripped
  LLFMT_HTML_INLINE,  ///< inline-styled HTML span runs (self-contained)
  LLFMT_HTML_CLASSES, ///< class-based HTML span runs (styled by get_style_block())
};

/// listing_lines_t flags: a 32-bit word whose low 8 bits hold the
/// ::listing_format_t and whose upper bits are decorations.
#define LLF_FORMAT_MASK 0x000000FF ///< extract the ::listing_format_t
#define LLF_LINKS       0x00000100 ///< HTML: emit in-document anchors/links

/// \defgroup LAF_ link_anchor_t::flags: describe a navigational endpoint
///@{
#define LAF_INCOMING 0x00000001 ///< the owning line is this identifier's
                                ///< definition: links from elsewhere land here
#define LAF_OUTGOING 0x00000002 ///< the owning line references this identifier,
                                ///< whose definition lives in this same document
#define LAF_XREF     0x00000004 ///< a cross-reference endpoint (rather than the
                                ///< direct flow/jump the line's own text spells
                                ///< out); higher bits carry its kind (reserved)
///@}

/// One navigational endpoint attached to a listing line: an anchor identifier
/// plus flags describing the edge it takes part in. A tiny movable value, so a
/// line can carry a vector of them: its own anchor, an outgoing reference, and
/// -- later -- each of its cross-references.
struct link_anchor_t
{
  /// Listing-kind-agnostic anchor id -- a name in a disassembly, the analogous
  /// computed id in pseudocode / type listings; never an address -- used as the
  /// HTML element id and as the link target. On both ends of one edge the
  /// identifier holds the same value, so a reference and its definition match by
  /// string.
  qstring identifier;
  uint32 flags = 0;             ///< \ref LAF_ bits qualifying \ref identifier
  link_anchor_t() {}
  link_anchor_t(const qstring &id, uint32 f) : identifier(id), flags(f) {}
  bool operator==(const link_anchor_t &r) const
    { return flags == r.flags && identifier == r.identifier; }
  bool operator!=(const link_anchor_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(link_anchor_t);
typedef qvector<link_anchor_t> link_anchors_t; ///< a line's navigational endpoints

/// One produced line. \ref cb is set by the constructor; extend this struct
/// only by appending fields.
struct listing_line_t
{
  size_t cb = sizeof(listing_line_t); ///< set on construction; hidden in Python
  qstring text;                       ///< encoded per the format's ::listing_format_t
  link_anchors_t anchors;             ///< navigational endpoints of this line;
                                      ///< empty when it takes no part in the link
                                      ///< graph. See \ref link_anchor_t.
  place_t *place = nullptr;           ///< borrow (whole instance is const-returned by next())
  color_t prefix_color = 0;           ///< the line-prefix color tag
  bgcolor_t bg_color = DEFCOLOR;      ///< line background, or DEFCOLOR for none
};
DECLARE_TYPE_AS_MOVABLE(listing_line_t);

/// A streaming generator of a listing's lines. The UI builds it; a script that
/// receives one (e.g. an HTML-export template's run() argument) borrows it and
/// must not delete it.
class listing_lines_t
{
public:
  uint32 flags = 0; ///< low 8 bits: ::listing_format_t; upper bits: LLF_*
  qstring title;    ///< suggested document title (the exported subject: a
                    ///< function, a type, the database), filled by the UI; a
                    ///< template may use it (empty => none suggested)
  bool cancelled = false; ///< set once the stream stops early because the user
                          ///< cancelled; read it through was_cancelled()
  virtual ~listing_lines_t() {}
  /// The next line, or \c nullptr at end.
  /// WARNING: the returned instance is a BORROW owned by the stream and valid
  /// ONLY until the next next() call (which overwrites it) or until the stream
  /// is destroyed. Do not store the pointer or any part of it (text, place,
  /// ...); copy what you need before calling next() again.
  virtual const listing_line_t *idaapi next() = 0;
  /// The CSS style block for ::LLFMT_HTML_CLASSES (empty otherwise).
  /// \return false if there is nothing to emit.
  virtual bool idaapi get_style_block(qstring *out) = 0;
  /// The anchor identifier of the definition rendered at \p place (populated
  /// lazily as lines are produced); false if none. For a function sidebar etc.
  virtual bool idaapi place_to_identifier(qstring *out, const place_t *place) const = 0;
  /// The listing text encoding (the low 8 bits of \ref flags).
  listing_format_t format() const
    { return listing_format_t(flags & LLF_FORMAT_MASK); }
  /// HTML: emit in-document anchors/links (::LLF_LINKS).
  bool emit_links() const { return (flags & LLF_LINKS) != 0; }
  /// Whether the stream stopped early because the user cancelled: next() then
  /// returns \c nullptr as at end. The stream polls the wait box's Cancel as it
  /// produces lines, so a consumer (e.g. an HTML-export template) need not poll.
  bool was_cancelled() const { return cancelled; }
};

//-------------------------------------------------------------------------
/// \defgroup SYNTAX_COLORIZE Syntax colorizer
/// Convert color-tagged listing text to HTML. The colors are supplied as data
/// (a per-tag list), so the conversion has no dependency on the GUI.
///@{

/// One tag's look: its color (::DEFCOLOR => inherit) and CSS class ("" => none).
struct listing_palette_entry_t
{
  bgcolor_t rgb = DEFCOLOR;   ///< 0xAARRGGBB, or ::DEFCOLOR to inherit
  qstring css;                ///< CSS class name for class-based HTML, else ""
};

/// A listing's color palette: for each ::COLOR_ tag, the color (and optional CSS
/// class) to draw it with, kept separately for text runs (\ref fg) and line
/// prefixes (\ref pfx) -- a tag can mean different things in the two roles (e.g.
/// ::COLOR_DEFAULT is the default text color as text, the default background as a
/// prefix). A plain value object: fill the entries you know and set \ref inited;
/// the export engine seeds an un-initialized palette from the built-in default
/// palette. The HTML renderer reads \ref listing_palette_entry_t::rgb in inline
/// mode and \ref listing_palette_entry_t::css in class mode.
struct listing_palette_t
{
  typedef listing_palette_entry_t entry_t;
  entry_t fg[COLOR_FG_MAX];     ///< text palette, indexed by ::COLOR_ tag
  entry_t pfx[COLOR_FG_MAX];    ///< line-prefix (gutter) palette, by ::COLOR_ tag
  bool inited = false;          ///< have the built-in defaults been applied?

  /// \return the tag's text color, or ::DEFCOLOR to inherit.
  bgcolor_t resolve_tag_color(color_t tag) const
    { return tag < COLOR_FG_MAX ? fg[tag].rgb : DEFCOLOR; }
  /// \return the tag's line-prefix (gutter) color, or ::DEFCOLOR to inherit.
  bgcolor_t resolve_tag_prefix(color_t tag) const
    { return tag < COLOR_FG_MAX ? pfx[tag].rgb : DEFCOLOR; }
  /// \return true and set \p out to the tag's text CSS class, else false (inline).
  bool resolve_tag_color_class(qstring *out, color_t tag) const
  {
    if ( tag < COLOR_FG_MAX && !fg[tag].css.empty() )
    {
      *out = fg[tag].css;
      return true;
    }
    return false;
  }
  /// \return true and set \p out to the tag's line-prefix CSS class, else false.
  bool resolve_tag_prefix_class(qstring *out, color_t tag) const
  {
    if ( tag < COLOR_FG_MAX && !pfx[tag].css.empty() )
    {
      *out = pfx[tag].css;
      return true;
    }
    return false;
  }
};

///@}

//-------------------------------------------------------------------------
/// \defgroup EXPORT_LISTING Listing export
/// Turn a listing's place ranges into styled lines, and whole HTML
/// documents/fragments -- all without a GUI. The caller supplies the data the
/// engine needs (palette, display options, ...) as an ::export_listing_t.
///@{

struct export_listing_t;   // defined below

/// export_listing_ctl() control codes: one per \ref export_listing_t scope
/// builder, which documents it.
enum export_listing_ctl_code_t
{
  ELCTL_ADD_DISASM_RANGE,       ///< arg1 = start ea, arg2 = end ea, arg3 = expand
  ELCTL_ADD_WHOLE_DISASSEMBLY,  ///< arg1 = expand
  ELCTL_ADD_FUNCTION,           ///< arg1 = ea, arg2 = expand
  ELCTL_ADD_ITEM,               ///< arg1 = ea, arg2 = expand
  ELCTL_ADD_TYPE,               ///< arg1 = type ordinal
  ELCTL_ADD_ALL_TYPES,          ///< no args
  ELCTL_ADD_PSEUDOCODE,         ///< arg1 = const strvec_t * (copied), arg2 = function ea
  ELCTL_ENSURE_SCOPE,           ///< arg1 = current thing (vs entire), arg2 = expand
  ELCTL_FREE_RESERVED,          ///< cfg = nullptr, arg1 = the reserved ptr to free
  ELCTL_CREATE_LINES,           ///< arg1 = listing_lines_t ** (out; caller owns),
                                ///< arg2 = rendering flags, arg3 = range index
};

/// The scope-builder dispatcher. Not called directly: the
/// \ref export_listing_t methods pass the right code and arguments.
idaman bool ida_export export_listing_ctl(
        export_listing_t *cfg,
        export_listing_ctl_code_t code,
        size_t arg1=0,
        size_t arg2=0,
        size_t arg3=0);

/// Owner of a config's internal bookkeeping (\ref export_listing_t::reserved);
/// releases it on destruction. Uncopyable, which also makes ::export_listing_t
/// non-copyable (pass it by reference).
struct export_listing_reserved_holder_t
{
  void *ptr = nullptr;   ///< opaque, kernel-managed
  export_listing_reserved_holder_t() {}
  DECLARE_UNCOPYABLE(export_listing_reserved_holder_t)
  ~export_listing_reserved_holder_t()
  {
    if ( ptr != nullptr )
      export_listing_ctl(nullptr, ELCTL_FREE_RESERVED, size_t(ptr));
  }
};

/// Everything a listing export needs, as data (no view): WHAT to export (the
/// \ref ranges) and the caller-supplied look (palette, style block, title).
/// HOW to render is not config state: it is the flags argument of
/// export_listing(). Strings and ranges are owned; the remaining pointers are
/// borrowed. Non-copyable; pass it by reference. \ref cb is set on
/// construction; append-only.
///
/// Scope with the add_* builders (calls accumulate) or fill \ref ranges
/// directly. The current_* triplet is the originating listing's position:
/// ensure_scope() materializes a whole scope from it.
struct export_listing_t
{
  size_t cb = sizeof(export_listing_t);        ///< set on construction; hidden in Python
  lines_gen_range_vec_t ranges;                ///< what to export (owned)
  listing_palette_t palette;                         ///< colors; the exporter fills
                                                     ///< the built-in defaults if the
                                                     ///< caller left it un-initialized
  qstring style_block;                               ///< <style> body for HTML_CSS_CLASSES
  qstring title;                                     ///< document title (empty => none)
  qstring template_path;                             ///< export_listing_to_file: a template
                                                     ///< .py (empty => built-in document)
  const place_t *current_place = nullptr;            ///< the originating listing's
                                                     ///< current place (borrowed)
  void *current_ud = nullptr;                        ///< ... its linearray place cookie (borrowed)
  const dual_text_options_t *current_disp = nullptr; ///< ... its display options (borrowed)
  export_listing_reserved_holder_t reserved;         ///< internal bookkeeping (owned: e.g.
                                                     ///< the pseudocode snapshots the ranges
                                                     ///< walk), managed through
                                                     ///< export_listing_ctl(). Not for callers.

  /// \name Scope builders
  /// One call per thing to export; calls accumulate, so a mixed export is a
  /// sequence of calls, emitted in insertion order. Each builder stamps the
  /// appended ranges with the right walking context; `expand` sets their
  /// \ref lines_gen_range_t::expand_hidden.
  ///@{

  /// Append a disassembly address range: [start, end), end-exclusive like a
  /// func_t/range_t; BADADDR as `end` means "to the listing end".
  void add_disasm_range(ea_t start, ea_t end=BADADDR, bool expand=false)
    { export_listing_ctl(this, ELCTL_ADD_DISASM_RANGE, size_t(start), size_t(end), expand); }

  /// Append the whole disassembly listing.
  void add_whole_disassembly(bool expand=false)
    { export_listing_ctl(this, ELCTL_ADD_WHOLE_DISASSEMBLY, expand); }

  /// Append the function containing `ea`, tail chunks included.
  /// \return false if there is no function there
  bool add_function(ea_t ea, bool expand=false)
    { return export_listing_ctl(this, ELCTL_ADD_FUNCTION, size_t(ea), expand); }

  /// Append the disassembly item at `ea` (its whole listing lines).
  /// \return false if `ea` is not mapped
  bool add_item(ea_t ea, bool expand=false)
    { return export_listing_ctl(this, ELCTL_ADD_ITEM, size_t(ea), expand); }

  /// Append a single local type, by ordinal (its header down to its footer).
  /// \return false if there is no such type
  bool add_type(uint32 ordinal)
    { return export_listing_ctl(this, ELCTL_ADD_TYPE, ordinal); }

  /// Append the whole local-types listing.
  void add_all_types()
    { export_listing_ctl(this, ELCTL_ADD_ALL_TYPES); }

  /// Append a pseudocode listing over `lines` (e.g. a cfunc's pseudocode).
  /// The lines are COPIED into the config: no lifetime obligation on the
  /// caller's vector or the cfunc. `ea` is the decompiled function's address;
  /// the range's places are built from it (through the registered place
  /// converter), so the export anchors the function (sidebar, incoming links)
  /// and links its calls to other exported functions.
  /// \return false if the decompiler is not available
  bool add_pseudocode(const strvec_t *lines, ea_t ea)
    { return export_listing_ctl(this, ELCTL_ADD_PSEUDOCODE, size_t(lines), size_t(ea)); }

  /// Materialize a scope from \ref current_place into \ref ranges: the
  /// current thing (`current`: the function/item, the type, the pseudocode)
  /// or the entire listing. Built ranges inherit \ref current_disp and
  /// `expand`. A config with non-empty ranges is left untouched (true).
  /// \return false when nothing can be built (no current place, or a listing
  /// kind whose entire-listing scope cannot be derived from a place).
  bool ensure_scope(bool current, bool expand=false)
    { return export_listing_ctl(this, ELCTL_ENSURE_SCOPE, current, expand); }
  ///@}

  /// The streaming engine: a generator over the range `range_index`,
  /// rendering per `flags` (::listing_format_t | ::LLF_LINKS) -- the consumer
  /// loops over the ranges itself, so it always knows which region it is
  /// rendering. The document is the config: in-document links may target any
  /// of its ranges, and the generators of one generation pass share the
  /// document's navigation state (a name anchors once per document), so
  /// create them in range order -- a non-monotonic index starts a new pass.
  /// The caller owns the result and must delete it; the config is borrowed
  /// and must outlive it. \return nullptr for an out-of-range index.
  listing_lines_t *create_lines(uint32 flags, size_t range_index)
  {
    listing_lines_t *gen = nullptr;
    export_listing_ctl(this, ELCTL_CREATE_LINES, size_t(&gen), flags, range_index);
    return gen;
  }
};

/// Whole-output producer: every range's lines joined into one string (no
/// trailing newline), rendered per `flags`.
idaman bool ida_export export_listing_to_string(
        qstring *out,
        export_listing_t *cfg,
        uint32 flags);

/// Whole-output producer: write a complete HTML document to \p path. When
/// \ref export_listing_t::template_path is set, that .py template's
/// `run(path, cfg)` takes over (receiving \p cfg, borrowed) and builds its
/// own generator(s); otherwise the built-in css-class document is emitted.
/// \return false with \p errbuf set on failure; \p out_lines (optional)
/// receives the built-in document's line count.
idaman bool ida_export export_listing_to_file(
        const char *path,
        export_listing_t *cfg,
        qstring *errbuf,
        int *out_lines=nullptr);
///@}

#endif

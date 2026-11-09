#ifndef IDA_HIGHLIGHTER
#define IDA_HIGHLIGHTER

#include <expr.hpp>

idaman void ida_export code_highlight_block(void *context, highlighter_cbs_t *highlighter_cbs, const qstring &text);

struct ida_syntax_highlighter_helper_t
{
  virtual ~ida_syntax_highlighter_helper_t() {}
// returns the length of text to colorize
// negative values may have special meaning in the future.
  virtual ssize_t get_text_color(syntax_highlight_style * /*out_color*/, const char * /*str*/) { return 0; }
// returns true if identifier is colorized
  virtual bool get_ident_color(syntax_highlight_style * /*out_color*/, const qstring &/*ident*/) { return false; }
};
typedef qvector<ida_syntax_highlighter_helper_t *> ida_syntax_highlighter_helpers_t;

#define MLTCMTMASK    0xF
#define PREPROC_FLAG  0x10

// Common implementation of syntax_highlighter_t used in different parts of IDA
//-V:ida_syntax_highlighter_t:730 not all members of a class are initialized inside the constructor
struct ida_syntax_highlighter_t : syntax_highlighter_t
{
protected:
  // keys of keywords_t point to memory from keyword_strings.
  // once allocated, this buffer won't be moved in the memory.
  qstrvec_t keyword_memory;
  // helper class so that keywords_t gets sorted by string contents, not pointer values.
  struct plain_char_ptr_t
  {
    const char *ptr;
    plain_char_ptr_t(const char *p = nullptr) : ptr(p) {}
    bool operator <(const plain_char_ptr_t &r) const
    {
      return strcmp(ptr, r.ptr) < 0;
    }
    bool operator ==(const plain_char_ptr_t &r) const
    {
      return strcmp(ptr, r.ptr) == 0;
    }
  };
  struct multicmt_t
  {
    qstring open_multicmt;
    qstring close_multicmt;
    multicmt_t() {}
    multicmt_t(const char *_open_multicmt, const char *_close_multicmt) :
      open_multicmt(_open_multicmt),
      close_multicmt(_close_multicmt)
    {}
  };

  // typedef std::map<plain_char_ptr_t, syntax_highlight_style> keywords_t;
  struct keywords_style_t
  {
    qvector<plain_char_ptr_t> keywords;
    syntax_highlight_style style;
  };
  typedef qvector<keywords_style_t> keywords_t;
  //typedef qvector<plain_char_ptr_t> keywords_t;
  typedef qvector<multicmt_t> multicmtvec_t;
  keywords_t keywords;

  qstring open_cmt;             // string that opens a regular line comment
  multicmtvec_t multicmts;
  char literal_closer;          // either close_strconst or close_chrconst for the current literal

  // color mappings
  syntax_highlight_style text_color = HF_DEFAULT;
  syntax_highlight_style comment_color = HF_COMMENT;
  syntax_highlight_style string_color = HF_STRING;
  syntax_highlight_style preprocessor_color = HF_PREPROC;

  ida_syntax_highlighter_helpers_t ida_syntax_highlighter_helpers;

  // work variables
  const char *input;                  // pointer to the start of the input buffer
  const char *pending;                // pointer in the input buffer
  syntax_highlight_style style = HF_DEFAULT; // current highlighting style

  bool pending_nonspaces_present(const char *end)
  {
    for ( const char *p = pending; p != end; ++p )
      if ( !qisspace(*p) )
        return true;
    return false;
  }

  const char *parse_literal_const(highlighter_cbs_t *highlighter_cbs, const char *ptr, char literal_closer);
  void flush_output(highlighter_cbs_t *highlighter_cbs, const char *ptr, syntax_highlight_style style);
  void handle_cmt(highlighter_cbs_t *highlighter_cbs, int mcmt_idx, const char **ptr);
  void handle_preproc(highlighter_cbs_t *highlighter_cbs, const char **ptr);

public:
  // if any of the following features is not needed, just zero them out:
  char open_strconst;           // character that opens a string constant
  char close_strconst;          // character that closes a string constant
  char open_chrconst;           // character that closes a character constant
  char close_chrconst;          // character that opens a character constant
  char escape_char;             // backslash
  char preprocessor_char;       // #

  ida_syntax_highlighter_t() : syntax_highlighter_t(&code_highlight_block) {}

  void highlight_block_ex(highlighter_cbs_t *highlighter_cbs, const qstring &text);
  void add_ida_syntax_highlighter_helper(ida_syntax_highlighter_helper_t *sh) { ida_syntax_highlighter_helpers.push_back(sh); }
  void set_open_cmt(const char *begin) { open_cmt = begin; }
  void add_multi_line_comment(const char *begin, const char *end)
  {
    multicmt_t &mcmt = multicmts.push_back();
    mcmt.open_multicmt = begin;
    mcmt.close_multicmt = end;
  }

  keywords_style_t *get_keyword_style(syntax_highlight_style _style)
  {
    keywords_style_t *pair_p = nullptr;
    for ( int i = 0; i < keywords.size(); i++ )
    {
      if ( keywords[i].style == _style )
      {
        pair_p = &keywords[i];
        break;
      }
    }
    if ( pair_p == nullptr )
    {
      keywords_style_t &pair = keywords.push_back();
      pair_p = &pair;
      pair_p->style = _style;
    }
    return pair_p;
  }

  void add_keyword_to_style(const char *kw, syntax_highlight_style _style)
  {
    keywords_style_t *pair_p = get_keyword_style(_style);
    pair_p->keywords.push_back(kw);
  }

  void add_keywords(const char *kwstr, syntax_highlight_style _style)
  {
    char *ctx;
    // in order not to allocate every keyword separately, we allocate the whole
    // kwstr string at once and will just store pointers to it in the map.
    qstring &mem = keyword_memory.push_back();
    mem = kwstr;
    for ( char *kw = qstrtok(mem.begin(), "|", &ctx); kw != nullptr; kw = qstrtok(nullptr, "|", &ctx) )
    {
      // there is room for optimization here...
      bool exists = false;
      for ( int i = 0; i < keywords.size(); i++ )
      {
        auto p = std::find(keywords[i].keywords.begin(), keywords[i].keywords.end(), kw);
        if ( p != keywords[i].keywords.end() )
        {
          // already exists, update the style
          if ( keywords[i].style != _style )
          {
            keywords[i].keywords.erase(p);
            add_keyword_to_style(kw, _style);
          }
          exists = true;
          break;
        }
      }
      if ( !exists )
        add_keyword_to_style(kw, _style);
    }
  }

};


#endif // IDA_HIGHLIGHTER

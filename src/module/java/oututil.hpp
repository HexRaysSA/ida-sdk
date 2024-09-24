#ifndef _OUTUTIL_HPP__
#define _OUTUTIL_HPP__

const color_t COLOR_NONE = 0;
#define WARN_SYM      ('#')

#define MIN_ARG_SIZE  3
#define STR_PRESERVED 64  // overlapped (MAXSTR*2) preservation (for color)

class out_java_t;

//----------------------------------------------------------------------
#ifdef TEST_FMTSTR
class out_java_t
{
public:
  qstring outbuf;

  void out_char(char c);
  void out_line(const char *str);
private:
  AS_PRINTF(2, 0) void out_vprintf(const char *format, va_list va);
};
#else
class out_java_t : public outctx_t
{
  out_java_t(void) = delete; // not used
  // due to create_context() call we cannot use PM from outctx_t
  java_t &pm() { return *GET_MODULE_DATA(java_t); }
  inline bool jasmin(void) const { return GET_MODULE_DATA(java_t)->jasmin(); }
public:
  // oututil.cpp
  int out_commented(const char *p, color_t color = COLOR_NONE);
  bool change_line(bool main = false);
  size_t putLine(java_t &pm);
  bool checkLine(size_t size);
  bool chkOutLine(const char *str, size_t len);
  bool chkOutKeyword(const char *str, uint len);
  bool chkOutSymbol(char c);
  bool chkOutChar(char c);
  bool chkOutSymSpace(char c);
  uchar putShort(ushort value, uchar wsym = WARN_SYM);
  char outName(ea_t from, int n, ea_t ea, uval_t off, uchar *rbad);
  uchar putVal(const op_t &x, uchar mode, uchar warn);
  uchar OutUtf8(ushort index, fmt_t mode, color_t color = COLOR_NONE);
  uchar out_index(ushort index, fmt_t mode, color_t color, uchar as_index);
  uchar out_alt_ind(uint32 val);
  void out_method_label(uchar is_end);
  uchar outOffName(ushort off);
  bool block_begin(uchar off);
  bool block_end(uint32 off);
  bool block_close(uint32 off, const char *name);
  bool close_comment(void);
  uchar out_nodelist(uval_t nodeid, uchar pos, const char *pref);
  void init_prompted_output(uchar pos = 0);
  void term_prompted_output(void);
  uchar OutConstant(const op_t &_x, bool include_descriptor=false);
  void myBorder(void);
  uchar out_problems(char str[MAXSTR], const char *prefix);
  uchar putScope(ushort scope, uint32 doff);
  size_t debLine(java_t &pm);

  void OutKeyword(const char *str, size_t len);
  void outLine(const char *str, uint len);
  uchar chkOutDot(void);
  void OutSpace(void);
  uchar chkOutSpace(void);

  size_t putDeb(uchar next);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);

  // npooluti.cpp
  size_t _one_line(void) { return 0; }
  int fmtString(java_t &pm, ushort index, ssize_t size, fmt_t mode, _PRMPT_ putproc = nullptr);
  void trunc_name(uint num, uchar type = 0);

  // out.cpp
  bool out_sm_end(void);
  bool out_deprecated(uchar pos);
  bool out_sm_start(int same);
  bool out_stackmap(const SMinfo *pinf);
  uchar OutModes(uint32 mode);
  uchar sign_out(ushort utsign, char mode);
  void out_switch(void);
  bool close_annotation(uint32 pos);
  const ushort *annotation(const ushort *p, uint *plen, uint pos);
  const ushort *annotation_element(const ushort *p, uint *plen, uint pos, ushort name);
  uchar annotation_loop(const uval_t *pnodes, uint nodecnt);
  uchar enclose_out(void);
  uchar out_seg_type(fmt_t fmt);
  uchar out_field_type(void);
  uchar out_includes(uval_t node, uchar pos);
  void java_header(void);
  void java_segstart(segment_t *seg);
  void java_segend(segment_t *seg);
  void java_data(bool /*analyze_only*/);

  // map.cpp
  bool print_newline(void);
  size_t write_utf(void);

private:
  char putMethodLabel(ushort off);
};
CASSERT(sizeof(out_java_t) == sizeof(outctx_t));
#endif // TEST_FMTSTR

//----------------------------------------------------------------------
#define CHK_OUT_STR(p)  chkOutLine(p, sizeof(p)-1)
#define OUT_KEYWORD(p)  OutKeyword(p, sizeof(p)-1)
#define CHK_OUT_KEYWORD(p)  chkOutKeyword(p, sizeof(p)-1)
#define OUT_STR(p)  outLine(p, sizeof(p)-1)

#endif

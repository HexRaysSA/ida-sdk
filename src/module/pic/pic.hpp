/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _PIC_HPP
#define _PIC_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"
#define PROCMOD_NAME            pic
#define PROCMOD_NODE_NAME       "$ " QSTRINGIZE(PROCMOD_NAME)

//------------------------------------------------------------------
enum regnum_t ENUM_SIZE(uint16)
{
  W, F,
  ACCESS,        // register for PIC18Cxx
  BANKED,        // register for PIC18Cxx
  FAST,          // register for PIC18Cxx
  FSR0,          // register for PIC18Cxx
  FSR1,          // register for PIC18Cxx
  FSR2,          // register for PIC18Cxx
  BANK,
  rVcs, rVds,    // virtual registers for code and data segments
  PCLATH,
  PCLATU         // register for PIC18Cxx
};

#define PIC16_FSR2L 0xFD9
#define PIC16_PLUSW2 0xFDB
#define PIC16_INDF2 0xFDF
#define PIC16_BANK 0xFE0
#define PIC16_FSR1L 0xFE1
#define PIC16_POSTINC1 0xFE6
#define PIC16_PCL 0xFF9
#define PIC16_PCLATH 0xFFA

//------------------------------------------------------------------
// processor types

typedef uchar proctype_t;

const proctype_t PIC12  = 0;
const proctype_t PIC14  = 1;
const proctype_t PIC16  = 2;

//------------------------------------------------------------------
inline bool is_bit_insn(const insn_t &insn)
{
  return insn.itype >= PIC_bcf && insn.itype <= PIC_btfss
      || insn.itype >= PIC_bcf3 && insn.itype <= PIC_btg3;
}

ea_t calc_code_mem(const insn_t &insn, ea_t ea);
int calc_outf(const op_t &x);

//------------------------------------------------------------------
void interr(const char *module);

void idaapi pic_segend(outctx_t &ctx, segment_t *seg);

int  idaapi is_align_insn(ea_t ea);

int idaapi is_jump_func(const func_t *pfn, ea_t *jump_target);
int idaapi is_sane_insn(int nocrefs);
int idaapi may_be_func(void);           // can a function start here?

//------------------------------------------------------------------
struct pic_iohandler_t : public iohandler_t
{
  struct pic_t &pm;
  pic_iohandler_t(pic_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual void get_cfg_filename(char *buf, size_t bufsize) override;
  virtual bool area_processing(ea_t /*start*/, ea_t /*end*/, const char * /*name*/, const char * /*aclass*/) override;
};

struct pic_t : public procmod_t
{
  pic_iohandler_t ioh = pic_iohandler_t(*this, helper);

  netnode helper;
  ea_t dataseg = BADADDR;
  int sav_respect_info = IORESP_NONE;

  inline void save_idpflags() { helper.altset(-1, idpflags); }
  inline void save_dataseg()  { helper.altset(0, ea2node(dataseg)); }

#define IDP_SIMPLIFY 0x0001     // simplify instructions
  ushort idpflags = IDP_SIMPLIFY;
  inline bool dosimple(void)
  { // if macros are enabled, we should simplify insns
    return inf_macros_enabled() || (idpflags & IDP_SIMPLIFY) != 0;
  }

  proctype_t ptype = PIC12;
  const char *cfgname = "pic12.cfg";
  bool set = false;
  bool flow = false;

  struct portmap_t
  {
    ea_t from;
    ea_t to;
  };
  qvector<portmap_t> map;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void create_mappings(void);
  void load_symbols_without_infotype(int _respect_info);
  void load_symbols(int _respect_info);
  const char *find_sym(ea_t address);
  const ioport_bits_t *find_bits(ea_t address);
  const char *find_bit(ea_t address, int bit);
  void apply_symbols(void);
  void setup_device(int lrespect_info);
  ea_t AdditionalSegment(size_t size, ea_t offset, const char *name) const;
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);
  void set_cpu(int n);
  void free_mappings(void);
  void add_mapping(ea_t from, ea_t to);
  ea_t map_port(ea_t from);
  void check_pclath(segment_t *s) const;

  bool build_macro(insn_t &insn, bool may_go_forward);
  void simplify(insn_t &insn) const;
  int basic_ana(insn_t &insn);
  int ana(insn_t *_insn);

  bool is_banked_reg(ea_t addr, int value) const;
  bool is_pcl(const insn_t &insn) const;
  bool is_bank(const insn_t &insn) const;
  bool is_pclath(const insn_t &insn) const;
  void process_immediate_number(const insn_t &insn, int n) const;
  void destroy_if_unnamed_array(ea_t ea) const;
  void propagate_sreg(const insn_t &insn, ea_t ea, int reg) const;
  void handle_operand(const insn_t &insn, const op_t &x, int, bool isload);
  void split(const insn_t &insn, int reg, sel_t v);
  bool is_load_tris_reg(const insn_t &insn);
  inline void set_plain_offset(ea_t insn_ea, int n, ea_t base) const;
  int emu(const insn_t &insn);
  bool create_func_frame(func_t *pfn) const;

  void pic_header(outctx_t &ctx);
  int out_equ(outctx_t &ctx);
  void out_equ(outctx_t &ctx, bool indent, const char *name, uval_t off);
  void pic_data(outctx_t &ctx, bool analyze_only);
  ea_t calc_data_mem(ea_t ea);
  bool conditional_insn(const insn_t &insn, flags64_t F) const; // may instruction be skipped?
  void print_segment_register(outctx_t &ctx, int reg, sel_t value);
  void pic_assumes(outctx_t &ctx);       // function to produce assume directives
  void pic_segstart(outctx_t &ctx, segment_t *Srange) const;
  void pic_footer(outctx_t &ctx) const;

  void load_from_idb();
};
extern int data_id;
#endif // _PIC_HPP

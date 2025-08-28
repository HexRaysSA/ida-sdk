
#ifndef _KR1878_HPP
#define _KR1878_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>

//------------------------------------------------------------------

#define amode     specflag2 // addressing mode
#define amode_x         0x10  // X:

//------------------------------------------------------------------
#define UAS_GNU 0x0001          // GNU assembler
//------------------------------------------------------------------
enum RegNo
{
  SR0,
  SR1,
  SR2,
  SR3,
  SR4,
  SR5,
  SR6,
  SR7,
  DSP,
  ISP,
  as,
  bs,
  cs,
  ds,
  vCS, vDS,       // virtual registers for code and data segments

};


//------------------------------------------------------------------

struct addargs_t
{
  ea_t ea;
  int nargs;
  op_t args[4][2];
};


//------------------------------------------------------------------
#define IDP_SIMPLIFY 0x0001     // simplify instructions
#define IDP_PSW_W    0x0002     // W-bit in PSW is set

extern ushort idpflags;

inline bool dosimple(void)      { return (idpflags & IDP_SIMPLIFY) != 0; }
inline bool psw_w(void)         { return (idpflags & IDP_PSW_W) != 0; }

ea_t calc_mem(const insn_t &insn, const op_t &x);

//------------------------------------------------------------------
void interr(const insn_t &insn, const char *module);

void idaapi kr1878_header(outctx_t &ctx);

void idaapi kr1878_segend(outctx_t &ctx, segment_t *seg);

int  idaapi is_align_insn(ea_t ea);
int  idaapi is_sp_based(const insn_t &insn, const op_t &x);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(const insn_t &insn, int nocrefs);
int may_be_func(const insn_t &insn);           // can a function start here?

void init_analyzer(void);

//------------------------------------------------------------------
struct kr1878_t : public procmod_t
{
  ioports_t ports;
  qstring device;
  netnode helper;
  ea_t xmem = BADADDR;
  op_t *op = nullptr;       // current operand
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const ioport_t *find_port(ea_t address);
  void read_kr1878_cfg(void);
  void set_device_name(const char *dev);
  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);

  ea_t calc_data_mem(const insn_t &insn, const op_t &x, ushort segreg) const;
  void handle_operand(const insn_t &insn, const op_t &x, bool isAlt, bool isload);
  void add_near_ref(const insn_t &insn, const op_t &x, ea_t ea);
  int emu(const insn_t &insn);

  void opreg(uint16 reg);
  void make_o_mem(const insn_t &insn);
  bool D_ddddd(const insn_t &, int value);
  bool S_ddddd(const insn_t &insn, int value);
  bool D_SR(const insn_t &, int value);
  bool S_SR(const insn_t &insn, int value);
  bool D_Imm(const insn_t &, int value);
  bool D_pImm(const insn_t &insn, int value);
  bool D_EA(const insn_t &insn, int value);
  bool use_table(const insn_t &insn, uint32 code, int entry, int start, int end);
  int ana(insn_t *_insn);

  void kr1878_assumes(outctx_t &ctx);
  void print_segment_register(outctx_t &ctx, int reg, sel_t value);
  void kr1878_segstart(outctx_t &ctx, segment_t *Srange) const;
  void kr1878_footer(outctx_t &ctx) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ kr1878"
#define PROCMOD_NAME kr1878
#endif // _KR1878_HPP

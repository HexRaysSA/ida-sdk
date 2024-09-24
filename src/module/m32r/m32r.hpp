
#ifndef _M32R_HPP
#define _M32R_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include "../iohandler.hpp"

#define PROCMOD_NAME            m32r
#define PROCMOD_NODE_NAME       "$ m32r"

// Flags for operand specflag1

#define NEXT_INSN_PARALLEL_NOP          0x0001     // next insn is a // nop
#define NEXT_INSN_PARALLEL_DSP          0x0002     // next insn is a // dsp
#define NEXT_INSN_PARALLEL_OTHER        0x0004       // next insn is an other // insn

#define SYNTHETIC_SHORT                 0x0010     // insn is synthetic short (ex bc.s)
#define SYNTHETIC_LONG                  0x0020     // insn is synthetic long (ex bc.l)

#define HAS_MSB                         0x0100     // insn _has_ its MSB to 1

// Synthetic instructions list:

/*
    m32r :

    bc.s label          bc label [8-bit offset]
    bc.l label          bc label [24-bit offset]
    bl.s label          bl label [8-bit offset]
    bl.l label          bl label [24-bit offset]
    bnc.s label         bnc label [8-bit offset]
    bnc.l label         bnc label [24-bit offset]
    bra.s label         bra label [8-bit offset]
    bra.l label         bra label [24-bit offset]
    ldi8 reg, #const    ldi reg, #const [8-bit constant]
    ldi16 reg, #const   ldi reg, #const [16-bit constant]
    push reg            st reg, @-sp
    pop reg             ld reg, @sp+

    m32rx :

    bcl.s label         bcl label [8 bit offset]
    bcl.l label         bcl label [24 bit offset]
    bncl.s label        bncl label [8 bit offset]
    bncl.l label        bncl label [24 bit offset]
*/

// Register aliases list:

/*
    m32r :

    r13         fp
    r14         lr
    r15         sp

    cr0         psw
    cr1         cbr
    cr2         spi
    cr3         spu
    cr6         bpc

    m32rx :

    cr8            bbpsw
    cr14        bbpc
*/

// define some shortcuts
#define rFP        rR13
#define rLR        rR14
#define rSP        rR15
#define rPSW       rCR0
#define rCBR       rCR1
#define rSPI       rCR2
#define rSPU       rCR3
#define rBPC       rCR6
#define rFPSR      rCR7

// m32rx only
#define rBBPSW    rCR8
#define rBBPC    rCR14

// m32r registers
enum m32r_registers
{
  // General-purpose registers
  rR0, rR1, rR2, rR3, rR4,
  rR5, rR6, rR7, rR8, rR9,
  rR10, rR11, rR12, rR13, rR14, rR15,

  // Control registers
  rCR0, rCR1, rCR2, rCR3, rCR6,

  // Program counter
  rPC,

  // m32rx special registers

  rA0, rA1,                                        // Accumulators
  rCR4, rCR5, rCR7, rCR8, rCR9,                    // Add. control registers
  rCR10, rCR11, rCR12, rCR13, rCR14, rCR15,

  rVcs, rVds    // these 2 registers are required by the IDA kernel
};

// m32r indirect addressing mode
enum m32r_phrases
{
  fRI,        // @R         Register indirect
  fRIBA,      // @R+        Register indirect update before add
  fRIAA,      // @+R        Register indirect update after add
  fRIAS       // @-R        Register indirect update after sub
};

// this module supports 2 processors: m32r and m32rx
enum processor_subtype_t
{
  prc_m32r = 0,
  prc_m32rx = 1
};

// exporting our routines
void idaapi m32r_footer(outctx_t &ctx);
void idaapi m32r_segstart(outctx_t &ctx, segment_t *seg);
int idaapi emu(const insn_t &insn);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi m32r_get_frame_retsize(const func_t *pfn);
int  idaapi is_sp_based(const insn_t &insn, const op_t &op);
bool idaapi can_have_type(const op_t &op);
int m32r_create_switch_xrefs(ea_t insn_ea, const switch_info_t &si);
int m32r_calc_switch_cases(casevec_t *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si);

//------------------------------------------------------------------
struct opcode;

struct m32r_iohandler_t : public iohandler_t
{
  struct m32r_t &pm;
  m32r_iohandler_t(m32r_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual void get_cfg_filename(char *buf, size_t bufsize) override;
};

struct m32r_t : public procmod_t
{
  // altval(-1) -> idpflags
  // supstr(-1) -> device
  netnode helper;
  m32r_iohandler_t ioh = m32r_iohandler_t(*this, helper);

#define IDP_SYNTHETIC   0x0001  // use synthetic instructions
#define IDP_REG_ALIASES 0x0002  // use register aliases
  uint32 idpflags = IDP_SYNTHETIC | IDP_REG_ALIASES;
  inline bool use_synthetic_insn(void) { return (idpflags & IDP_SYNTHETIC)   != 0; }
  inline bool use_reg_aliases(void)    { return (idpflags & IDP_REG_ALIASES) != 0; }

  // Current processor type (prc_m32r or prc_m32rx)
  processor_subtype_t ptype = prc_m32r;
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool idb_loaded);
  void handle_new_flags(bool save=true);
  const ioport_t *find_sym(ea_t address);

  int ana(insn_t *_insn);
  const opcode *get_opcode(int word) const;
  bool ana_special(insn_t &insn, int word, int *s) const;
  int parse_fp_insn(insn_t &insn, int word);

  void m32r_header(outctx_t &ctx);
  inline const char *ptype_str(void) const;

  void handle_operand(const insn_t &insn, const op_t &op, bool loading);
  int emu(const insn_t &insn);

  void save_idpflags() { helper.altset(-1, idpflags); }
  void load_from_idb();
};
extern int data_id;

#endif /* _M32R_HPP */

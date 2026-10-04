/*
 *      Interactive disassembler (IDA).
 *      Version 2.06
 *      Copyright (c) 1990-93 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef I5HPP
#define I5HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include "../iohandler.hpp"

//------------------------------------------------------------------
// debugger functions
typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

//------------------------------------------------------------------
// customization of insn_t structure:
#define o_cond  o_idpspec0

#define Cond    reg


//------------------------------------------------------------------
enum opcond_t          // condition code types
{
  oc_nz,
  oc_z,
  oc_nc,
  oc_c,
  oc_po,
  oc_pe,
  oc_p,
  oc_m,
  oc_not
};

//------------------------------------------------------------------
#define _PT_64180       0x01                    // HD64180
#define _PT_Z80         0x02                    // Z80
#define _PT_8085        0x04                    // Intel 8085
#define _PT_Z180        0x08                    // Z180
#define _PT_Z380        0x10                    // Z380
#define _PT_GB          0x20                    // GameBoy
#define _PT_EZ80        0x40                    // Zilog eZ80

#define PT_GB            _PT_GB
#define PT_EZ80          _PT_EZ80
#define PT_Z380          _PT_Z380
#define PT_Z180         ( PT_Z380 | _PT_Z180 | _PT_EZ80)
#define PT_64180        ( PT_Z180 | _PT_64180)
#define PT_Z80          ( PT_64180| _PT_Z80  | _PT_GB)
#define PT_8085         ( PT_Z80  | _PT_8085 )

extern int pflag;

enum RegNo ENUM_SIZE(uint16)
{
  R_b = 0,
  R_c = 1,
  R_d = 2,
  R_e = 3,
  R_h = 4,
  R_l = 5,
  R_a = 7,
  R_bc = 8,
  R_de = 9,
  R_hl = 10,
  R_af = 11,
  R_sp = 12,
  R_ix = 13,
  R_iy = 14,
  R_af2 = 15,
  R_r = 16,
  R_i = 17,
  R_f = 18,
  R_xl = 19,
  R_xh = 20,
  R_yl = 21,
  R_yh = 22,

  R_w,
  R_lw,
  R_ixl,
  R_ixu,
  R_dsr,
  R_xsr,
  R_iyl,
  R_iyu,
  R_ysr,
  R_sr,
  R_ib,
  R_iw,
  R_xm,
  R_lck,
  R_bc2,
  R_de2,
  R_hl2,
  R_ix2,
  R_iy2,
  R_b2,
  R_c2,
  R_d2,
  R_e2,
  R_h2,
  R_l2,
  R_m2,
  R_a2,

  R_vcs,            // virtual code segment register
  R_vds,            // virtual data segment register
  R_mb,             // eZ80: MBASE (upper address byte in Z80 mode)
  R_adl             // eZ80: virtual ADL mode flag (0=Z80 mode, 1=ADL mode)
};


//------------------------------------------------------------------
#define UAS_NOENS   0x0001              // I5: don't specify start addr in the .end directive
#define UAS_NPAIR   0x0002              // I5: pairs are denoted by 1 char ('b')
#define UAS_UNDOC   0x0004              // I5: does assembler support undoc-d instrs?
#define UAS_MKIMM   0x0008              // I5: place # in front of imm operand
#define UAS_MKOFF   0x0010              // I5: offset(ix) form
#define UAS_CNDUP   0x0020              // I5: conditions UPPERCASE
#define UAS_FUNNY   0x0040              // I5: special for A80
#define UAS_CSEGS   0x0080              // I5: generate 'cseg' directives
#define UAS_TOFF    0x0100              // I5: (ix+-10)
#define UAS_ZMASM   0x0200              // ZMASM
#define UAS_GBASM   0x0400              // RGBASM


#define aux_off16   0x0001              // o_displ: off16

// eZ80 memory mode suffix (insn.auxpref bits 1..3)
#define aux_sfx_shift 1
#define aux_sfx_mask  (7 << aux_sfx_shift)
enum ez80_sfx_t                         // values of the aux_sfx field
{
  SFX_NONE = 0,
  SFX_SIS,                              // .sis: 16-bit data, 16-bit imm/addr
  SFX_LIS,                              // .lis: 24-bit data, 16-bit imm/addr
  SFX_SIL,                              // .sil: 16-bit data, 24-bit imm/addr
  SFX_LIL,                              // .lil: 24-bit data, 24-bit imm/addr
};

inline ez80_sfx_t get_sfx(const insn_t &insn)
{
  return ez80_sfx_t((insn.auxpref & aux_sfx_mask) >> aux_sfx_shift);
}

//------------------------------------------------------------------
struct z80_iohandler_t : public iohandler_t
{
  z80_iohandler_t(netnode &nn) : iohandler_t(nn) {}
};

struct insndesc_t;
struct z80_t : public procmod_t
{
  netnode helper;
  z80_iohandler_t ioh = z80_iohandler_t(helper);

  int pflag = 0;
  int code;

  uchar saved_value = 0;
  bool flow = false;
  bool isx = false;

  // eZ80 decode state, valid during ana of one instruction
  bool ez_adl = false;  // current ADL mode (from the virtual 'adl' sreg)
  bool ez_il = false;   // fetch 24-bit immediates/addresses (instruction stream long)
  bool ez_l = false;    // 24-bit data block operation (register/memory width)

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *find_ioport(uval_t port);
  const char *find_ioport_bit(int port, int bit);
  void choose_device(int respinfo);

  void set_cpu(int np);
  void load_from_idb();

  const char *set_idp_options(const char *keyword, int /*value_type*/, const void * /*value*/, bool /*idb_loaded*/);

  // out.cpp
  inline bool isFunny(void) { return (ash.uflag & UAS_FUNNY) != 0; }
  void i5_header(outctx_t &ctx);
  void i5_footer(outctx_t &ctx);
  void i5_segstart(outctx_t &ctx, ea_t seg_ea);

  // ana.cpp
  int  i5_ana(insn_t *_insn);
  void load_z80_operand(insn_t &insn, op_t &x, uchar op);
  bool search_map(insn_t &insn, const insndesc_t *map, uchar _code);
  bool z380_insns(insn_t &insn, const insndesc_t *map, const insndesc_t *cb);
  bool z380_ED(insn_t &insn);
  void z80_ixcommands(insn_t &insn, bool _isx);
  void z80_misc(insn_t &insn);
  void ConvertToZ80(insn_t &insn);
  void op_r1(op_t &x) const;
  void op_r2(op_t &x) const;
  void op_ss(op_t &x) const;
  void op_dd(op_t &x) const;
  void op_xdispl(insn_t &insn, op_t &x) const;
  void op_ix(op_t &x) const;
  void op_ibyte(op_t &x, int low) const;
  int op_xbytereg(op_t &x, uint16 mode) const;
  int op_xr1(op_t &x) const;
  int op_xr2(op_t &x) const;
  uval_t get_next_mword(insn_t &insn) const;
  void op_ad(insn_t &insn, op_t &x) const;
  void op_nn(insn_t &insn, op_t &x) const;
  void op_mm(insn_t &insn, op_t &x) const;
  void op_e(insn_t &insn, op_t &x) const;
  inline bool isGB(void);
  inline bool isZ380(void);
  inline bool isZ180(void);
  inline bool isZ80(void);
  inline bool is64180(void);
  inline bool is8085(void);
  inline bool isEZ80(void) const;

  // emu.cpp
  int  i5_emu(const insn_t &insn);
  void load_operand(const insn_t &insn, const op_t &x);
  void save_operand(const insn_t &insn, const op_t &x) const;
  ea_t ez80_map_data_ea(const insn_t &insn, const op_t &x) const;
  sval_t named_regval(const char *regname, getreg_t *getreg, const regval_t *rv);
  sval_t regval(const op_t &op, getreg_t *getreg, const regval_t *rv);
  bool check_cond(uint16_t cc, getreg_t *getreg, const regval_t *regvalues);
  ea_t next_exec_insn(
        ea_t ea,
        getreg_t *getreg,
        const regval_t *regvalues);
  ea_t calc_step_over(ea_t ip) const;
  bool get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        getreg_t *getreg,
        const regval_t *regvalues);
  bool get_reg_info(
        const char **main_regname,
        bitrange_t *bitrange,
        const char *regname);
};

extern int data_id;
#define PROCMOD_NAME            z80
#define PROCMOD_NODE_NAME       "$ " QSTRINGIZE(PROCMOD_NAME)


inline bool z80_t::isGB(void)    { return (pflag & PT_GB)    != 0; }
inline bool z80_t::isZ380(void)  { return (pflag & PT_Z380)  != 0; }
inline bool z80_t::isZ180(void)  { return (pflag & PT_Z180)  != 0; }
inline bool z80_t::isZ80(void)   { return (pflag & PT_Z80)   != 0; }
inline bool z80_t::is64180(void) { return (pflag & PT_64180) != 0; }
inline bool z80_t::is8085(void)  { return !isZ80();                }
inline bool z80_t::isEZ80(void) const { return (pflag & PT_EZ80) != 0; }

#endif // I5HPP

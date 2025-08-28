
#ifndef __ST9_HPP
#define __ST9_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include <segregs.hpp>
#include "../iohandler.hpp"

#define PROCMOD_NAME            st9
#define PROCMOD_NODE_NAME       "$ st9"

// Operand flags
#define OP_IS_IND           0x00000001      // Operand is indirect, and should be
                                            // printed between ().
#define OP_IMM_NO_SHIFT     0x00000002      // Operand is immediate, and should not
                                            // be prefixed by the '#' character.
#define OP_REG_WITH_BIT     0x00000004      // Operand is register, and a bit number can be
                                            // found in the "value" field.
#define OP_BIT_COMPL        0x00000008      // Bit number is a complement, and should be
                                            // prefixed by the '!' character.
#define OP_DISPL_FUNC_ARG   0x00000010      // Operand is a displacement, and should be considered
                                            // as a function argument variable.
// Flags for ash.uFlag
#define UAS_ASW             0x00000001      // current assembler is ASW.

inline bool is_ind(const op_t &op)
{
  return (op.specflag1 & OP_IS_IND) != 0;
}

inline bool is_imm_no_shift(const op_t &op)
{
  return op.type == o_imm && (op.specflag1 & OP_IMM_NO_SHIFT) != 0;
}

inline bool is_reg_with_bit(const op_t &op)
{
  return op.type == o_reg && (op.specflag1 & OP_REG_WITH_BIT) != 0;
}

inline bool is_bit_compl(const op_t &op)
{
  return (op.specflag1 & OP_BIT_COMPL) != 0;
}

// ST9+ registers :
enum st9_registers
{
  rR0,
  rR1,
  rR2,
  rR3,
  rR4,
  rR5,
  rR6,
  rR7,
  rR8,
  rR9,
  rR10,
  rR11,
  rR12,
  rR13,
  rR14,
  rR15,
  rR16,
  rR17,
  rR18,
  rR19,
  rR20,
  rR21,
  rR22,
  rR23,
  rR24,
  rR25,
  rR26,
  rR27,
  rR28,
  rR29,
  rR30,
  rR31,
  rR32,
  rR33,
  rR34,
  rR35,
  rR36,
  rR37,
  rR38,
  rR39,
  rR40,
  rR41,
  rR42,
  rR43,
  rR44,
  rR45,
  rR46,
  rR47,
  rR48,
  rR49,
  rR50,
  rR51,
  rR52,
  rR53,
  rR54,
  rR55,
  rR56,
  rR57,
  rR58,
  rR59,
  rR60,
  rR61,
  rR62,
  rR63,
  rR64,
  rR65,
  rR66,
  rR67,
  rR68,
  rR69,
  rR70,
  rR71,
  rR72,
  rR73,
  rR74,
  rR75,
  rR76,
  rR77,
  rR78,
  rR79,
  rR80,
  rR81,
  rR82,
  rR83,
  rR84,
  rR85,
  rR86,
  rR87,
  rR88,
  rR89,
  rR90,
  rR91,
  rR92,
  rR93,
  rR94,
  rR95,
  rR96,
  rR97,
  rR98,
  rR99,
  rR100,
  rR101,
  rR102,
  rR103,
  rR104,
  rR105,
  rR106,
  rR107,
  rR108,
  rR109,
  rR110,
  rR111,
  rR112,
  rR113,
  rR114,
  rR115,
  rR116,
  rR117,
  rR118,
  rR119,
  rR120,
  rR121,
  rR122,
  rR123,
  rR124,
  rR125,
  rR126,
  rR127,
  rR128,
  rR129,
  rR130,
  rR131,
  rR132,
  rR133,
  rR134,
  rR135,
  rR136,
  rR137,
  rR138,
  rR139,
  rR140,
  rR141,
  rR142,
  rR143,
  rR144,
  rR145,
  rR146,
  rR147,
  rR148,
  rR149,
  rR150,
  rR151,
  rR152,
  rR153,
  rR154,
  rR155,
  rR156,
  rR157,
  rR158,
  rR159,
  rR160,
  rR161,
  rR162,
  rR163,
  rR164,
  rR165,
  rR166,
  rR167,
  rR168,
  rR169,
  rR170,
  rR171,
  rR172,
  rR173,
  rR174,
  rR175,
  rR176,
  rR177,
  rR178,
  rR179,
  rR180,
  rR181,
  rR182,
  rR183,
  rR184,
  rR185,
  rR186,
  rR187,
  rR188,
  rR189,
  rR190,
  rR191,
  rR192,
  rR193,
  rR194,
  rR195,
  rR196,
  rR197,
  rR198,
  rR199,
  rR200,
  rR201,
  rR202,
  rR203,
  rR204,
  rR205,
  rR206,
  rR207,
  rR208,
  rR209,
  rR210,
  rR211,
  rR212,
  rR213,
  rR214,
  rR215,
  rR216,
  rR217,
  rR218,
  rR219,
  rR220,
  rR221,
  rR222,
  rR223,
  rR224,
  rR225,
  rR226,
  rR227,
  rR228,
  rR229,
  rR230,
  rR231,
  rR232,
  rR233,
  rR234,
  rR235,
  rR236,
  rR237,
  rR238,
  rR239,
  rR240,
  rR241,
  rR242,
  rR243,
  rR244,
  rR245,
  rR246,
  rR247,
  rR248,
  rR249,
  rR250,
  rR251,
  rR252,
  rR253,
  rR254,
  rR255,
  rRR0,
  rRR1,
  rRR2,
  rRR3,
  rRR4,
  rRR5,
  rRR6,
  rRR7,
  rRR8,
  rRR9,
  rRR10,
  rRR11,
  rRR12,
  rRR13,
  rRR14,
  rRR15,
  rRR16,
  rRR17,
  rRR18,
  rRR19,
  rRR20,
  rRR21,
  rRR22,
  rRR23,
  rRR24,
  rRR25,
  rRR26,
  rRR27,
  rRR28,
  rRR29,
  rRR30,
  rRR31,
  rRR32,
  rRR33,
  rRR34,
  rRR35,
  rRR36,
  rRR37,
  rRR38,
  rRR39,
  rRR40,
  rRR41,
  rRR42,
  rRR43,
  rRR44,
  rRR45,
  rRR46,
  rRR47,
  rRR48,
  rRR49,
  rRR50,
  rRR51,
  rRR52,
  rRR53,
  rRR54,
  rRR55,
  rRR56,
  rRR57,
  rRR58,
  rRR59,
  rRR60,
  rRR61,
  rRR62,
  rRR63,
  rRR64,
  rRR65,
  rRR66,
  rRR67,
  rRR68,
  rRR69,
  rRR70,
  rRR71,
  rRR72,
  rRR73,
  rRR74,
  rRR75,
  rRR76,
  rRR77,
  rRR78,
  rRR79,
  rRR80,
  rRR81,
  rRR82,
  rRR83,
  rRR84,
  rRR85,
  rRR86,
  rRR87,
  rRR88,
  rRR89,
  rRR90,
  rRR91,
  rRR92,
  rRR93,
  rRR94,
  rRR95,
  rRR96,
  rRR97,
  rRR98,
  rRR99,
  rRR100,
  rRR101,
  rRR102,
  rRR103,
  rRR104,
  rRR105,
  rRR106,
  rRR107,
  rRR108,
  rRR109,
  rRR110,
  rRR111,
  rRR112,
  rRR113,
  rRR114,
  rRR115,
  rRR116,
  rRR117,
  rRR118,
  rRR119,
  rRR120,
  rRR121,
  rRR122,
  rRR123,
  rRR124,
  rRR125,
  rRR126,
  rRR127,
  rRR128,
  rRR129,
  rRR130,
  rRR131,
  rRR132,
  rRR133,
  rRR134,
  rRR135,
  rRR136,
  rRR137,
  rRR138,
  rRR139,
  rRR140,
  rRR141,
  rRR142,
  rRR143,
  rRR144,
  rRR145,
  rRR146,
  rRR147,
  rRR148,
  rRR149,
  rRR150,
  rRR151,
  rRR152,
  rRR153,
  rRR154,
  rRR155,
  rRR156,
  rRR157,
  rRR158,
  rRR159,
  rRR160,
  rRR161,
  rRR162,
  rRR163,
  rRR164,
  rRR165,
  rRR166,
  rRR167,
  rRR168,
  rRR169,
  rRR170,
  rRR171,
  rRR172,
  rRR173,
  rRR174,
  rRR175,
  rRR176,
  rRR177,
  rRR178,
  rRR179,
  rRR180,
  rRR181,
  rRR182,
  rRR183,
  rRR184,
  rRR185,
  rRR186,
  rRR187,
  rRR188,
  rRR189,
  rRR190,
  rRR191,
  rRR192,
  rRR193,
  rRR194,
  rRR195,
  rRR196,
  rRR197,
  rRR198,
  rRR199,
  rRR200,
  rRR201,
  rRR202,
  rRR203,
  rRR204,
  rRR205,
  rRR206,
  rRR207,
  rRR208,
  rRR209,
  rRR210,
  rRR211,
  rRR212,
  rRR213,
  rRR214,
  rRR215,
  rRR216,
  rRR217,
  rRR218,
  rRR219,
  rRR220,
  rRR221,
  rRR222,
  rRR223,
  rRR224,
  rRR225,
  rRR226,
  rRR227,
  rRR228,
  rRR229,
  rRR230,
  rRR231,
  rRR232,
  rRR233,
  rRR234,
  rRR235,
  rRR236,
  rRR237,
  rRR238,
  rRR239,
  rRR240,
  rRR241,
  rRR242,
  rRR243,
  rRR244,
  rRR245,
  rRR246,
  rRR247,
  rRR248,
  rRR249,
  rRR250,
  rRR251,
  rRR252,
  rRR253,
  rRR254,
  rRR255,
  rr0,
  rr1,
  rr2,
  rr3,
  rr4,
  rr5,
  rr6,
  rr7,
  rr8,
  rr9,
  rr10,
  rr11,
  rr12,
  rr13,
  rr14,
  rr15,
  rrr0,
  rrr1,
  rrr2,
  rrr3,
  rrr4,
  rrr5,
  rrr6,
  rrr7,
  rrr8,
  rrr9,
  rrr10,
  rrr11,
  rrr12,
  rrr13,
  rrr14,
  rrr15,
  rRW,            // register window number
  rRP,            // register page
  rCSR,           // code segment register
  rDPR0, rDPR1, rDPR2, rDPR3, // Data page registers
  st9_lastreg = rDPR3,
};

// ST9 condition codes
enum st9_cond_codes
{
  cUNKNOWN,
  cF,         // always false
  cT,         // always true
  cC,         // carry
  cNC,        // not carry
  cZ,         // zero
  cNZ,        // not zero
  cPL,        // plus
  cMI,        // minus
  cOV,        // overflow
  cNOV,       // no overflow
  cEQ,        // equal
  cNE,        // not equal
  cGE,        // greater than or equal
  cLT,        // less than
  cGT,        // greater than
  cLE,        // less than or equal
  cUGE,       // unsigned greated than or equal
  cUL,        // unsigned less than
  cUGT,       // unsigned greater than
  cULE        // unsigned less than or equal
};

enum st9_phrases ENUM_SIZE(uint8)
{
  fPI,        // post incrementation      (rr)+
  fPD,        // pre decrementation       -(rr)
  fDISP       // displacement             rrx(rry)
};

inline bool is_jmp_cc(int insn)
{
  return insn == st9_jpcc || insn == st9_jrcc;
}

//------------------------------------------------------------------
struct st9_iohandler_t : public iohandler_t
{
  struct st9_t &pm;
  st9_iohandler_t(st9_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
};

struct st9_t : public procmod_t
{
  // The netnode helper.
  // Using this node we will save current configuration information in the
  // IDA database.
  netnode helper;
  st9_iohandler_t ioh = st9_iohandler_t(*this, helper);

  const char *RegNames[st9_lastreg + 1];
  qstrvec_t dynamic_rgnames; // dynamically generated names for rR1..rR255

  const char *gr_cmt = nullptr;
  int ref_dpr_id;  // id of refinfo handler
#define IDP_GR_DEC 0x0001 // print general registers in decimal format
#define IDP_GR_HEX 0x0002 // print general registers in hexadecimal format
#define IDP_GR_BIN 0x0004 // print general registers in binary format
  uint32 idpflags = IDP_GR_DEC;
  ushort print_style = 3;
  bool flow;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const ioport_t *find_sym(ea_t address);
  void patch_general_registers();
  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool idb_loaded);

  int st9_emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &op, bool lwrite);
  bool create_func_frame(func_t *pfn) const;

  void st9_assumes(outctx_t &ctx);
  void st9_footer(outctx_t &ctx) const;
  void st9_segstart(outctx_t &ctx, segment_t *Sarea) const;

  void save_idpflags() { helper.altset(-1, idpflags); }
  void load_from_idb();
};
extern int data_id;

// exporting our routines
void idaapi st9_header(outctx_t &ctx);
int idaapi st9_ana(insn_t *insn);
ea_t get_dest_addr(const insn_t &insn, const op_t &x);
bool st9_is_switch(switch_info_t *si, const insn_t &insn);

extern const char *const ConditionCodes[];

#endif /* __ST9_HPP */

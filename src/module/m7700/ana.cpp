
#include "m7700.hpp"

// 7700 operation codes :
struct opcode
{
  uint16 insn;                        // instruction
  uint16 code;                        // code of opcode
  m7700_addr_mode_t mode;             // addressing mode
};

// 7700 instructions
static const struct opcode opcodes_7700[] =
{
  // ADC
  { m7700_adc,       0x69,   A_IMM                           },
  { m7700_adc,       0x65,   A_DIR                           },
  { m7700_adc,       0x75,   A_DIR_IND_X                     },
  { m7700_adc,       0x72,   A_DIR_INDI                      },
  { m7700_adc,       0x61,   A_DIR_IND_X_INDI                },
  { m7700_adc,       0x71,   A_DIR_INDI_IND_Y                },
  { m7700_adc,       0x67,   A_DIR_INDI_LONG                 },
  { m7700_adc,       0x77,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_adc,       0x6D,   A_ABS                           },
  { m7700_adc,       0x7D,   A_ABS_IND_X                     },
  { m7700_adc,       0x79,   A_ABS_IND_Y                     },
  { m7700_adc,       0x6F,   A_ABS_LONG                      },
  { m7700_adc,       0x7F,   A_ABS_LONG_IND_X                },
  { m7700_adc,       0x63,   A_STACK_PTR_REL                 },
  { m7700_adc,       0x73,   A_STACK_PTR_REL_IIY             },
  // AND
  { m7700_and,       0x29,   A_IMM                           },
  { m7700_and,       0x25,   A_DIR                           },
  { m7700_and,       0x35,   A_DIR_IND_X                     },
  { m7700_and,       0x32,   A_DIR_INDI                      },
  { m7700_and,       0x21,   A_DIR_IND_X_INDI                },
  { m7700_and,       0x31,   A_DIR_INDI_IND_Y                },
  { m7700_and,       0x27,   A_DIR_INDI_LONG                 },
  { m7700_and,       0x37,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_and,       0x2D,   A_ABS                           },
  { m7700_and,       0x3D,   A_ABS_IND_X                     },
  { m7700_and,       0x39,   A_ABS_IND_Y                     },
  { m7700_and,       0x2F,   A_ABS_LONG                      },
  { m7700_and,       0x3F,   A_ABS_LONG_IND_X                },
  { m7700_and,       0x23,   A_STACK_PTR_REL                 },
  { m7700_and,       0x33,   A_STACK_PTR_REL_IIY             },
  // ASL
  { m7700_asl,       0x0A,   A_ACC_A                         },
  { m7700_asl,       0x420A, A_ACC_B                         },
  { m7700_asl,       0x06,   A_DIR                           },
  { m7700_asl,       0x16,   A_DIR_IND_X                     },
  { m7700_asl,       0x0E,   A_ABS                           },
  { m7700_asl,       0x1E,   A_ABS_IND_X                     },
  // BBC
  { m7700_bbc,       0x34,   A_DIR_BIT_REL                   },
  { m7700_bbc,       0x3C,   A_ABS_BIT_REL                   },
  // BBS
  { m7700_bbs,       0x24,   A_DIR_BIT_REL                   },
  { m7700_bbs,       0x2C,   A_ABS_BIT_REL                   },
  // BCC
  { m7700_bcc,       0x90,   A_REL                           },
  // BCS
  { m7700_bcs,       0xB0,   A_REL                           },
  // BEQ
  { m7700_beq,       0xF0,   A_REL                           },
  // BMI
  { m7700_bmi,       0x30,   A_REL                           },
  // BNE
  { m7700_bne,       0xD0,   A_REL                           },
  // BPL
  { m7700_bpl,       0x10,   A_REL                           },
  // BRA
  { m7700_bra,       0x80,   A_REL                           },
  { m7700_bra,       0x82,   A_REL_LONG                      },
#if 0 /* detected as a special insn */
  // BRK
  { m7700_brk,       0x00EA, A_IMPL                          },
#endif
  // BVC
  { m7700_bvc,       0x50,   A_REL                           },
  // BVS
  { m7700_bvs,       0x70,   A_REL                           },
  // CLB
  { m7700_clb,       0x14,   A_DIR_BIT                       },
  { m7700_clb,       0x1C,   A_ABS_BIT                       },
  // CLC
  { m7700_clc,       0x18,   A_IMPL                          },
  // CLI
  { m7700_cli,       0x58,   A_IMPL                          },
  // CLM
  { m7700_clm,       0xD8,   A_IMPL                          },
  // CLP
  { m7700_clp,       0xC2,   A_IMM                           },
  // CLV
  { m7700_clv,       0xB8,   A_IMPL                          },
  // CMP
  { m7700_cmp,       0xC9,   A_IMM                           },
  { m7700_cmp,       0xC5,   A_DIR                           },
  { m7700_cmp,       0xD5,   A_DIR_IND_X                     },
  { m7700_cmp,       0xD2,   A_DIR_INDI                      },
  { m7700_cmp,       0xC1,   A_DIR_IND_X_INDI                },
  { m7700_cmp,       0xD1,   A_DIR_INDI_IND_Y                },
  { m7700_cmp,       0xC7,   A_DIR_INDI_LONG                 },
  { m7700_cmp,       0xD7,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_cmp,       0xCD,   A_ABS                           },
  { m7700_cmp,       0xDD,   A_ABS_IND_X                     },
  { m7700_cmp,       0xD9,   A_ABS_IND_Y                     },
  { m7700_cmp,       0xCF,   A_ABS_LONG                      },
  { m7700_cmp,       0xDF,   A_ABS_LONG_IND_X                },
  { m7700_cmp,       0xC3,   A_STACK_PTR_REL                 },
  { m7700_cmp,       0xD3,   A_STACK_PTR_REL_IIY             },
  // CPX
  { m7700_cpx,       0xE0,   A_IMM                           },
  { m7700_cpx,       0xE4,   A_DIR                           },
  { m7700_cpx,       0xEC,   A_ABS                           },
  // CPY
  { m7700_cpy,       0xC0,   A_IMM                           },
  { m7700_cpy,       0xC4,   A_DIR                           },
  { m7700_cpy,       0xCC,   A_ABS                           },
  // DEC
  { m7700_dec,       0x1A,   A_ACC_A                         },
  { m7700_dec,       0x421A, A_ACC_B                         },
  { m7700_dec,       0xC6,   A_DIR                           },
  { m7700_dec,       0xD6,   A_DIR_IND_X                     },
  { m7700_dec,       0xCE,   A_ABS                           },
  { m7700_dec,       0xDE,   A_ABS_IND_X                     },
  // DEX
  { m7700_dex,       0xCA,   A_IMPL                          },
  // DEY
  { m7700_dey,       0x88,   A_IMPL                          },
  // DIV
  { m7700_div,       0x8929, A_IMM                           },
  { m7700_div,       0x8925, A_DIR                           },
  { m7700_div,       0x8935, A_DIR_IND_X                     },
  { m7700_div,       0x8932, A_DIR_INDI                      },
  { m7700_div,       0x8921, A_DIR_IND_X_INDI                },
  { m7700_div,       0x8931, A_DIR_INDI_IND_Y                },
  { m7700_div,       0x8927, A_DIR_INDI_LONG                 },
  { m7700_div,       0x8937, A_DIR_INDI_LONG_IND_Y           },
  { m7700_div,       0x892D, A_ABS                           },
  { m7700_div,       0x893D, A_ABS_IND_X                     },
  { m7700_div,       0x8939, A_ABS_IND_Y                     },
  { m7700_div,       0x892F, A_ABS_LONG                      },
  { m7700_div,       0x893F, A_ABS_LONG_IND_X                },
  { m7700_div,       0x8923, A_STACK_PTR_REL                 },
  { m7700_div,       0x8933, A_STACK_PTR_REL_IIY             },
  // EOR
  { m7700_eor,       0x49,   A_IMM                           },
  { m7700_eor,       0x45,   A_DIR                           },
  { m7700_eor,       0x55,   A_DIR_IND_X                     },
  { m7700_eor,       0x52,   A_DIR_INDI                      },
  { m7700_eor,       0x41,   A_DIR_IND_X_INDI                },
  { m7700_eor,       0x51,   A_DIR_INDI_IND_Y                },
  { m7700_eor,       0x47,   A_DIR_INDI_LONG                 },
  { m7700_eor,       0x57,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_eor,       0x4D,   A_ABS                           },
  { m7700_eor,       0x5D,   A_ABS_IND_X                     },
  { m7700_eor,       0x59,   A_ABS_IND_Y                     },
  { m7700_eor,       0x4F,   A_ABS_LONG                      },
  { m7700_eor,       0x5F,   A_ABS_LONG_IND_X                },
  { m7700_eor,       0x43,   A_STACK_PTR_REL                 },
  { m7700_eor,       0x53,   A_STACK_PTR_REL_IIY             },
  // INC
  { m7700_inc,       0x3A,   A_ACC_A                         },
  { m7700_inc,       0x423A, A_ACC_B                         },
  { m7700_inc,       0xE6,   A_DIR                           },
  { m7700_inc,       0xF6,   A_DIR_IND_X                     },
  { m7700_inc,       0xEE,   A_ABS                           },
  { m7700_inc,       0xFE,   A_ABS_IND_X                     },
  // INX
  { m7700_inx,       0xE8,   A_IMPL                          },
  // INY
  { m7700_iny,       0xC8,   A_IMPL                          },
  // JMP
  { m7700_jmp,       0x4C,   A_ABS                           },
  { m7700_jmp,       0x5C,   A_ABS_LONG                      },
  { m7700_jmp,       0x6C,   A_ABS_INDI                      },
  { m7700_jmp,       0xDC,   A_ABS_INDI_LONG                 },
  { m7700_jmp,       0x7C,   A_ABS_IND_X_INDI                },
  // JSR
  { m7700_jsr,       0x20,   A_ABS                           },
  { m7700_jsr,       0x22,   A_ABS_LONG                      },
  { m7700_jsr,       0xFC,   A_ABS_IND_X_INDI                },
  // LDA
  { m7700_lda,       0xA9,   A_IMM                           },
  { m7700_lda,       0xA5,   A_DIR                           },
  { m7700_lda,       0xB5,   A_DIR_IND_X                     },
  { m7700_lda,       0xB2,   A_DIR_INDI                      },
  { m7700_lda,       0xA1,   A_DIR_IND_X_INDI                },
  { m7700_lda,       0xB1,   A_DIR_INDI_IND_Y                },
  { m7700_lda,       0xA7,   A_DIR_INDI_LONG                 },
  { m7700_lda,       0xB7,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_lda,       0xAD,   A_ABS                           },
  { m7700_lda,       0xBD,   A_ABS_IND_X                     },
  { m7700_lda,       0xB9,   A_ABS_IND_Y                     },
  { m7700_lda,       0xAF,   A_ABS_LONG                      },
  { m7700_lda,       0xBF,   A_ABS_LONG_IND_X                },
  { m7700_lda,       0xA3,   A_STACK_PTR_REL                 },
  { m7700_lda,       0xB3,   A_STACK_PTR_REL_IIY             },
  // LDM
  { m7700_ldm,       0x64,   A_DIR                           },
  { m7700_ldm,       0x74,   A_DIR_IND_X                     },
  { m7700_ldm,       0x9C,   A_ABS                           },
  { m7700_ldm,       0x9E,   A_ABS_IND_X                     },
  // LDT
  { m7700_ldt,       0x89C2, A_IMM                           },
  // LDX
  { m7700_ldx,       0xA2,   A_IMM                           },
  { m7700_ldx,       0xA6,   A_DIR                           },
  { m7700_ldx,       0xB6,   A_DIR_IND_Y                     },
  { m7700_ldx,       0xAE,   A_ABS                           },
  { m7700_ldx,       0xBE,   A_ABS_IND_Y                     },
  // LDY
  { m7700_ldy,       0xA0,   A_IMM                           },
  { m7700_ldy,       0xA4,   A_DIR                           },
  { m7700_ldy,       0xB4,   A_DIR_IND_X                     },
  { m7700_ldy,       0xAC,   A_ABS                           },
  { m7700_ldy,       0xBC,   A_ABS_IND_X                     },
  // LSR
  { m7700_lsr,       0x4A,   A_ACC_A                         },
  { m7700_lsr,       0x424A, A_ACC_B                         },
  { m7700_lsr,       0x46,   A_DIR                           },
  { m7700_lsr,       0x56,   A_DIR_IND_X                     },
  { m7700_lsr,       0x4E,   A_ABS                           },
  { m7700_lsr,       0x5E,   A_ABS_IND_X                     },
  // MPY
  { m7700_mpy,       0x8909, A_IMM                           },
  { m7700_mpy,       0x8905, A_DIR                           },
  { m7700_mpy,       0x8915, A_DIR_IND_X                     },
  { m7700_mpy,       0x8912, A_DIR_INDI                      },
  { m7700_mpy,       0x8901, A_DIR_IND_X_INDI                },
  { m7700_mpy,       0x8911, A_DIR_INDI_IND_Y                },
  { m7700_mpy,       0x8907, A_DIR_INDI_LONG                 },
  { m7700_mpy,       0x8917, A_DIR_INDI_LONG_IND_Y           },
  { m7700_mpy,       0x890D, A_ABS                           },
  { m7700_mpy,       0x891D, A_ABS_IND_X                     },
  { m7700_mpy,       0x8919, A_ABS_IND_Y                     },
  { m7700_mpy,       0x890F, A_ABS_LONG                      },
  { m7700_mpy,       0x891F, A_ABS_LONG_IND_X                },
  { m7700_mpy,       0x8903, A_STACK_PTR_REL                 },
  { m7700_mpy,       0x8913, A_STACK_PTR_REL_IIY             },
  // MVN
  { m7700_mvn,       0x54,   A_BT                            },
  // MVP
  { m7700_mvp,       0x44,   A_BT                            },
  // NOP
  { m7700_nop,       0xEA,   A_IMPL                          },
  // ORA
  { m7700_ora,       0x09,   A_IMM                           },
  { m7700_ora,       0x05,   A_DIR                           },
  { m7700_ora,       0x15,   A_DIR_IND_X                     },
  { m7700_ora,       0x12,   A_DIR_INDI                      },
  { m7700_ora,       0x01,   A_DIR_IND_X_INDI                },
  { m7700_ora,       0x11,   A_DIR_INDI_IND_Y                },
  { m7700_ora,       0x07,   A_DIR_INDI_LONG                 },
  { m7700_ora,       0x17,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_ora,       0x0D,   A_ABS                           },
  { m7700_ora,       0x1D,   A_ABS_IND_X                     },
  { m7700_ora,       0x19,   A_ABS_IND_Y                     },
  { m7700_ora,       0x0F,   A_ABS_LONG                      },
  { m7700_ora,       0x1F,   A_ABS_LONG_IND_X                },
  { m7700_ora,       0x03,   A_STACK_PTR_REL                 },
  { m7700_ora,       0x13,   A_STACK_PTR_REL_IIY             },
  // PEA
  { m7700_pea,       0xF4,   A_STACK_L                       },
  // PEI
  { m7700_pei,       0xD4,   A_STACK_S                       },
  // PER
  { m7700_per,       0x62,   A_STACK_L                       },
  // PHA
  { m7700_pha,       0x48,   A_STACK                         },
  // PHB
  { m7700_phb,       0x4248, A_STACK                         },
  // PHD
  { m7700_phd,       0x0B,   A_STACK                         },
  // PHG
  { m7700_phg,       0x4B,   A_STACK                         },
  // PHP
  { m7700_php,       0x08,   A_STACK                         },
  // PHT
  { m7700_pht,       0x8B,   A_STACK                         },
  // PHX
  { m7700_phx,       0xDA,   A_STACK                         },
  // PHY
  { m7700_phy,       0x5A,   A_STACK                         },
  // PLA
  { m7700_pla,       0x68,   A_STACK                         },
  // PLB
  { m7700_plb,       0x4268, A_STACK                         },
  // PLD
  { m7700_pld,       0x2B,   A_STACK                         },
  // PLP
  { m7700_plp,       0x28,   A_STACK                         },
  // PLT
  { m7700_plt,       0xAB,   A_STACK                         },
  // PLX
  { m7700_plx,       0xFA,   A_STACK                         },
  // PLY
  { m7700_ply,       0x7A,   A_STACK                         },
  // PSH
  { m7700_psh,       0xEB,   A_STACK_S                       },
  // PUL
  { m7700_pul,       0xFB,   A_STACK_S                       },
  // RLA
  { m7700_rla,       0x8949, A_IMM                           },
  // ROL
  { m7700_rol,       0x2A,   A_ACC_A                         },
  { m7700_rol,       0x422A, A_ACC_B                         },
  { m7700_rol,       0x26,   A_DIR                           },
  { m7700_rol,       0x36,   A_DIR_IND_X                     },
  { m7700_rol,       0x2E,   A_ABS                           },
  { m7700_rol,       0x3E,   A_ABS_IND_X                     },
  // ROR
  { m7700_ror,       0x6A,   A_ACC_A                         },
  { m7700_ror,       0x426A, A_ACC_B                         },
  { m7700_ror,       0x66,   A_DIR                           },
  { m7700_ror,       0x76,   A_DIR_IND_X                     },
  { m7700_ror,       0x6E,   A_ABS                           },
  { m7700_ror,       0x7E,   A_ABS_IND_X                     },
  // RTI
  { m7700_rti,       0x40,   A_IMPL                          },
  // RTL
  { m7700_rtl,       0x6B,   A_IMPL                          },
  // RTS
  { m7700_rts,       0x60,   A_IMPL                          },
  // SBC
  { m7700_sbc,       0xE9,   A_IMM                           },
  { m7700_sbc,       0xE5,   A_DIR                           },
  { m7700_sbc,       0xF5,   A_DIR_IND_X                     },
  { m7700_sbc,       0xF2,   A_DIR_INDI                      },
  { m7700_sbc,       0xE1,   A_DIR_IND_X_INDI                },
  { m7700_sbc,       0xF1,   A_DIR_INDI_IND_Y                },
  { m7700_sbc,       0xE7,   A_DIR_INDI_LONG                 },
  { m7700_sbc,       0xF7,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_sbc,       0xED,   A_ABS                           },
  { m7700_sbc,       0xFD,   A_ABS_IND_X                     },
  { m7700_sbc,       0xF9,   A_ABS_IND_Y                     },
  { m7700_sbc,       0xEF,   A_ABS_LONG                      },
  { m7700_sbc,       0xFF,   A_ABS_LONG_IND_X                },
  { m7700_sbc,       0xE3,   A_STACK_PTR_REL                 },
  { m7700_sbc,       0xF3,   A_STACK_PTR_REL_IIY             },
  // SEB
  { m7700_seb,       0x04,   A_DIR_BIT                       },
  { m7700_seb,       0x0C,   A_ABS_BIT                       },
  // SEC
  { m7700_sec,       0x38,   A_IMPL                          },
  // SEI
  { m7700_sei,       0x78,   A_IMPL                          },
  // SEM
  { m7700_sem,       0xF8,   A_IMPL                          },
  // SEP
  { m7700_sep,       0xE2,   A_IMM                           },
  // STA
  { m7700_sta,       0x85,   A_DIR                           },
  { m7700_sta,       0x95,   A_DIR_IND_X                     },
  { m7700_sta,       0x92,   A_DIR_INDI                      },
  { m7700_sta,       0x81,   A_DIR_IND_X_INDI                },
  { m7700_sta,       0x91,   A_DIR_INDI_IND_Y                },
  { m7700_sta,       0x87,   A_DIR_INDI_LONG                 },
  { m7700_sta,       0x97,   A_DIR_INDI_LONG_IND_Y           },
  { m7700_sta,       0x8D,   A_ABS                           },
  { m7700_sta,       0x9D,   A_ABS_IND_X                     },
  { m7700_sta,       0x99,   A_ABS_IND_Y                     },
  { m7700_sta,       0x8F,   A_ABS_LONG                      },
  { m7700_sta,       0x9F,   A_ABS_LONG_IND_X                },
  { m7700_sta,       0x83,   A_STACK_PTR_REL                 },
  { m7700_sta,       0x93,   A_STACK_PTR_REL_IIY             },
  // STP
  { m7700_stp,       0xDB,   A_IMPL                          },
  // STX
  { m7700_stx,       0x86,   A_DIR                           },
  { m7700_stx,       0x96,   A_DIR_IND_Y                     },
  { m7700_stx,       0x8E,   A_ABS                           },
  // STY
  { m7700_sty,       0x84,   A_DIR                           },
  { m7700_sty,       0x94,   A_DIR_IND_X                     },
  { m7700_sty,       0x8C,   A_ABS                           },
  // TAD
  { m7700_tad,       0x5B,   A_IMPL                          },
  // TAS
  { m7700_tas,       0x1B,   A_IMPL                          },
  // TAX
  { m7700_tax,       0xAA,   A_IMPL                          },
  // TAY
  { m7700_tay,       0xA8,   A_IMPL                          },
  // TBD
  { m7700_tbd,       0x425B, A_IMPL                          },
  // TBS
  { m7700_tbs,       0x421B, A_IMPL                          },
  // TBX
  { m7700_tbx,       0x42AA, A_IMPL                          },
  // TBY
  { m7700_tby,       0x42A8, A_IMPL                          },
  // TDA
  { m7700_tda,       0x7B,   A_IMPL                          },
  // TDB
  { m7700_tdb,       0x427B, A_IMPL                          },
  // TSA
  { m7700_tsa,       0x3B,   A_IMPL                          },
  // TSB
  { m7700_tsb,       0x423B, A_IMPL                          },
  // TSX
  { m7700_tsx,       0xBA,   A_IMPL                          },
  // TXA
  { m7700_txa,       0x8A,   A_IMPL                          },
  // TXB
  { m7700_txb,       0x428A, A_IMPL                          },
  // TXS
  { m7700_txs,       0x9A,   A_IMPL                          },
  // TXY
  { m7700_txy,       0x9B,   A_IMPL                          },
  // TYA
  { m7700_tya,       0x98,   A_IMPL                          },
  // TYB
  { m7700_tyb,       0x4298, A_IMPL                          },
  // TYX
  { m7700_tyx,       0xBB,   A_IMPL                          },
  // WIT
  { m7700_wit,       0xCB,   A_IMPL                          },
  // XAB
  { m7700_xab,       0x8928, A_IMPL                          }
};

// 7750 instructions
static const struct opcode opcodes_7750[] =
{
  // ASR
  { m7750_asr,       0x8908, A_ACC_A                         },
  { m7750_asr,       0x4208, A_ACC_B                         },
  { m7750_asr,       0x8906, A_DIR                           },
  { m7750_asr,       0x8916, A_DIR_IND_X                     },
  { m7750_asr,       0x890E, A_ABS                           },
  { m7750_asr,       0x891E, A_ABS_IND_X                     },
  // DIVS
  { m7750_divs,      0x89A9, A_IMM                           },
  { m7750_divs,      0x89A5, A_DIR                           },
  { m7750_divs,      0x89B5, A_DIR_IND_X                     },
  { m7750_divs,      0x89B2, A_DIR_INDI                      },
  { m7750_divs,      0x89A1, A_DIR_IND_X_INDI                },
  { m7750_divs,      0x89B1, A_DIR_INDI_IND_Y                },
  { m7750_divs,      0x89A7, A_DIR_INDI_LONG                 },
  { m7750_divs,      0x89B7, A_DIR_INDI_LONG_IND_Y           },
  { m7750_divs,      0x89AD, A_ABS                           },
  { m7750_divs,      0x89BD, A_ABS_IND_X                     },
  { m7750_divs,      0x89B9, A_ABS_IND_Y                     },
  { m7750_divs,      0x89AF, A_ABS_LONG                      },
  { m7750_divs,      0x89BF, A_ABS_LONG_IND_X                },
  { m7750_divs,      0x89A3, A_STACK_PTR_REL                 },
  { m7750_divs,      0x89B3, A_STACK_PTR_REL_IIY             },
  // EXTS
  { m7750_exts,      0x898B, A_ACC_A                         },
  { m7750_exts,      0x428B, A_ACC_B                         },
  // EXTZ
  { m7750_extz,      0x89AB, A_ACC_A                         },
  { m7750_extz,      0x42AB, A_ACC_B                         },
  // MPYS
  { m7750_mpys,      0x8989, A_IMM                           },
  { m7750_mpys,      0x8985, A_DIR                           },
  { m7750_mpys,      0x8995, A_DIR_IND_X                     },
  { m7750_mpys,      0x8992, A_DIR_INDI                      },
  { m7750_mpys,      0x8981, A_DIR_IND_X_INDI                },
  { m7750_mpys,      0x8991, A_DIR_INDI_IND_Y                },
  { m7750_mpys,      0x8987, A_DIR_INDI_LONG                 },
  { m7750_mpys,      0x8997, A_DIR_INDI_LONG_IND_Y           },
  { m7750_mpys,      0x898D, A_ABS                           },
  { m7750_mpys,      0x899D, A_ABS_IND_X                     },
  { m7750_mpys,      0x8999, A_ABS_IND_Y                     },
  { m7750_mpys,      0x898F, A_ABS_LONG                      },
  { m7750_mpys,      0x899F, A_ABS_LONG_IND_X                },
  { m7750_mpys,      0x8983, A_STACK_PTR_REL                 },
  { m7750_mpys,      0x8993, A_STACK_PTR_REL_IIY             }
};

struct opcode_flag
{
  int insn;
  int flags;
#define MEM_R    OP_ADDR_R    // read access
#define MEM_W    OP_ADDR_W    // write access
};

static const struct opcode_flag opcodes_flags[] =
{
  { m7700_adc,     MEM_R    },
  { m7700_and,     MEM_R    },
  { m7700_asl,     MEM_W    },
  { m7750_asr,     MEM_W    },
  { m7700_bbc,     MEM_R    },
  { m7700_bbs,     MEM_R    },
  { m7700_clb,     MEM_W    },
  { m7700_cmp,     MEM_R    },
  { m7700_cpx,     MEM_R    },
  { m7700_cpy,     MEM_R    },
  { m7700_dec,     MEM_W    },
  { m7700_div,     MEM_R    },
  { m7750_divs,    MEM_R    },
  { m7700_eor,     MEM_R    },
  { m7700_inc,     MEM_W    },
  { m7700_jmp,     MEM_R    },
  { m7700_jsr,     MEM_R    },
  { m7700_lda,     MEM_R    },
  { m7700_ldm,     MEM_W    },
  { m7700_ldx,     MEM_R    },
  { m7700_ldy,     MEM_R    },
  { m7700_lsr,     MEM_W    },
  { m7700_mpy,     MEM_R    },
  { m7750_mpys,    MEM_R    },
  { m7700_ora,     MEM_R    },
  { m7700_rol,     MEM_W    },
  { m7700_ror,     MEM_W    },
  { m7700_sbc,     MEM_R    },
  { m7700_seb,     MEM_W    },
  { m7700_sta,     MEM_W    },
  { m7700_stx,     MEM_W    },
  { m7700_sty,     MEM_W    }
};

static bool with_acc(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case m7700_adc:
    case m7700_and:
    case m7700_cmp:
    case m7700_eor:
    case m7700_lda:
    case m7700_sta:
    case m7700_ora:
    case m7700_sbc:
      return true;
  }
  return false;
}

static bool imm_read_another_byte(const insn_t &insn)
{
  bool m16 = get_sreg(insn.ea, rfM) == 0;
  bool x16 = get_sreg(insn.ea, rfX) == 0;

  // if insn are using X flag and this flag is set to 0
  switch ( insn.itype )
  {
    case m7700_cpx:
    case m7700_cpy:
    case m7700_ldx:
    case m7700_ldy:
      if ( x16 )
        return true;
  }

  // if insn is not using M flag
  switch ( insn.itype )
  {
    case m7700_clp:
    case m7700_ldt:
    case m7700_pea:
    case m7700_pei:
    case m7700_per:
    case m7700_psh:
    case m7700_pul:
    case m7700_sep:
    case m7700_mvn:
    case m7700_mvp:
      return false;
  }
  // return true if M flag is set to 0
  return m16;
}

inline static void set_flag(op_t &x, int flag)
{
  x.specflag1 |= flag;
}

inline static void set_flag(insn_t &insn, int flag)
{
  insn.auxpref |= flag;
}

inline static void set_op_reg(op_t &op, uint16 reg)
{
  op.type = o_reg;
  op.reg = reg;
  op.dtype = dt_word; // XXX not sure
}

// shortcuts
#define set_op_acc_a(op)     set_op_reg(op, rA)
#define set_op_acc_b(op)     set_op_reg(op, rB)
//#define set_op_ind_x(op)     set_op_reg(op, rX)
#define set_op_ind_y(op)     set_op_reg(op, rY)

static uint16 my_next_word(insn_t &insn)
{
  uchar b1 = insn.get_next_byte();
  uchar b2 = insn.get_next_byte();
  return b1 | (b2 << 8);
}

static uint32 my_next_3bytes(insn_t &insn)
{
  uchar b1 = insn.get_next_byte();
  uchar b2 = insn.get_next_byte();
  uchar b3 = insn.get_next_byte();
  return b1 | (b2 << 8) | (b3 << 16);
}

inline static int d_typ2addr(insn_t &insn, char d_typ)
{
  switch ( d_typ )
  {
    default:
      INTERR(10026);
    case dt_byte:  return insn.get_next_byte();
    case dt_word:  return my_next_word(insn);

    // special case: dt_dword is 3 bytes long here
    case dt_dword: return my_next_3bytes(insn);
  }
}

inline static void set_op_imm(insn_t &insn, op_t &op, char d_typ)
{
  op.type = o_imm;
  op.value = d_typ2addr(insn, d_typ);
  op.dtype = d_typ;
  // when operating on 16-bit data in immediate addressing
  // mode with data lenght selection flag set to 0, the
  // bytes-count increases by 1
  if ( imm_read_another_byte(insn) )
  {
    op.value |= insn.get_next_byte() << 8;
    op.dtype = dt_word;
  }
}

inline static void set_op_bit(insn_t &insn, op_t &op)
{
  set_op_imm(insn, op, dt_byte);
  op.type = o_bit;
}

inline static void set_op_addr(insn_t &insn, op_t &op, char d_typ)
{
  op.type = o_near;
  op.dtype = with_acc(insn) ? dt_word : d_typ;
  op.addr = d_typ2addr(insn, d_typ);
}

inline static void set_op_mem(insn_t &insn, op_t &op, char d_typ, int flags)
{
  op.type = o_mem;
  op.dtype = with_acc(insn) ? dt_word : d_typ;
  op.addr = d_typ2addr(insn, d_typ);
  set_flag(op, flags);
}

inline static void set_op_displ(insn_t &insn, op_t &op, char d_typ, uint16 reg)
{
  op.type = o_displ;
  op.dtype = with_acc(insn) ? dt_word : d_typ;
  op.addr = d_typ2addr(insn, d_typ);
  op.reg = reg;
}

#define x       insn.ops[n]
#define next_x  insn.ops[n + 1]

// get an opcode flags struct from insn
static int get_opcode_flags(const int insn)
{
  for ( int i = 0; i < qnumber(opcodes_flags); i++ )
  {
    if ( opcodes_flags[i].insn != insn )
      continue;

    return opcodes_flags[i].flags;
  }
  return 0;
}

static inline bool is_jmp(const insn_t &insn)
{
  return insn.itype == m7700_jmp || insn.itype == m7700_jsr;
}

static void set_op_mem_dr_rel(const insn_t &insn, op_t &op)
{
  sel_t s = get_sreg(insn.ea, rDR);
  // if the value of the DR register is known,
  // we can compute the absolute address
  if ( s != BADSEL )
  {
    op.addr += s;
    // set operand type according to the M bit
    bool m16 = get_sreg(insn.ea, rfM) == 0;
    op.dtype = m16 ? dt_word : dt_byte;
  }
  set_flag(op, OP_ADDR_DR_REL);
}

// fill insn struct according to the specified addressing mode
void m7700_t::fill_insn(insn_t &insn, m7700_addr_mode_t mode)
{
  int n = 0;      // current operand
  const int curflags = get_opcode_flags(insn.itype); // current flags

  // if the first operand should be an accumulator (either A or B),
  // just fill accordingly the insn structure
  if ( with_acc(insn) )
  {
    if ( with_acc_b )
      set_op_acc_b(x);
    else
      set_op_acc_a(x);
    n++;
  }

  // the LDM instruction operands are always preceded by an immediate value,
  // but this immediate value is always at the end of the operation code.
  if ( insn.itype == m7700_ldm )
    n++;

  switch ( mode )
  {
    case A_IMPL:                 // implied
      // nothing to do !
      break;

    case A_IMM:                  // immediate
      set_op_imm(insn, x, dt_byte);
      break;

    case A_ACC_A:                // accumulator A
      set_op_acc_a(x);
      break;

    case A_ACC_B:                // accumulator B
      set_op_acc_b(x);
      break;

    case A_DIR:                  // direct
      set_op_mem(insn, x, dt_byte, curflags);
      set_op_mem_dr_rel(insn, x);
      break;

    case A_DIR_BIT:              // direct bit
      set_op_mem(insn, next_x, dt_byte, curflags);
      set_op_mem_dr_rel(insn, next_x);
      set_op_bit(insn, x);
      break;

    case A_DIR_IND_X:            // direct indexed X
      set_op_displ(insn, x, dt_byte, rX);
      set_op_mem_dr_rel(insn, x);
      break;

    case A_DIR_IND_Y:            // direct indexed Y
      set_op_displ(insn, x, dt_byte, rY);
      set_op_mem_dr_rel(insn, x);
      break;

    case A_DIR_INDI:             // direct indirect
      set_op_mem(insn, x, dt_byte, curflags);
      set_flag(x, OP_ADDR_IND);
      set_op_mem_dr_rel(insn, x);
      break;

    case A_DIR_IND_X_INDI:       // direct indexed X indirect
      set_op_displ(insn, x, dt_byte, rX);
      set_flag(x, OP_DISPL_IND);
      set_op_mem_dr_rel(insn, x);
      break;

    case A_DIR_INDI_IND_Y:       // direct indirect indexed Y
      set_op_displ(insn, x, dt_byte, rY);
      set_flag(x, OP_DISPL_IND_P1);
      set_op_mem_dr_rel(insn, x);
      break;

    case A_DIR_INDI_LONG:         // direct indirect long
      set_op_mem(insn, x, dt_byte, curflags);
      set_flag(x, OP_ADDR_IND);
      set_op_mem_dr_rel(insn, x);
      set_flag(insn, INSN_LONG_FORMAT);
      break;

    case A_DIR_INDI_LONG_IND_Y:   // direct indirect long indexed Y
      set_op_displ(insn, x, dt_byte, rY);
      set_flag(x, OP_DISPL_IND_P1);
      set_op_mem_dr_rel(insn, x);
      set_flag(insn, INSN_LONG_FORMAT);
      break;

    case A_ABS:                  // absolute
      if ( is_jmp(insn) )
        set_op_addr(insn, x, dt_word);
      else
        set_op_mem(insn, x, dt_word, curflags);
      break;

    case A_ABS_BIT:              // absolute bit
      set_op_mem(insn, next_x, dt_word, curflags);
      set_op_bit(insn, x);
      break;

    case A_ABS_IND_X:            // absolute indexed X
      set_op_displ(insn, x, dt_word, rX);
      break;

    case A_ABS_IND_Y:            // absolute indexed Y
      set_op_displ(insn, x, dt_word, rY);
      break;

    case A_ABS_LONG:             // absolute long
      if ( is_jmp(insn) )
      {
        set_op_addr(insn, x, dt_dword);
        set_flag(insn, INSN_LONG_FORMAT);
      }
      else
        set_op_mem(insn, x, dt_dword, curflags);
      break;

    case A_ABS_LONG_IND_X:       // absolute long indexed X
      set_op_displ(insn, x, dt_dword, rX);
      break;

    case A_ABS_INDI:             // absolute indirect
      set_op_mem(insn, x, dt_word, curflags);
      set_flag(x, OP_ADDR_IND);
      break;

    case A_ABS_INDI_LONG:        // absolute indirect long
      set_op_mem(insn, x, dt_word, curflags);
      set_flag(x, OP_ADDR_IND);
      if ( is_jmp(insn) )
        set_flag(insn, INSN_LONG_FORMAT);
      break;

    case A_ABS_IND_X_INDI:       // absolute indexed X indirect
      set_op_displ(insn, x, dt_word, rX);
      set_flag(x, OP_DISPL_IND);
      break;

    case A_STACK:                // stack
      // nothing to do !
      break;

    case A_STACK_S:              // stack short
      set_op_imm(insn, x, dt_byte);
      break;

    case A_STACK_L:              // stack long
      set_op_imm(insn, x, dt_word);
      break;

    case A_REL:                  // relative
      set_op_addr(insn, x, dt_byte);
      x.addr = (signed char) x.addr + insn.ip + insn.size;
      break;

    case A_REL_LONG:             // relative long
      set_op_addr(insn, x, dt_word);
      x.addr = (signed short) x.addr + insn.ip + insn.size;
      set_flag(insn, INSN_LONG_FORMAT);
      break;

    case A_DIR_BIT_REL:          // direct bit relative
      set_op_mem(insn, next_x, dt_byte, curflags);
      set_op_mem_dr_rel(insn, x);
      set_op_bit(insn, x);
      n += 2;
      set_op_addr(insn, x, dt_byte);
      x.addr = (signed char) x.addr + insn.ip + insn.size;
      break;

    case A_ABS_BIT_REL:          // absolute bit relative
      set_op_mem(insn, next_x, dt_word, curflags);
      set_op_bit(insn, x);
      n += 2;
      set_op_addr(insn, x, dt_byte);
      x.addr = (signed char) x.addr + insn.ip + insn.size;
      break;

    case A_STACK_PTR_REL:        // stack pointer relative
      set_op_displ(insn, x, dt_byte, rS);
      break;

    case A_STACK_PTR_REL_IIY:    // stack pointer relative indirect indexed Y
      set_op_displ(insn, x, dt_byte, rS);
      set_flag(x, OP_DISPL_IND);
      set_op_ind_y(next_x);
      break;

    case A_BT:                   // block transfer
      set_op_imm(insn, x, dt_byte);
      set_flag(x, OP_IMM_WITHOUT_SHARP);
      n += 2;
      set_op_imm(insn, x, dt_byte);
      set_flag(x, OP_IMM_WITHOUT_SHARP);
      break;

    default:
      INTERR(10027);
  }

  // now we can read immediate from operation code, and fill the first operand
  // as it should be
  if ( insn.itype == m7700_ldm )
  {
    n = 0;
    set_op_imm(insn, x, dt_byte);
    /*
    if ( x.dtype == dt_word )
       set_flag(insn, INSN_LONG_FORMAT);
    */
  }
}

// get an opcode struct from code
const struct opcode *m7700_t::get_opcode(uint16 code)
{
  // check in the 7700 opcodes
  for ( int i = 0; i < qnumber(opcodes_7700); i++ )
  {
    if ( opcodes_7700[i].code != code )
      continue;
    return &opcodes_7700[i];
  }
  // check in the 7750 opcodes
  if ( ptype == prc_m7750 )
  {
    for ( int i = 0; i < qnumber(opcodes_7750); i++ )
    {
      if ( opcodes_7750[i].code != code )
        continue;

      return &opcodes_7750[i];
    }
  }
  // check in the 7700 opcodes with a FF00 mask if equals to 4200
  if ( ((code & 0xFF00) >> 8) == 0x42 )
  {
    code &= 0x00FF;
    with_acc_b = true;
    return get_opcode(code & 0x00FF);
  }
  return nullptr;
}

// analyze an instruction
int m7700_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  const struct opcode *op;
  uint16 code;

  with_acc_b = false;

  // read a byte
  code = insn.get_next_byte();

  // detect BRK insn
  if ( code == 0x00 && get_byte(insn.ea + 1) == 0xEA )
  {
    insn.itype = m7700_brk;
    insn.size += 1;
    goto ana_finished;
  }

  // some instructions have their opcodes represented in 2 bytes,
  // so we need to pick an another byte
  if ( code == 0x42 || code == 0x89 )
    code = (code << 8) + insn.get_next_byte();

  // analyze and return corresponding opcode struct
  op = get_opcode(code);
  if ( op == nullptr )     // no instruction was found..
    return 0;

  // fill the insn struct
  insn.itype = op->insn;
  fill_insn(insn, op->mode);

ana_finished:
  return insn.size;
}

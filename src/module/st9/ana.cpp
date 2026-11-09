
#include "st9.hpp"

enum st9_addressing_modes ENUM_SIZE(uint16)
{
  A_IMPL,         // implied
  A_wrd_wrs,      // rd,rs
  A_wrd_wrsi,     // rd,(rs)
  A_wrdi_wrs,     // (rd),rs
  A_wrdi_grs,     // (rd),Rs
  A_grd_wrsi,     // Rd,(rs)
  A_grd_grs,      // Rd,Rs
  A_grs_grd,      // Rs,Rd
  A_grd_8q,       // Rd,#N
  A_grpd_grps,    // RRd,RRs
  A_grpd_16q_0,   // RRd,#NN with first byte mask xxxxxxx0
  A_grpd_16q_1,   // RRd,#NN with first byte mask xxxxxxx1
  A_grp_8q,       // RR,#N
  A_grs,          // Rs
  A_grsi,         // (Rs)
  A_grd,          // Rd
  A_grdi,         // (Rd)
  A_grp_0,        // RR with first byte mask xxxxxxx0
  A_grp_1,        // RR with first byte mask xxxxxxx1
  A_grpi,         // (RR)
  A_8q,           // N
  A_16q,          // NN
  A_grps,         // RRs
  A_grpd_0,       // RRd with first byte mask xxxxxxx0
  A_grpd_1,       // RRd with first byte mask xxxxxxx1
  A_grpdi,        // (RRd)
  A_wrpd_wrps,    // rrd,rrs
  A_wrpdi_wrps,   // (rrd),rrs
  A_wrpd_wrpsi,   // rrd,(rrs)
  A_wrpdi_wrpsi,  // (rrd),(rrs)

  A_wrpdip_wrpsip_00,    // (rrd)+,(rrs)+ with first byte mask xxx0xxx0
  A_wrpdip_wrpsip_10,    // (rrd)+,(rrs)+ with first byte mask xxx1xxx0
  A_wrpdip_wrpsip_01,    // (rrd)+,(rrs)+ with first byte mask xxx0xxx1
  A_wrpdip_wrpsip_11,    // (rrd)+,(rrs)+ with first byte mask xxx1xxx1

  A_wrpd_wrs,     // rrd,rs
  A_8qxwrp_16q,   // Nd(rr),#NNs
  A_16qxwrp_16q,  // NNd(rr),#NNs
  A_8qxwrp_gr,    // N(rr),R
  A_16qxwrp_gr,   // NN(rr),R
  A_16q_8q,       // NNd,#Ns
  A_16q_16q,      // NNd,#NNs
  A_wr_wrpxwrp,   // rd,rrs(rrx)
  A_wrpxwrp_wr,   // rrd(rrx),rs
  A_wrp_wrpxwrp,  // rrd,rrs(rrx)
  A_wrpxwrp_wrp,  // rrd(rrx),rrs

  A_gr_wrpi,      // Rd,(rrs)
  A_wrip_gr,      // (rrd),Rs
  A_grpi_wrip,    // (RRd),(rrs)
  A_gri_wrip_01,  // (R),(rr) with first byte mask 0100xxxx
  A_gri_wrip_11,  // (R),(rr) with first byte mask 1100xxxx
  A_gr_8qxwrp,    // Rd,N(rrx)
  A_gr_16qxwrp,   // Rd,NN(rrx)
  A_grp_wrpi,     // RRd,(rrs)

  A_8qxwrp_grp,   // N(rrx),RRs
  A_grp_8qxwrp,   // RRs,N(rrx)
  A_16qxwrp_grp,  // NN(rrx),RRs
  A_grp_16qxwrp,  // RRs,NN(rrx)

  A_8qxgrpi,      // N(RRx)
  A_16qxgrpi,     // NN(RRx)

  A_wrd_wrpsi_8q_0,   // rd,(rrs),N with first byte mask xxx0xxxx
  A_wrd_wrpsi_8q_1,   // rd,(rrs),N with first byte mask xxx1xxxx

  A_grpd_wrsi,    // RRd,(rs)

  A_8qxwr_wrs,    // N(rx),rs
  A_wrs_8qxwr,    // rs,N(rx)
  A_grd_wrpip,    // Rd,(rrs)+
  A_wrpip_grd,    // (rrs)+,Rd
  A_wrd_wrpi,     // rd,(rrs)
  A_wrpi_wrd,     // (rrs),rd

  A_wrpi_grp,     // (rr),RR
  A_wrpi_16q,     // (rr),#NN

  A_grd_wrpim,    // Rd,-(rrs)
  A_wrpim_grd,    // -(rrs),Rd
  A_grpd_wrpim,   // RRd,-(rrs)
  A_wrpim_grpd,   // -(rrs),RRd
  A_16q_wrs,      // NN,rs
  A_wrd_16q,      // rd,NN

  A_grpd_wrpip,   // RRd,(rrs)+
  A_wrpip_grpd,   // (rrd)+,RRs

  A_wrip_wrpip,   // (rd)+,(rrs)+
  A_wrpip_wrip,   // (rrs)+,(rd)+

  A_8qxwrip_wrp,  // N(rx),rrs
  A_wrp_8qxwrip,  // rrd,N(rx)

  A_wrp_16q,      // rrd,NN
  A_16q_wrp,      // NN,rrs

  A_wrp_wrp_grp,  // rrh,rrl,RRs
  A_wrdi_grp,     // (rd),RRs
  A_wrpi_8q,      // (rrd),#N

  A_wrb_wrb_10,   // rd.b,rs.b with first word mask xxx1xxxx xxx0xxxx
  A_wrb_wrb_11,   // rd.b,rs.b with first word mask xxx1xxxx xxx1xxxx
  A_wrb_nwrb_10,  // rd.b,!rs.b with first word mask xxx1xxxx xxx0xxxx
  A_wrb_nwrb_11,  // rd.b,!rs.b with first word mask xxx1xxxx xxx1xxxx
  A_wrb,          // rd.b
  A_wrbi,         // (rr).bd
  A_bwr_8q_0,     // b.rd,N with first byte mask xxx0xxxx
  A_bwr_8q_1,     // b.rd,N with first byte mask xxx1xxxx

  A_seg_16q_01,   // nnnnnn,NN with first byte mask 01xxxxxx
  A_seg_16q_11,   // nnnnnn,NN with first byte mask 11xxxxxx

  A_rwn_000,      // wwwww with first byte mask xxxxx000
  A_rwn_100,      // wwwww with first byte mask xxxxx100
  A_rwn_101,      // wwwww with first byte mask xxxxx101
  A_rpn,          // pppppp
};

struct opcode
{
  uint16 code;        // opcode
  uint16 insn;        // insn mnemonic
  uint16 addr;        // addressing mode
};

static const opcode opcodes[] =
{
  { 0x00,     st9_ei,         A_IMPL          },
  { 0x01,     st9_scf,        A_IMPL          },
  { 0x02,     st9_or,         A_wrd_wrs       },
  { 0x03,     st9_or,         A_wrd_wrsi      },
  { 0x04,     st9_or,         A_grd_grs       },
  { 0x05,     st9_or,         A_grd_8q        },
  { 0x06,     st9_aldw,       A_8qxwrp_16q    },
  { 0x06,     st9_aldw,       A_16qxwrp_16q   },
  { 0x07,     st9_orw,        A_grpd_grps     },
  { 0x07,     st9_orw,        A_grpd_16q_1    },
  { 0x08,     st9_ld,         A_grs           },
  { 0x09,     st9_ld,         A_grd           },
  { 0x0A,     st9_djnz,       A_8q            },
  { 0x0B,     st9_jrcc,       A_8q            },
  { 0x0C,     st9_ld,         A_8q            },
  { 0x0D,     st9_jpcc,       A_16q           },
  { 0x0E,     st9_orw,        A_wrpd_wrps     },
  { 0x0E,     st9_orw,        A_wrpdi_wrps    },
  { 0x0E,     st9_orw,        A_wrpd_wrpsi    },
  { 0x0E,     st9_orw,        A_wrpdi_wrpsi   },
  { 0x0F,     st9_bor,        A_wrb_wrb_10    },
  { 0x0F,     st9_bor,        A_wrb_nwrb_11   },
  { 0x0F,     st9_bset,       A_wrb           },
  { 0x10,     st9_di,         A_IMPL          },
  { 0x11,     st9_rcf,        A_IMPL          },
  { 0x12,     st9_and,        A_wrd_wrs       },
  { 0x13,     st9_and,        A_wrd_wrsi      },
  { 0x14,     st9_and,        A_grd_grs       },
  { 0x15,     st9_and,        A_grd_8q        },
  { 0x16,     st9_xch,        A_grs_grd       },
  { 0x17,     st9_andw,       A_grpd_grps     },
  { 0x17,     st9_andw,       A_grpd_16q_1    },
  { 0x18,     st9_ld,         A_grs           },
  { 0x19,     st9_ld,         A_grd           },
  { 0x1A,     st9_djnz,       A_8q            },
  { 0x1B,     st9_jrcc,       A_8q            },
  { 0x1C,     st9_ld,         A_8q            },
  { 0x1D,     st9_jpcc,       A_16q           },
  { 0x1E,     st9_andw,       A_wrpd_wrps     },
  { 0x1E,     st9_andw,       A_wrpdi_wrps    },
  { 0x1E,     st9_andw,       A_wrpd_wrpsi    },
  { 0x1E,     st9_andw,       A_wrpdi_wrpsi   },
  { 0x1F,     st9_band,       A_wrb_wrb_11    },
  { 0x1F,     st9_band,       A_wrb_nwrb_10   },
  { 0x1F,     st9_bres,       A_wrb           },
  { 0x20,     st9_popu,       A_grd           },
  { 0x21,     st9_popu,       A_grdi          },
  { 0x22,     st9_sbc,        A_wrd_wrs       },
  { 0x23,     st9_sbc,        A_wrd_wrsi      },
  { 0x24,     st9_sbc,        A_grd_grs       },
  { 0x25,     st9_sbc,        A_grd_8q        },
  { 0x26,     st9_ald,        A_8qxwrp_gr     },
  { 0x26,     st9_ald,        A_16qxwrp_gr    },
  { 0x27,     st9_sbcw,       A_grpd_grps     },
  { 0x27,     st9_sbcw,       A_grpd_16q_1    },
  { 0x28,     st9_ld,         A_grs           },
  { 0x29,     st9_ld,         A_grd           },
  { 0x2A,     st9_djnz,       A_8q            },
  { 0x2B,     st9_jrcc,       A_8q            },
  { 0x2C,     st9_ld,         A_8q            },
  { 0x2D,     st9_jpcc,       A_16q           },
  { 0x2E,     st9_sbcw,       A_wrpd_wrps     },
  { 0x2E,     st9_sbcw,       A_wrpdi_wrps    },
  { 0x2E,     st9_sbcw,       A_wrpd_wrpsi    },
  { 0x2E,     st9_sbcw,       A_wrpdi_wrpsi   },
  { 0x2F,     st9_sraw,       A_grp_0         },
  { 0x2F,     st9_ald,        A_16q_8q        },
  { 0x30,     st9_pushu,      A_grd           },
  { 0x31,     st9_pushu,      A_grdi          },
  { 0x32,     st9_adc,        A_wrd_wrs       },
  { 0x33,     st9_adc,        A_wrd_wrsi      },
  { 0x34,     st9_adc,        A_grd_grs       },
  { 0x35,     st9_adc,        A_grd_8q        },
  { 0x36,     st9_rrcw,       A_grp_0         },
  { 0x36,     st9_aldw,       A_16q_16q       },
  { 0x37,     st9_adcw,       A_grpd_grps     },
  { 0x37,     st9_adcw,       A_grpd_16q_1    },
  { 0x38,     st9_ld,         A_grs           },
  { 0x39,     st9_ld,         A_grd           },
  { 0x3A,     st9_djnz,       A_8q            },
  { 0x3B,     st9_jrcc,       A_8q            },
  { 0x3C,     st9_ld,         A_8q            },
  { 0x3D,     st9_jpcc,       A_16q           },
  { 0x3E,     st9_adcw,       A_wrpd_wrps     },
  { 0x3E,     st9_adcw,       A_wrpdi_wrps    },
  { 0x3E,     st9_adcw,       A_wrpd_wrpsi    },
  { 0x3E,     st9_adcw,       A_wrpdi_wrpsi   },
  { 0x3F,     st9_calls,      A_seg_16q_01    },
  { 0x3F,     st9_jps,        A_seg_16q_11    },
  { 0x40,     st9_dec,        A_grd           },
  { 0x41,     st9_dec,        A_grdi          },
  { 0x42,     st9_add,        A_wrd_wrs       },
  { 0x43,     st9_add,        A_wrd_wrsi      },
  { 0x44,     st9_add,        A_grd_grs       },
  { 0x45,     st9_add,        A_grd_8q        },
  { 0x46,     st9_ret,        A_IMPL          },
  { 0x47,     st9_addw,       A_grpd_grps     },
  { 0x47,     st9_addw,       A_grpd_16q_1    },
  { 0x48,     st9_ld,         A_grs           },
  { 0x49,     st9_ld,         A_grd           },
  { 0x4A,     st9_djnz,       A_8q            },
  { 0x4B,     st9_jrcc,       A_8q            },
  { 0x4C,     st9_ld,         A_8q            },
  { 0x4D,     st9_jpcc,       A_16q           },
  { 0x4E,     st9_addw,       A_wrpd_wrps     },
  { 0x4E,     st9_addw,       A_wrpdi_wrps    },
  { 0x4E,     st9_addw,       A_wrpd_wrpsi    },
  { 0x4E,     st9_addw,       A_wrpdi_wrpsi   },
  { 0x4F,     st9_mul,        A_wrpd_wrs      },
  { 0x50,     st9_inc,        A_grd           },
  { 0x51,     st9_inc,        A_grdi          },
  { 0x52,     st9_sub,        A_wrd_wrs       },
  { 0x53,     st9_sub,        A_wrd_wrsi      },
  { 0x54,     st9_sub,        A_grd_grs       },
  { 0x55,     st9_sub,        A_grd_8q        },
  { 0x56,     st9_divws,      A_wrp_wrp_grp   },
  { 0x57,     st9_subw,       A_grpd_grps     },
  { 0x57,     st9_subw,       A_grpd_16q_1    },
  { 0x58,     st9_ld,         A_grs           },
  { 0x59,     st9_ld,         A_grd           },
  { 0x5A,     st9_djnz,       A_8q            },
  { 0x5B,     st9_jrcc,       A_8q            },
  { 0x5C,     st9_ld,         A_8q            },
  { 0x5D,     st9_jpcc,       A_16q           },
  { 0x5E,     st9_subw,       A_wrpd_wrps     },
  { 0x5E,     st9_subw,       A_wrpdi_wrps    },
  { 0x5E,     st9_subw,       A_wrpd_wrpsi    },
  { 0x5E,     st9_subw,       A_wrpdi_wrpsi   },
  { 0x5F,     st9_div,        A_wrpd_wrs      },
  { 0x60,     st9_ald,        A_wr_wrpxwrp    },
  { 0x60,     st9_ald,        A_wrpxwrp_wr    },
  { 0x60,     st9_aldw,       A_wrp_wrpxwrp   },
  { 0x60,     st9_aldw,       A_wrpxwrp_wrp   },
  { 0x61,     st9_ccf,        A_IMPL          },
  { 0x62,     st9_xor,        A_wrd_wrs       },
  { 0x63,     st9_xor,        A_wrd_wrsi      },
  { 0x64,     st9_xor,        A_grd_grs       },
  { 0x65,     st9_xor,        A_grd_8q        },
  { 0x66,     st9_push,       A_grd           },
  { 0x67,     st9_xorw,       A_grpd_grps     },
  { 0x67,     st9_xorw,       A_grpd_16q_1    },
  { 0x68,     st9_ld,         A_grs           },
  { 0x69,     st9_ld,         A_grd           },
  { 0x6A,     st9_djnz,       A_8q            },
  { 0x6B,     st9_jrcc,       A_8q            },
  { 0x6C,     st9_ld,         A_8q            },
  { 0x6D,     st9_jpcc,       A_16q           },
  { 0x6E,     st9_xorw,       A_wrpd_wrps     },
  { 0x6E,     st9_xorw,       A_wrpdi_wrps    },
  { 0x6E,     st9_xorw,       A_wrpd_wrpsi    },
  { 0x6E,     st9_xorw,       A_wrpdi_wrpsi   },
  { 0x6F,     st9_bxor,       A_wrb_wrb_10    },
  { 0x6F,     st9_bxor,       A_wrb_nwrb_11   },
  { 0x6F,     st9_bcpl,       A_wrb           },
  { 0x70,     st9_da,         A_grd           },
  { 0x71,     st9_da,         A_grdi          },
  { 0x72,     st9_ald,        A_gr_wrpi       },
  { 0x72,     st9_ald,        A_wrip_gr       },
  { 0x73,     st9_calls,      A_gri_wrip_01   },
  { 0x73,     st9_jps,        A_gri_wrip_11   },
  { 0x73,     st9_ald,        A_grpi_wrip     },
  { 0x74,     st9_call,       A_grpdi         },
  { 0x74,     st9_pushw,      A_grps          },
  { 0x75,     st9_popw,       A_grpd_0        },
  { 0x75,     st9_unlink,     A_grpd_1        },
  { 0x76,     st9_pop,        A_grd           },
  { 0x77,     st9_pop,        A_grdi          },
  { 0x78,     st9_ld,         A_grs           },
  { 0x79,     st9_ld,         A_grd           },
  { 0x7A,     st9_djnz,       A_8q            },
  { 0x7B,     st9_jrcc,       A_8q            },
  { 0x7C,     st9_ld,         A_8q            },
  { 0x7D,     st9_jpcc,       A_16q           },
  { 0x7E,     st9_aldw,       A_grp_wrpi      },
  { 0x7F,     st9_ald,        A_gr_8qxwrp     },
  { 0x7F,     st9_ald,        A_gr_16qxwrp    },
  { 0x80,     st9_cpl,        A_grd           },
  { 0x81,     st9_cpl,        A_grdi          },
  { 0x82,     st9_cp,         A_wrd_wrs       },
  { 0x83,     st9_cp,         A_wrd_wrsi      },
  { 0x84,     st9_cp,         A_grd_grs       },
  { 0x85,     st9_cp,         A_grd_8q        },
  { 0x86,     st9_aldw,       A_8qxwrp_grp    },
  { 0x86,     st9_aldw,       A_grp_8qxwrp    },
  { 0x86,     st9_aldw,       A_16qxwrp_grp   },
  { 0x86,     st9_aldw,       A_grp_16qxwrp   },
  { 0x87,     st9_cpw,        A_grpd_grps     },
  { 0x87,     st9_cpw,        A_grpd_16q_1    },
  { 0x88,     st9_ld,         A_grs           },
  { 0x89,     st9_ld,         A_grd           },
  { 0x8A,     st9_djnz,       A_8q            },
  { 0x8B,     st9_jrcc,       A_8q            },
  { 0x8C,     st9_ld,         A_8q            },
  { 0x8D,     st9_jpcc,       A_16q           },
  { 0x8E,     st9_cpw,        A_wrpd_wrps     },
  { 0x8E,     st9_cpw,        A_wrpdi_wrps    },
  { 0x8E,     st9_cpw,        A_wrpd_wrpsi    },
  { 0x8E,     st9_cpw,        A_wrpdi_wrpsi   },
  { 0x8FF1,   st9_push,       A_8q            },
  { 0x8FF3,   st9_pushu,      A_8q            },
  { 0x8FC1,   st9_pushw,      A_16q           },
  { 0x8FC3,   st9_pushuw,     A_16q           },
  { 0x8F01,   st9_pea,        A_8qxgrpi       },
  { 0x8F01,   st9_pea,        A_16qxgrpi      },
  { 0x8F03,   st9_peau,       A_8qxgrpi       },
  { 0x8F03,   st9_peau,       A_16qxgrpi      },
  { 0x8F,     st9_rlcw,       A_grpd_0        },
  { 0x90,     st9_clr,        A_grd           },
  { 0x91,     st9_clr,        A_grdi          },
  { 0x92,     st9_cp,         A_wrd_wrs       },
  { 0x93,     st9_cp,         A_wrd_wrsi      },
  { 0x94,     st9_cp,         A_grd_grs       },
  { 0x95,     st9_cp,         A_grd_8q        },
  { 0x96,     st9_aldw,       A_wrdi_grp      },
  { 0x97,     st9_cpw,        A_grpd_grps     },
  { 0x97,     st9_cpw,        A_grpd_16q_1    },
  { 0x98,     st9_ld,         A_grs           },
  { 0x99,     st9_ld,         A_grd           },
  { 0x9A,     st9_djnz,       A_8q            },
  { 0x9B,     st9_jrcc,       A_8q            },
  { 0x9C,     st9_ld,         A_8q            },
  { 0x9D,     st9_jpcc,       A_16q           },
  { 0x9E,     st9_cpw,        A_wrpd_wrps     },
  { 0x9E,     st9_cpw,        A_wrpdi_wrps    },
  { 0x9E,     st9_cpw,        A_wrpd_wrpsi    },
  { 0x9E,     st9_cpw,        A_wrpdi_wrpsi   },
  { 0x9F,     st9_cpjfi,      A_wrd_wrpsi_8q_0    },
  { 0x9F,     st9_cpjti,      A_wrd_wrpsi_8q_1    },
  { 0xA0,     st9_rol,        A_grd           },
  { 0xA1,     st9_rol,        A_grdi          },
  { 0xA2,     st9_tm,         A_wrd_wrs       },
  { 0xA3,     st9_tm,         A_wrd_wrsi      },
  { 0xA4,     st9_tm,         A_grd_grs       },
  { 0xA5,     st9_tm,         A_grd_8q        },
  { 0xA6,     st9_aldw,       A_grpd_wrsi     },
  { 0xA7,     st9_tmw,        A_grpd_grps     },
  { 0xA7,     st9_tmw,        A_grpd_16q_1    },
  { 0xA8,     st9_ld,         A_grs           },
  { 0xA9,     st9_ld,         A_grd           },
  { 0xAA,     st9_djnz,       A_8q            },
  { 0xAB,     st9_jrcc,       A_8q            },
  { 0xAC,     st9_ld,         A_8q            },
  { 0xAD,     st9_jpcc,       A_16q           },
  { 0xAE,     st9_tmw,        A_wrpd_wrps     },
  { 0xAE,     st9_tmw,        A_wrpdi_wrps    },
  { 0xAE,     st9_tmw,        A_wrpd_wrpsi    },
  { 0xAE,     st9_tmw,        A_wrpdi_wrpsi   },
  { 0xAF,     st9_btjt,       A_bwr_8q_0      },
  { 0xAF,     st9_btjf,       A_bwr_8q_1      },
  { 0xB0,     st9_rlc,        A_grd           },
  { 0xB1,     st9_rlc,        A_grdi          },
  { 0xB2,     st9_ld,         A_8qxwr_wrs     },
  { 0xB3,     st9_ld,         A_wrs_8qxwr     },
  { 0xB4,     st9_ald,        A_grd_wrpip     },
  { 0xB4,     st9_ald,        A_wrpip_grd     },
  { 0xB5,     st9_ld,         A_wrd_wrpi      },
  { 0xB5,     st9_ld,         A_wrpi_wrd      },
  { 0xB6,     st9_pushuw,     A_grp_0         },
  { 0xB6,     st9_linku,      A_grp_8q        },
  { 0xB7,     st9_popuw,      A_grp_0         },
  { 0xB7,     st9_unlinku,    A_grp_1         },
  { 0xB8,     st9_ld,         A_grs           },
  { 0xB9,     st9_ld,         A_grd           },
  { 0xBA,     st9_djnz,       A_8q            },
  { 0xBB,     st9_jrcc,       A_8q            },
  { 0xBC,     st9_ld,         A_8q            },
  { 0xBD,     st9_jpcc,       A_16q           },
  { 0xBE,     st9_aldw,       A_wrpi_grp      },
  { 0xBE,     st9_aldw,       A_wrpi_16q      },
  { 0xBF01,   st9_halt,       A_IMPL          },
  { 0xBF,     st9_ldw,        A_grpd_16q_0    },
  { 0xC0,     st9_ror,        A_grd           },
  { 0xC1,     st9_ror,        A_grdi          },
  { 0xC2,     st9_ald,        A_grd_wrpim     },
  { 0xC2,     st9_ald,        A_wrpim_grd     },
  { 0xC3,     st9_aldw,       A_grpd_wrpim    },
  { 0xC3,     st9_aldw,       A_wrpim_grpd    },
  { 0xC4,     st9_ald,        A_wrd_16q       },
  { 0xC5,     st9_ald,        A_16q_wrs       },
  { 0xC6,     st9_ext,        A_grp_1         },
  { 0xC6,     st9_dwjnz,      A_grp_8q        },
  { 0xC7,     st9_srp,        A_rwn_000       },
  { 0xC7,     st9_srp0,       A_rwn_100       },
  { 0xC7,     st9_srp1,       A_rwn_101       },
  { 0xC7,     st9_spp,        A_rpn           },
  { 0xC8,     st9_ld,         A_grs           },
  { 0xC9,     st9_ld,         A_grd           },
  { 0xCA,     st9_djnz,       A_8q            },
  { 0xCB,     st9_jrcc,       A_8q            },
  { 0xCC,     st9_ld,         A_8q            },
  { 0xCD,     st9_jpcc,       A_16q           },
  { 0xCE,     st9_etrap,      A_IMPL          },
  { 0xCF,     st9_decw,       A_grpd_0        },
  { 0xD0,     st9_rrc,        A_grd           },
  { 0xD1,     st9_rrc,        A_grdi          },
  { 0xD2,     st9_call,       A_16q           },
  { 0xD3,     st9_iret,       A_IMPL          },
  { 0xD4,     st9_jp,         A_grpi          },
  { 0xD4,     st9_link,       A_grp_8q        },
  { 0xD5,     st9_aldw,       A_grpd_wrpip    },
  { 0xD5,     st9_aldw,       A_wrpip_grpd    },
  { 0xD6,     st9_ldpp,       A_wrpdip_wrpsip_00  },
  { 0xD6,     st9_lddp,       A_wrpdip_wrpsip_10  },
  { 0xD6,     st9_ldpd,       A_wrpdip_wrpsip_01  },
  { 0xD6,     st9_lddd,       A_wrpdip_wrpsip_11  },
  { 0xD7,     st9_ld,         A_wrip_wrpip    },
  { 0xD7,     st9_ld,         A_wrpip_wrip    },
  { 0xD8,     st9_ld,         A_grs           },
  { 0xD9,     st9_ld,         A_grd           },
  { 0xDA,     st9_djnz,       A_8q            },
  { 0xDB,     st9_jrcc,       A_8q            },
  { 0xDC,     st9_ld,         A_8q            },
  { 0xDD,     st9_jpcc,       A_16q           },
  { 0xDE,     st9_ldw,        A_8qxwrip_wrp   },
  { 0xDE,     st9_ldw,        A_wrp_8qxwrip   },
  { 0xDF,     st9_incw,       A_grpd_0        },
  { 0xE0,     st9_sra,        A_grd           },
  { 0xE1,     st9_sra,        A_grdi          },
  { 0xE2,     st9_aldw,       A_wrp_16q       },
  { 0xE2,     st9_aldw,       A_16q_wrp       },
  { 0xE3,     st9_ldw,        A_wrpd_wrps     },
  { 0xE3,     st9_ldw,        A_wrpdi_wrps    },
  { 0xE3,     st9_ldw,        A_wrpd_wrpsi    },
  { 0xE3,     st9_ldw,        A_wrpdi_wrpsi   },
  { 0xE4,     st9_ld,         A_wrd_wrsi      },
  { 0xE5,     st9_ld,         A_wrdi_wrs      },
  { 0xE6,     st9_ald,        A_wrdi_grs      },
  { 0xE7,     st9_ald,        A_grd_wrsi      },
  { 0xE8,     st9_ld,         A_grs           },
  { 0xE9,     st9_ld,         A_grd           },
  { 0xEA,     st9_djnz,       A_8q            },
  { 0xEB,     st9_jrcc,       A_8q            },
  { 0xEC,     st9_ld,         A_8q            },
  { 0xED,     st9_jpcc,       A_16q           },
  { 0xEE,     st9_spm,        A_IMPL          },
  { 0xEF01,   st9_wfi,        A_IMPL          },
  { 0xEF31,   st9_eret,       A_IMPL          },
  { 0xEF,     st9_ldw,        A_grpd_grps     },
  { 0xF0,     st9_swap,       A_grd           },
  { 0xF1,     st9_swap,       A_grdi          },
  { 0xF2,     st9_bld,        A_wrb_wrb_10    },
  { 0xF2,     st9_bld,        A_wrb_nwrb_11   },
  { 0xF2,     st9_btset,      A_wrb           },
  { 0xF3,     st9_ald,        A_wrpi_8q       },
  { 0xF4,     st9_ld,         A_grd_grs       },
  { 0xF5,     st9_ld,         A_grd_8q        },
  { 0xF601,   st9_rets,       A_IMPL          },
  { 0xF6,     st9_btset,      A_wrbi          },
  { 0xF7,     st9_push,       A_grsi          },
  { 0xF8,     st9_ld,         A_grs           },
  { 0xF9,     st9_ld,         A_grd           },
  { 0xFA,     st9_djnz,       A_8q            },
  { 0xFB,     st9_jrcc,       A_8q            },
  { 0xFC,     st9_ld,         A_8q            },
  { 0xFD,     st9_jpcc,       A_16q           },
  { 0xFE,     st9_sdm,        A_IMPL          },
  { 0xFF,     st9_nop,        A_IMPL          }
};

//----------------------------------------------------------------------
static const opcode *find_opcode(insn_t &insn, int _code)
{
  for ( int i = 0; i < qnumber(opcodes); i++ )
  {
    // is the opcode coded in a word ?
    bool need_another_byte = ((opcodes[i].code & 0xFF00) >> 8) != 0;

    int code = need_another_byte
             ? (_code << 8) | get_byte(insn.ea + insn.size)
             : _code;

    // opcode is wrong
    if ( opcodes[i].code != code )
      continue;

    int next_byte = get_byte(insn.ea + insn.size + (need_another_byte ? 1 : 0));
    int mask = 0;
    int value = 0;

    switch ( opcodes[i].addr )
    {
      // 0000000X (X == 0)
      case A_grpd_grps:
      case A_16qxwrp_16q:
      case A_16qxwrp_gr:
      case A_wrip_gr:
      case A_gr_16qxwrp:
      case A_grpd_0:
      case A_grps:
      case A_wrpip_grd:
      case A_wrd_wrpi:
      case A_grp_0:
      case A_wrpi_16q:
      case A_grpd_16q_0:
      case A_wrpim_grd:
      case A_wrpim_grpd:
      case A_grpi:
      case A_wrpip_grpd:
      case A_wrpip_wrip:
      case A_wrp_16q:
        mask = 0x01;
        value = 0x00;
        break;

      case A_wrb:
        mask = 0x10;
        value = 0x00;
        break;

      // 0000000X (X == 1)
      case A_grpd_16q_1:
      case A_8qxwrp_16q:
      case A_8qxwrp_gr:
      case A_gr_wrpi:
      case A_gr_8qxwrp:
      case A_grpd_1:
      case A_grpdi:
      case A_grd_wrpip:
      case A_wrpi_wrd:
      case A_grp_1:
      case A_wrpi_grp:
      case A_grd_wrpim:
      case A_grpd_wrpim:
      case A_grpd_wrpip:
      case A_wrip_wrpip:
      case A_16q_wrp:
        mask = 0x01;
        value = 0x01;
        break;

      // 00000XXX (XXX = 000)
      case A_rwn_000:
        mask = 0x07;
        value = 0x00;
        break;

      // 00000XXX (XXX = 100)
      case A_rwn_100:
        mask = 0x07;
        value = 0x04;
        break;

      // 00000XXX (XXX = 101)
      case A_rwn_101:
        mask = 0x07;
        value = 0x05;
        break;

      // XY000000 (XY == 01)
      case A_seg_16q_01:
        mask = 0xC0;
        value = 0x40;
        break;

      // XY000000 (XY == 11)
      case A_seg_16q_11:
        mask = 0xC0;
        value = 0xC0;
        break;

      // 000000XY (XY = 10)
      case A_rpn:
        mask = 0x03;
        value = 0x02;
        break;

      // 000X0000 (X == 0)
      case A_wrd_wrpsi_8q_0:
      case A_wrp_8qxwrip:
      case A_bwr_8q_0:
        mask = 0x10;
        value = 0x00;
        break;

      // 000X0000 (X == 1)
      case A_wrd_wrpsi_8q_1:
      case A_8qxwrip_wrp:
      case A_bwr_8q_1:
        mask = 0x10;
        value = 0x10;
        break;

      // XXXX0000 (XXXX = 0100)
      case A_gri_wrip_01:
        mask = 0xF0;
        value = 0x40;
        break;

      // XXXX0000 (XXXX = 1100)
      case A_gri_wrip_11:
        mask = 0xF0;
        value = 0xC0;
        break;

      // 000X000Y (X == 0 && Y == 0)
      case A_wrpd_wrps:
      case A_wrpdip_wrpsip_00:
      case A_wrp_wrpxwrp:
      case A_wrbi:
        mask = 0x11;
        value = 0x00;
        break;

      // 000X000Y (X == 1 && Y == 0)
      case A_wrpdi_wrps:
      case A_wrpdip_wrpsip_10:
      case A_wr_wrpxwrp:
        mask = 0x11;
        value = 0x10;
        break;

      // 000X000Y (X == 0 && Y == 1)
      case A_wrpd_wrpsi:
      case A_wrpdip_wrpsip_01:
      case A_wrpxwrp_wrp:
        mask = 0x11;
        value = 0x01;
        break;

      // 000X000Y (X == 1 && Y == 1)
      case A_wrpdi_wrpsi:
      case A_wrpdip_wrpsip_11:
      case A_wrpxwrp_wr:
        mask = 0x11;
        value = 0x11;
        break;

      // 0000X (X = 0001)
      case A_16q_8q:
      case A_16q_16q:
        mask = 0x0F;
        value = 0x01;
        break;

      // 0000000X (X == 1) && 3th byte MSB == 1
      case A_8qxwrp_grp:
        if ( (get_byte(insn.ea + insn.size + 2) & 0x01) == 1 )
        {
          mask = 0x01;
          value = 0x01;
        }
        else
          mask = -1;
        break;

      // 0000000X (X == 1) && 3th byte MSB == 0
      case A_grp_8qxwrp:
        if ( (get_byte(insn.ea + insn.size + 2) & 0x01) == 0 )
        {
          mask = 0x01;
          value = 0x01;
        }
        else
          mask = -1;
        break;

      // 0000000X (X == 1) && 4th byte MSB == 1
      case A_16qxwrp_grp:
        if ( (get_byte(insn.ea + insn.size + 3) & 0x01) == 1 )
        {
          mask = 0x01;
          value = 0x00;
        }
        else
          mask = -1;
        break;

      // 0000000X (X == 1) && 4th byte MSB == 0
      case A_grp_16qxwrp:
        if ( (get_byte(insn.ea + insn.size + 3) & 0x01) == 0 )
        {
          mask = 0x01;
          value = 0x00;
        }
        else
          mask = -1;
        break;

      // 2nd byte MSB == 0
      case A_8qxgrpi:
        if ( (get_byte(insn.ea + insn.size + 1) & 0x01) != 0 )
          mask = -1;
        break;

      // 2nd byte MSB == 1
      case A_16qxgrpi:
        if ( (get_byte(insn.ea + insn.size + 1) & 0x01) != 1 )
          mask = -1;
        break;

      // NOTE: it seems that there is an error in the manual :
      // rd.b,rs.b and rd.b,rs.!b opcodes are inversed !

      // 000X0000 (X == 1) + 0x000Y0000 (Y == 0)
      case A_wrb_wrb_10:
      case A_wrb_nwrb_10:
        if ( (get_byte(insn.ea + insn.size + 1) & 0x10) == 0 )
        {
          mask = 0x10;
          value = 0x10;
        }
        else
          mask = -1;
        break;

      // 000X0000 (X == 1) + 0x000Y0000 (Y == 1)
      case A_wrb_wrb_11:
      case A_wrb_nwrb_11:
        if ( (get_byte(insn.ea + insn.size + 1) & 0x10) == 0x10 )
        {
          mask = 0x10;
          value = 0x10;
        }
        else
          mask = -1;
        break;

    }

    // addr mode is wrong
    if ( mask != 0 && (mask == -1 || (next_byte & mask) != value) )
      continue;

    // Yahoo !
    if ( need_another_byte )
      insn.size++;

    return &opcodes[i];
  }
  return nullptr;
}

//----------------------------------------------------------------------
static int get_condition_code(int code)
{
  switch ( code )
  {
    case 0x0B:      // JR F,N
    case 0x0D:      // JP F,NN
      return cF;

    case 0x1B:      // JR LT,N
    case 0x1D:      // JP LT,NN
      return cLT;

    case 0x2B:      // JR LE,N
    case 0x2D:      // JP LE,NN
      return cLE;

    case 0x3B:      // JR ULE,N
    case 0x3D:      // JP ULE,NN
      return cULE;

    case 0x4B:      // JR OV,N
    case 0x4D:      // JP OV,NN
      return cOV;

    case 0x5B:      // JR MI,N
    case 0x5D:      // JP MI,NN
      return cMI;

    case 0x6B:      // JR EQ,N
    case 0x6D:      // JP EQ,NN
      return cEQ;

    // XXX
    // According to the manual, 0x7X is related
    // to the UL condition code.
    // JRUL/JPUL cannot be assembled (unknown instruction).
    // objdump9 disassemble 0x7X with the C condition code,
    // therefore we use it instead of UL.
    case 0x7B:      // JR C,N
    case 0x7D:      // JP C,NN
      return cC;

    case 0x8B:      // JR T,N
    case 0x8D:      // JP T,NN
      return cT;

    case 0x9B:      // JR GE,N
    case 0x9D:      // JP GE,NN
      return cGE;

    case 0xAB:      // JR GT,N
    case 0xAD:      // JP GT,NN
      return cGT;

    case 0xBB:      // JR UGT,N
    case 0xBD:      // JP UGT,NN
      return cUGT;

    case 0xCB:      // JR NOV,N
    case 0xCD:      // JP NOV,NN
      return cNOV;

    case 0xDB:      // JR PL,N
    case 0xDD:      // JP PL,NN
      return cPL;

    case 0xEB:      // JR NE,N
    case 0xED:      // JP NE,NN
      return cNE;

    case 0xFB:      // JR NC,N
    case 0xFD:      // JP NC,NN
      return cNC;
  }
  return cUNKNOWN;
}

//----------------------------------------------------------------------
static uint16 get_working_register(int code)
{
  uchar reg_id = (code & 0xF0) >> 4;
  return rr0 + reg_id;
}

//----------------------------------------------------------------------
// general register: if the 4 Most Significant Bits (MSB) are Dh then the 4 Least Significant
// Bits (LSB) specify a working register
static uint16 get_general_register(int code, bool pair = false)
{
  uchar reg_grp = (code & 0xF0) >> 4;
  // group D (R208-R223) refers to working registers

  if ( reg_grp == 0xD )
    return (pair ? rrr0 : rr0) + (code & 0x0F);
  else
    return (pair ? rRR0 : rR0) + code;
}

//----------------------------------------------------------------------
static uint16 get_alu_insn(const insn_t &insn, int code)
{
  int insn_id = (code & 0xF0) >> 4;

  QASSERT(10031, insn.itype == st9_ald || insn.itype == st9_aldw);

  bool long_insn = insn.itype == st9_aldw;

  if ( !long_insn )
  {
    switch ( insn_id )
    {
      case 0x0: return st9_or;
      case 0x1: return st9_and;
      case 0x2: return st9_sbc;
      case 0x3: return st9_adc;
      case 0x4: return st9_add;
      case 0x5: return st9_sub;
      case 0x6: return st9_xor;
      case 0x8: return st9_cp;
      case 0x9: return st9_cp;
      case 0xA: return st9_tm;
      case 0xF: return st9_ld;
    }
  }
  else
  {
    switch ( insn_id )
    {
      case 0x0: return st9_orw;
      case 0x1: return st9_andw;
      case 0x2: return st9_sbcw;
      case 0x3: return st9_adcw;
      case 0x4: return st9_addw;
      case 0x5: return st9_subw;
      case 0x6: return st9_xorw;
      case 0x8: return st9_cpw;
      case 0x9: return st9_cpw;
      case 0xA: return st9_tmw;
      case 0xF: return st9_ldw;
    }
  }
  return st9_null;
}

//----------------------------------------------------------------------
// fill instruction flag
static void set_flag(insn_t &insn, int flag)
{
  insn.auxpref |= flag;
}

//----------------------------------------------------------------------
// fill operand flag
static void set_flag(op_t &x, int flag)
{
  x.specflag1 |= flag;
}

//----------------------------------------------------------------------
// fill an operand as a register
static void set_reg(op_t &op, uint16 reg, int flag = 0)
{
  op.type = o_reg;
  op.reg = reg;
  op.dtype = dt_byte;
  if ( flag )
    set_flag(op, flag);
}

//----------------------------------------------------------------------
// fill an operand as an immediate value
static void set_imm(op_t &op, int val, char d_typ, int flag = 0)
{
  op.type = o_imm;
  op.value = val;
  op.dtype = d_typ;
  if ( flag )
    set_flag(op, flag);
}

//----------------------------------------------------------------------
// fill an operand as a displacement
static void set_displ(op_t &op, optype_t a1_t, uint16 a1, optype_t a2_t, uint16 a2, char dtyp = dt_byte)
{
  op.type = o_displ;
  op.reg = 0;
  switch ( a1_t )
  {
    case o_reg:
      op.reg = a1;
      break;

    case o_mem:
      op.addr = a1;
      break;

    default:
      INTERR(10032);
  }
  switch ( a2_t )
  {
    case o_reg:
      if ( op.reg == 0 )
        op.reg = a2;
      else
        INTERR(10033);
      break;

    default:
      INTERR(10034);
  }
  op.dtype = dtyp;
}

//----------------------------------------------------------------------
// fill an operand as a phrase
static void set_phrase(op_t &op, st9_phrases phrase, uint16 reg1, int reg2 = -1, char dtyp = dt_byte)
{
  op.type = o_phrase;
  op.reg = reg1;
  op.specflag2 = phrase;
  op.dtype = dtyp;
  if ( reg2 != -1 )
  {
    op.specflag2 = (reg2 & 0xFF00) >> 8;
    op.specflag3 = (reg2 & 0x00FF);
  }
}

//----------------------------------------------------------------------
// add a bit number to a register operand
static void set_bit(op_t &op, int bit, int flag = 0)
{
  op.value = bit;
  if ( flag )
    set_flag(op, flag);
}

//----------------------------------------------------------------------
// fill an operand as an address (data or code)
static void set_addr(op_t &op, optype_t type, ea_t addr, char dtyp = dt_byte)
{
  QASSERT(10035, type == o_mem || type == o_near || type == o_far); // bad optype_t in set_addr()
  op.type = type;
  op.addr = addr;
  op.dtype = dtyp;
}

//----------------------------------------------------------------------
static uint16 my_next_word(insn_t &insn)
{
  uchar b1 = insn.get_next_byte();
  uchar b2 = insn.get_next_byte();
  return b1 | (b2 << 8);
}

//----------------------------------------------------------------------
static void fill_cmd(insn_t &insn, int byte, const opcode *op)
{
  QASSERT(10036, op != nullptr);
  insn.itype = op->insn;

  switch ( op->addr )
  {
    // Implied
    case A_IMPL:
      // Nothing to do !
      break;

    // rd,rs
    case A_wrd_wrs:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + ((byte & 0xF0) >> 4));
      set_reg(insn.Op2, rr0 + (byte & 0x0F));
      break;

    // rd,(rs)
    case A_wrd_wrsi:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + ((byte & 0xF0) >> 4));
      set_reg(insn.Op2, rr0 + (byte & 0x0F), OP_IS_IND);
      break;

    // (rd),rs
    case A_wrdi_wrs:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + ((byte & 0xF0) >> 4), OP_IS_IND);
      set_reg(insn.Op2, rr0 + (byte & 0x0F));
      break;

    // (rd),Rs
    case A_wrdi_grs:
      QASSERT(10037, insn.itype == st9_ald);
      set_reg(insn.Op2, get_general_register(insn.get_next_byte()));
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rr0 + (byte & 0x0F), OP_IS_IND);
      break;

    // Rd,(rs)
    case A_grd_wrsi:
      QASSERT(10038, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rr0 + (byte & 0x0F), OP_IS_IND);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // Rs,Rd
    case A_grs_grd:
    // Rd,Rs
    case A_grd_grs:
      set_reg(insn.Op2, get_general_register(insn.get_next_byte()));
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // Rd,#N
    case A_grd_8q:
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      set_imm(insn.Op2, insn.get_next_byte(), dt_byte);
      break;

    // RRd,RRs
    case A_grpd_grps:
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true));
      set_reg(insn.Op2, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // RRd,#NN
    case A_grpd_16q_0:
    case A_grpd_16q_1:
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true));
      set_imm(insn.Op2, insn.get_next_word(), dt_word);
      break;

    // RR,N
    case A_grp_8q:
      {
        byte = insn.get_next_byte();
        uint16 reg = get_general_register(byte & 0xFE, true);
        if ( insn.itype == st9_dwjnz )
        {
          set_addr(insn.Op2, o_near, insn.get_next_byte());
          insn.Op2.addr = (signed char) insn.Op2.addr + insn.ip + insn.size;
        }
        else
        { // link or linku
          set_imm(insn.Op2, 0xFF - insn.get_next_byte(), dt_byte);
        }
        set_reg(insn.Op1, reg);
      }
      break;

    // Rs
    case A_grs:
      if ( insn.itype == st9_ld )
      {
        set_reg(insn.Op1, get_working_register(byte));
        set_reg(insn.Op2, get_general_register(insn.get_next_byte()));
      }
      else
        set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // Rd
    case A_grd:
      if ( insn.itype == st9_ld )
      {
        set_reg(insn.Op2, get_working_register(byte));
        set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      }
      else
        set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // (R)
    case A_grdi:
    case A_grsi:
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()), OP_IS_IND);
      break;

    // RR
    case A_grp_0:
    case A_grp_1:
    case A_grps:
    case A_grpd_0:
    case A_grpd_1:
      {
        byte = insn.get_next_byte();
        uint16 reg = get_general_register((byte & 0xFE), true);
        set_reg(insn.Op1, reg);
      }
      break;

    // (RR)
    case A_grpi:
    case A_grpdi:
      set_reg(insn.Op1, get_general_register((insn.get_next_byte() & 0xFE), true), OP_IS_IND);
      break;

    // N
    case A_8q:
      if ( is_jmp_cc(insn.itype) )
      {
        set_flag(insn, get_condition_code(byte));
        set_addr(insn.Op1, o_near, insn.get_next_byte());
        insn.Op1.addr = (signed char) insn.Op1.addr + insn.ip + insn.size;
      }
      else if ( insn.itype == st9_djnz )
      {
        set_reg(insn.Op1, get_working_register(byte));
        set_addr(insn.Op2, o_near, insn.get_next_byte());
        insn.Op2.addr = (signed char) insn.Op2.addr + insn.ip + insn.size;
      }
      else if ( insn.itype == st9_ld )
      {
        set_reg(insn.Op1, get_working_register(byte));
        set_imm(insn.Op2, insn.get_next_byte(), dt_byte);
        insn.Op2.addr = (signed char) insn.Op2.addr + insn.ip + insn.size;
      }
      else if ( insn.itype == st9_push
             || insn.itype == st9_pushu
             || insn.itype == st9_pushw )
      {
        set_imm(insn.Op1, insn.get_next_byte(), dt_byte);
      }
      else
      {
        set_addr(insn.Op1, o_mem, insn.get_next_byte());
        insn.Op1.addr = (signed char) insn.Op1.addr + insn.ip + insn.size;
      }
      break;

    // NN
    case A_16q:
      if ( is_jmp_cc(insn.itype) || insn.itype == st9_call )
      {
        if ( is_jmp_cc(insn.itype) )
          set_flag(insn, get_condition_code(byte));
        set_addr(insn.Op1, o_near, insn.get_next_word());
      }
      else if ( insn.itype == st9_push
             || insn.itype == st9_pushu
             || insn.itype == st9_pushw
             || insn.itype == st9_pushuw )
      {
        set_imm(insn.Op1, insn.get_next_word(), dt_word);
      }
      else
      {
        set_addr(insn.Op1, o_mem, insn.get_next_word());
      }
      break;

    // rrd,rrs
    case A_wrpd_wrps:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + ((byte & 0xE0) >> 4));
      set_reg(insn.Op2, rrr0 + (byte & 0x0E));
      break;

    // (rrd),rrs
    case A_wrpdi_wrps:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + ((byte & 0xE0) >> 4), OP_IS_IND);
      set_reg(insn.Op2, rrr0 + (byte & 0x0E));
      break;

    // rrd,(rrs)
    case A_wrpd_wrpsi:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + ((byte & 0xE0) >> 4));
      set_reg(insn.Op2, rrr0 + (byte & 0x0E), OP_IS_IND);
      break;

    // (rrd),(rrs)
    case A_wrpdi_wrpsi:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + ((byte & 0xE0) >> 4), OP_IS_IND);
      set_reg(insn.Op2, rrr0 + (byte & 0x0E), OP_IS_IND);
      break;

    // rrd,rs
    case A_wrpd_wrs:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + ((byte & 0xE0) >> 4));
      set_reg(insn.Op2, rr0 + (byte & 0x0F));
      break;

    // rd,(rrs)
    case A_wrd_wrpi:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + ((byte & 0xF0) >> 4));
      set_reg(insn.Op2, rrr0 + (byte & 0x0E), OP_IS_IND);
      break;

    // (rrs),rd
    case A_wrpi_wrd:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_reg(insn.Op2, rr0 + ((byte & 0xF0) >> 4));
      break;

    // Nd(rr),#NNs
    case A_8qxwrp_16q:
      QASSERT(10039, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op1, o_mem, char(insn.get_next_byte()), o_reg, rrr0 + (byte & 0x0E), dt_word);
      set_imm(insn.Op2, insn.get_next_word(), dt_word);
      break;

    // NNd(rr),#NNs
    case A_16qxwrp_16q:
      QASSERT(10040, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op1, o_mem, short(insn.get_next_word()), o_reg, rrr0 + (byte & 0x0E), dt_word);
      set_imm(insn.Op2, insn.get_next_word(), dt_word);
      break;

    // N(rr),R
    case A_8qxwrp_gr:
      QASSERT(10041, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op1, o_mem, char(insn.get_next_byte()), o_reg, rrr0 + (byte & 0x0E));
      set_reg(insn.Op2, get_general_register(insn.get_next_byte()));
      break;

    // NN(rr),R
    case A_16qxwrp_gr:
      QASSERT(10042, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op1, o_mem, short(insn.get_next_word()), o_reg, rrr0 + (byte & 0x0E));
      set_reg(insn.Op2, get_general_register(insn.get_next_byte()));
      break;

    // NNd,#Ns
    case A_16q_8q:
      QASSERT(10043, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_imm(insn.Op2, insn.get_next_byte(), dt_byte);
      set_addr(insn.Op1, o_mem, insn.get_next_word());
      break;

    // NNd,#NNs
    case A_16q_16q:
      QASSERT(10044, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_imm(insn.Op2, insn.get_next_word(), dt_word);
      set_addr(insn.Op1, o_mem, insn.get_next_word(), dt_word);
      break;

    // rd,rrs(rrx)
    case A_wr_wrpxwrp:
      QASSERT(10045, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      set_phrase(insn.Op2, fDISP, rrr0 + ((byte & 0xE0) >> 4), rrr0 + (byte & 0x0E));
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rr0 + (byte & 0x0F));
      break;

    // rrd(rrx),rs
    case A_wrpxwrp_wr:
      QASSERT(10046, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      set_phrase(insn.Op1, fDISP, rrr0 + ((byte & 0xE0) >> 4), rrr0 + (byte & 0x0E));
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rr0 + (byte & 0x0F));
      break;

    // rrd,rrs(rrx)
    case A_wrp_wrpxwrp:
      QASSERT(10047, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      set_phrase(insn.Op2, fDISP, rrr0 + ((byte & 0xE0) >> 4), rrr0 + (byte & 0x0E), dt_word);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rrr0 + (byte & 0x0E));
      break;

    // rrd(rrx),rrs
    case A_wrpxwrp_wrp:
      QASSERT(10048, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      set_phrase(insn.Op1, fDISP, rrr0 + ((byte & 0xE0) >> 4), rrr0 + (byte & 0x0E), dt_word);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rrr0 + (byte & 0x0E));
      break;

    // Rd,(rrs)
    case A_gr_wrpi:
      QASSERT(10049, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // (rrd),Rs
    case A_wrip_gr:
      QASSERT(10050, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_reg(insn.Op2, get_general_register(insn.get_next_byte()));
      break;

    // (RRd),(rrs)
    case A_grpi_wrip:
      QASSERT(10051, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true), OP_IS_IND);
      break;

    // (R),(rr)
    case A_gri_wrip_01:
    case A_gri_wrip_11:
      set_reg(insn.Op2, rrr0 + (insn.get_next_byte() & 0x0E), OP_IS_IND);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()), OP_IS_IND);
      break;

    // Rd,N(rrx)
    case A_gr_8qxwrp:
      QASSERT(10052, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op2, o_mem, char(insn.get_next_byte()), o_reg, rrr0 + (byte & 0x0E));
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // Rd,NN(rrx)
    case A_gr_16qxwrp:
      QASSERT(10053, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op2, o_mem, short(insn.get_next_word()), o_reg, rrr0 + (byte & 0x0E));
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // RRd,(rrs)
    case A_grp_wrpi:
      QASSERT(10054, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // N(rrx),RRs
    case A_8qxwrp_grp:
      QASSERT(10055, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op1, o_mem, char(insn.get_next_byte()), o_reg, rrr0 + (byte & 0x0E), dt_word);
      set_reg(insn.Op2, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // RRd,N(rrx)
    case A_grp_8qxwrp:
      QASSERT(10056, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op2, o_mem, char(insn.get_next_byte()), o_reg, rrr0 + (byte & 0x0E), dt_word);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // NN(rrx),RRs
    case A_16qxwrp_grp:
      QASSERT(10057, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op1, o_mem, short(insn.get_next_word()), o_reg, rrr0 + (byte & 0x0E), dt_word);
      set_reg(insn.Op2, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // RRd,NN(rrx)
    case A_grp_16qxwrp:
      QASSERT(10058, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_displ(insn.Op2, o_mem, short(insn.get_next_word()), o_reg, rrr0 + (byte & 0x0E), dt_word);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // N(RRx)
    case A_8qxgrpi:
      byte = insn.get_next_byte();
      set_displ(insn.Op1, o_mem, char(insn.get_next_byte()), o_reg, get_general_register(byte & 0xFE, true));
      break;

    // NN(RRx)
    case A_16qxgrpi:
      byte = insn.get_next_byte();
      // this word is coded with little endian
      set_displ(insn.Op1, o_mem, short(my_next_word(insn)), o_reg, get_general_register(byte & 0xFE, true));
      break;

    // rd,(rrs),N
    case A_wrd_wrpsi_8q_0:
    case A_wrd_wrpsi_8q_1:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + (byte & 0x0F));
      set_reg(insn.Op2, rrr0 + ((byte & 0xE0) >> 4), OP_IS_IND);
      set_imm(insn.Op3, insn.get_next_byte(), dt_byte);
      break;

    // RRd,(rs)
    case A_grpd_wrsi:
      QASSERT(10059, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rr0 + (byte & 0x0F), OP_IS_IND);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // N(rx),rs
    case A_8qxwr_wrs:
      byte = insn.get_next_byte();
      set_reg(insn.Op2, rr0 + ((byte & 0xF0) >> 4));
      set_displ(insn.Op1, o_mem, char(insn.get_next_byte()), o_reg, rr0 + (byte & 0x0F));
      break;

    // rs,N(rx)
    case A_wrs_8qxwr:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + ((byte & 0xF0) >> 4));
      set_displ(insn.Op2, o_mem, char(insn.get_next_byte()), o_reg, rr0 + (byte & 0x0F));
      break;

    // Rd,(rrs)+
    case A_grd_wrpip:
      QASSERT(10060, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op2, fPI, rrr0 + (byte & 0x0E));
      set_reg(insn.Op1, get_general_register(insn.get_next_byte()));
      break;

    // (rrs)+,Rd
    case A_wrpip_grd:
      QASSERT(10061, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op1, fPI, rrr0 + (byte & 0x0E));
      set_reg(insn.Op2, rR0 + insn.get_next_byte());
      break;

    // (rr),RR
    case A_wrpi_grp:
      QASSERT(10062, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_reg(insn.Op2, rRR0 + (insn.get_next_byte() & 0x0E));
      break;

    // (rr),#NN
    case A_wrpi_16q:
      QASSERT(10063, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_imm(insn.Op2, insn.get_next_word(), dt_word);
      break;

    // Rd,-(rrs)
    case A_grd_wrpim:
      QASSERT(10064, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op2, fPD, rrr0 + (byte & 0x0E));
      set_reg(insn.Op1, rR0 + insn.get_next_byte());
      break;

    // -(rrs),Rd
    case A_wrpim_grd:
      QASSERT(10065, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op1, fPD, rrr0 + (byte & 0x0E));
      set_reg(insn.Op2, rR0 + insn.get_next_byte());
      break;

    // RRd,-(rrs)
    case A_grpd_wrpim:
      QASSERT(10066, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op2, fPD, rrr0 + (byte & 0x0E), -1, dt_word);
      set_reg(insn.Op1, rRR0 + insn.get_next_byte());
      break;

    // -(rrs),RRd
    case A_wrpim_grpd:
      QASSERT(10067, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op1, fPD, rrr0 + (byte & 0x0E), -1, dt_word);
      set_reg(insn.Op2, rRR0 + insn.get_next_byte());
      break;

    // NN,rs
    case A_16q_wrs:
      QASSERT(10068, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rr0 + (byte & 0x0F));
      set_addr(insn.Op1, o_mem, insn.get_next_word());
      break;

    // rd,NN
    case A_wrd_16q:
      QASSERT(10069, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rr0 + (byte & 0x0F));
      set_addr(insn.Op2, o_mem, insn.get_next_word());
      break;

    // (rd)+,(rrs)+
    case A_wrip_wrpip:
      byte = insn.get_next_byte();
      set_phrase(insn.Op1, fPI, rr0 + ((byte & 0xE0) >> 4));
      set_phrase(insn.Op2, fPI, rrr0 + (byte & 0x0E));
      break;

    // (rrs)+,(rd)+
    case A_wrpip_wrip:
      byte = insn.get_next_byte();
      set_phrase(insn.Op2, fPI, rr0 + ((byte & 0xE0) >> 4));
      set_phrase(insn.Op1, fPI, rrr0 + (byte & 0x0E));
      break;

    // (rrd)+,(rrs)+
    case A_wrpdip_wrpsip_00:
    case A_wrpdip_wrpsip_10:
    case A_wrpdip_wrpsip_01:
    case A_wrpdip_wrpsip_11:
      byte = insn.get_next_byte();
      set_phrase(insn.Op1, fPI, rrr0 + ((byte & 0xE0) >> 4));
      set_phrase(insn.Op2, fPI, rrr0 + (byte & 0x0E));
      break;

    // RRd,(rrs)+
    case A_grpd_wrpip:
      QASSERT(10070, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op2, fPI, rrr0 + (byte & 0x0E), -1, dt_word);
      set_reg(insn.Op1, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // (rrd)+,RRs
    case A_wrpip_grpd:
      QASSERT(10071, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_phrase(insn.Op1, fPI, rrr0 + (byte & 0x0E), -1, dt_word);
      set_reg(insn.Op2, get_general_register(insn.get_next_byte() & 0xFE, true));
      break;

    // N(rx),rrs
    case A_8qxwrip_wrp:
      byte = insn.get_next_byte();
      set_displ(insn.Op1, o_mem, char(insn.get_next_byte()), o_reg, rr0 + (byte & 0x0F));
      set_reg(insn.Op2, rrr0 + ((byte & 0xE0) >> 4));
      break;

    // rrd,N(rx)
    case A_wrp_8qxwrip:
      byte = insn.get_next_byte();
      set_displ(insn.Op2, o_mem, char(insn.get_next_byte()), o_reg, rr0 + (byte & 0x0F));
      set_reg(insn.Op1, rrr0 + ((byte & 0xE0) >> 4));
      break;

    // rrd,NN
    case A_wrp_16q:
      QASSERT(10072, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rrr0 + (byte & 0x0E));
      set_addr(insn.Op2, o_mem, insn.get_next_word(), dt_word);
      break;

    // NN,rrs
    case A_16q_wrp:
      QASSERT(10073, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op2, rrr0 + (byte & 0x0E));
      set_addr(insn.Op1, o_mem, insn.get_next_word(), dt_word);
      break;

    // rrh,rrl,RRs
    case A_wrp_wrp_grp:
      set_reg(insn.Op3, rRR0 + (insn.get_next_byte() & 0x0E));
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + ((byte & 0xE0) >> 4));
      set_reg(insn.Op2, rrr0 + (byte & 0x0E));
      break;

    // (rd),RRs
    case A_wrdi_grp:
      QASSERT(10074, insn.itype == st9_aldw);
      byte = insn.get_next_byte();
      set_reg(insn.Op2, rRR0 + (byte & 0x0E));
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rr0 + (byte & 0x0F), OP_IS_IND);
      break;

    // (rrd),#N
    case A_wrpi_8q:
      QASSERT(10075, insn.itype == st9_ald);
      byte = insn.get_next_byte();
      insn.itype = get_alu_insn(insn, byte);
      set_reg(insn.Op1, rrr0 + (byte & 0x0E), OP_IS_IND);
      set_imm(insn.Op2, insn.get_next_byte(), dt_byte);
      break;

#define BIT_OP_1    (insn.itype != st9_bld ? insn.Op1 : insn.Op2)
#define BIT_OP_2    (insn.itype != st9_bld ? insn.Op2 : insn.Op1)

    // rd.b,rs.b
    case A_wrb_wrb_10:
    case A_wrb_wrb_11:
      byte = insn.get_next_byte();
      set_reg(BIT_OP_1, rr0 + (byte & 0x0F), OP_REG_WITH_BIT);
      set_bit(BIT_OP_1, (byte & 0xE0) >> 5);
      byte = insn.get_next_byte();
      set_reg(BIT_OP_2, rr0 + (byte & 0x0F), OP_REG_WITH_BIT);
      set_bit(BIT_OP_2, (byte & 0xE0) >> 5);
      break;

    // rd.b,rs.!b
    case A_wrb_nwrb_10:
    case A_wrb_nwrb_11:
      byte = insn.get_next_byte();
      set_reg(BIT_OP_1, rr0 + (byte & 0x0F), OP_REG_WITH_BIT);
      set_bit(BIT_OP_1, (byte & 0xE0) >> 5, insn.itype == st9_bld ? OP_BIT_COMPL : 0);
      byte = insn.get_next_byte();
      set_reg(BIT_OP_2, rr0 + (byte & 0x0F), OP_REG_WITH_BIT);
      set_bit(BIT_OP_2, (byte & 0xE0) >> 5, insn.itype != st9_bld ? OP_BIT_COMPL : 0);
      break;

    // rd.b
    case A_wrb:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + (byte & 0x0F), OP_REG_WITH_BIT);
      set_bit(insn.Op1, (byte & 0xE0) >> 5);
      break;

    // (rr).bd
    case A_wrbi:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rrr0 + (byte & 0x0F), OP_REG_WITH_BIT | OP_IS_IND);
      set_bit(insn.Op1, (byte & 0xE0) >> 5);
      break;

    // b.rd,N
    case A_bwr_8q_0:
    case A_bwr_8q_1:
      byte = insn.get_next_byte();
      set_reg(insn.Op1, rr0 + (byte & 0x0F), OP_REG_WITH_BIT);
      set_bit(insn.Op1, (byte & 0xE0) >> 5);
      set_addr(insn.Op2, o_near, insn.get_next_byte());
      insn.Op2.addr = (signed char) insn.Op2.addr + insn.ip + insn.size;
      break;

    // nnnnnn,NN (calls, jps)
    case A_seg_16q_01:
    case A_seg_16q_11:
      {
        uint8 seg = insn.get_next_byte() & 0x3F;
        uint16 dst = insn.get_next_word();
        ea_t fardest = (seg<<16) |dst;
        if ( is_mapped(fardest) )
        {
          set_addr(insn.Op1, o_far, fardest);
        }
        else
        {
          set_imm(insn.Op1, seg, dt_byte, OP_IMM_NO_SHIFT);
          set_addr(insn.Op2, o_near, dst);
        }

      }
      break;

    // wwwww
    case A_rwn_000:
    case A_rwn_100:
    case A_rwn_101:
      set_imm(insn.Op1, (insn.get_next_byte() & 0xF8) >> 3, dt_byte);
      break;

    // pppppp
    case A_rpn:
      set_imm(insn.Op1, (insn.get_next_byte() & 0xFC) >> 2, dt_byte);
      break;
  }
}

//----------------------------------------------------------------------
// analyze an instruction
int idaapi st9_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  int byte = insn.get_next_byte();

  const opcode *op = find_opcode(insn, byte);
  if ( op == nullptr )
    return 0;

  fill_cmd(insn, byte, op);

  return insn.size;
}

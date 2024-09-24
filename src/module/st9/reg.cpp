
#include "st9.hpp"
#include <cvt64.hpp>

#include <segregs.hpp>
int data_id;

const char *const ConditionCodes[] =
{
  "UNKNOWN",
  "f",         // always false
  "t",         // always true
  "c",         // carry
  "nc",        // not carry
  "z",         // zero
  "nz",        // not zero
  "pl",        // plus
  "mi",        // minus
  "ov",        // overflow
  "nov",       // no overflow
  "eq",        // equal
  "ne",        // not equal
  "ge",        // greater than or equal
  "lt",        // less than
  "gt",        // greater than
  "le",        // less than or equal
  "uge",       // unsigned greated than or equal
  "ul",        // unsigned less than
  "ugt",       // unsigned greater than
  "ule"        // unsigned less than or equal
};

// ST9 registers names
static const char *const src_RegNames[] =
{
  "R0",
  "R1",
  "R2",
  "R3",
  "R4",
  "R5",
  "R6",
  "R7",
  "R8",
  "R9",
  "R10",
  "R11",
  "R12",
  "R13",
  "R14",
  "R15",
  "R16",
  "R17",
  "R18",
  "R19",
  "R20",
  "R21",
  "R22",
  "R23",
  "R24",
  "R25",
  "R26",
  "R27",
  "R28",
  "R29",
  "R30",
  "R31",
  "R32",
  "R33",
  "R34",
  "R35",
  "R36",
  "R37",
  "R38",
  "R39",
  "R40",
  "R41",
  "R42",
  "R43",
  "R44",
  "R45",
  "R46",
  "R47",
  "R48",
  "R49",
  "R50",
  "R51",
  "R52",
  "R53",
  "R54",
  "R55",
  "R56",
  "R57",
  "R58",
  "R59",
  "R60",
  "R61",
  "R62",
  "R63",
  "R64",
  "R65",
  "R66",
  "R67",
  "R68",
  "R69",
  "R70",
  "R71",
  "R72",
  "R73",
  "R74",
  "R75",
  "R76",
  "R77",
  "R78",
  "R79",
  "R80",
  "R81",
  "R82",
  "R83",
  "R84",
  "R85",
  "R86",
  "R87",
  "R88",
  "R89",
  "R90",
  "R91",
  "R92",
  "R93",
  "R94",
  "R95",
  "R96",
  "R97",
  "R98",
  "R99",
  "R100",
  "R101",
  "R102",
  "R103",
  "R104",
  "R105",
  "R106",
  "R107",
  "R108",
  "R109",
  "R110",
  "R111",
  "R112",
  "R113",
  "R114",
  "R115",
  "R116",
  "R117",
  "R118",
  "R119",
  "R120",
  "R121",
  "R122",
  "R123",
  "R124",
  "R125",
  "R126",
  "R127",
  "R128",
  "R129",
  "R130",
  "R131",
  "R132",
  "R133",
  "R134",
  "R135",
  "R136",
  "R137",
  "R138",
  "R139",
  "R140",
  "R141",
  "R142",
  "R143",
  "R144",
  "R145",
  "R146",
  "R147",
  "R148",
  "R149",
  "R150",
  "R151",
  "R152",
  "R153",
  "R154",
  "R155",
  "R156",
  "R157",
  "R158",
  "R159",
  "R160",
  "R161",
  "R162",
  "R163",
  "R164",
  "R165",
  "R166",
  "R167",
  "R168",
  "R169",
  "R170",
  "R171",
  "R172",
  "R173",
  "R174",
  "R175",
  "R176",
  "R177",
  "R178",
  "R179",
  "R180",
  "R181",
  "R182",
  "R183",
  "R184",
  "R185",
  "R186",
  "R187",
  "R188",
  "R189",
  "R190",
  "R191",
  "R192",
  "R193",
  "R194",
  "R195",
  "R196",
  "R197",
  "R198",
  "R199",
  "R200",
  "R201",
  "R202",
  "R203",
  "R204",
  "R205",
  "R206",
  "R207",
  "R208",
  "R209",
  "R210",
  "R211",
  "R212",
  "R213",
  "R214",
  "R215",
  "R216",
  "R217",
  "R218",
  "R219",
  "R220",
  "R221",
  "R222",
  "R223",
  "R224",
  "R225",
  "R226",
  "R227",
  "R228",
  "R229",
  "R230",
  "R231",
  "R232",
  "R233",
  "R234",
  "R235",
  "R236",
  "R237",
  "R238",
  "R239",
  "R240",
  "R241",
  "R242",
  "R243",
  "R244",
  "R245",
  "R246",
  "R247",
  "R248",
  "R249",
  "R250",
  "R251",
  "R252",
  "R253",
  "R254",
  "R255",
  "RR0",
  "RR1",
  "RR2",
  "RR3",
  "RR4",
  "RR5",
  "RR6",
  "RR7",
  "RR8",
  "RR9",
  "RR10",
  "RR11",
  "RR12",
  "RR13",
  "RR14",
  "RR15",
  "RR16",
  "RR17",
  "RR18",
  "RR19",
  "RR20",
  "RR21",
  "RR22",
  "RR23",
  "RR24",
  "RR25",
  "RR26",
  "RR27",
  "RR28",
  "RR29",
  "RR30",
  "RR31",
  "RR32",
  "RR33",
  "RR34",
  "RR35",
  "RR36",
  "RR37",
  "RR38",
  "RR39",
  "RR40",
  "RR41",
  "RR42",
  "RR43",
  "RR44",
  "RR45",
  "RR46",
  "RR47",
  "RR48",
  "RR49",
  "RR50",
  "RR51",
  "RR52",
  "RR53",
  "RR54",
  "RR55",
  "RR56",
  "RR57",
  "RR58",
  "RR59",
  "RR60",
  "RR61",
  "RR62",
  "RR63",
  "RR64",
  "RR65",
  "RR66",
  "RR67",
  "RR68",
  "RR69",
  "RR70",
  "RR71",
  "RR72",
  "RR73",
  "RR74",
  "RR75",
  "RR76",
  "RR77",
  "RR78",
  "RR79",
  "RR80",
  "RR81",
  "RR82",
  "RR83",
  "RR84",
  "RR85",
  "RR86",
  "RR87",
  "RR88",
  "RR89",
  "RR90",
  "RR91",
  "RR92",
  "RR93",
  "RR94",
  "RR95",
  "RR96",
  "RR97",
  "RR98",
  "RR99",
  "RR100",
  "RR101",
  "RR102",
  "RR103",
  "RR104",
  "RR105",
  "RR106",
  "RR107",
  "RR108",
  "RR109",
  "RR110",
  "RR111",
  "RR112",
  "RR113",
  "RR114",
  "RR115",
  "RR116",
  "RR117",
  "RR118",
  "RR119",
  "RR120",
  "RR121",
  "RR122",
  "RR123",
  "RR124",
  "RR125",
  "RR126",
  "RR127",
  "RR128",
  "RR129",
  "RR130",
  "RR131",
  "RR132",
  "RR133",
  "RR134",
  "RR135",
  "RR136",
  "RR137",
  "RR138",
  "RR139",
  "RR140",
  "RR141",
  "RR142",
  "RR143",
  "RR144",
  "RR145",
  "RR146",
  "RR147",
  "RR148",
  "RR149",
  "RR150",
  "RR151",
  "RR152",
  "RR153",
  "RR154",
  "RR155",
  "RR156",
  "RR157",
  "RR158",
  "RR159",
  "RR160",
  "RR161",
  "RR162",
  "RR163",
  "RR164",
  "RR165",
  "RR166",
  "RR167",
  "RR168",
  "RR169",
  "RR170",
  "RR171",
  "RR172",
  "RR173",
  "RR174",
  "RR175",
  "RR176",
  "RR177",
  "RR178",
  "RR179",
  "RR180",
  "RR181",
  "RR182",
  "RR183",
  "RR184",
  "RR185",
  "RR186",
  "RR187",
  "RR188",
  "RR189",
  "RR190",
  "RR191",
  "RR192",
  "RR193",
  "RR194",
  "RR195",
  "RR196",
  "RR197",
  "RR198",
  "RR199",
  "RR200",
  "RR201",
  "RR202",
  "RR203",
  "RR204",
  "RR205",
  "RR206",
  "RR207",
  "RR208",
  "RR209",
  "RR210",
  "RR211",
  "RR212",
  "RR213",
  "RR214",
  "RR215",
  "RR216",
  "RR217",
  "RR218",
  "RR219",
  "RR220",
  "RR221",
  "RR222",
  "RR223",
  "RR224",
  "RR225",
  "RR226",
  "RR227",
  "RR228",
  "RR229",
  "RR230",
  "RR231",
  "RR232",
  "RR233",
  "RR234",
  "RR235",
  "RR236",
  "RR237",
  "RR238",
  "RR239",
  "RR240",
  "RR241",
  "RR242",
  "RR243",
  "RR244",
  "RR245",
  "RR246",
  "RR247",
  "RR248",
  "RR249",
  "RR250",
  "RR251",
  "RR252",
  "RR253",
  "RR254",
  "RR255",
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "rr0",
  "rr1",
  "rr2",
  "rr3",
  "rr4",
  "rr5",
  "rr6",
  "rr7",
  "rr8",
  "rr9",
  "rr10",
  "rr11",
  "rr12",
  "rr13",
  "rr14",
  "rr15",
  "RW",
  "RP",
  "csr",
  "dpr0", "dpr1", "dpr2", "dpr3",
};

//----------------------------------------------------------------------
// returns a pointer to a ioport_t object if address was found in the config file.
// otherwise, returns nullptr.
const ioport_t *st9_t::find_sym(ea_t address)
{
  return find_ioport(ioh.ports, address);
}

//----------------------------------------------------------------------
void st9_t::patch_general_registers()
{
  char b[15];
  b[0] = '\0';

  ushort style = idpflags & IDP_GR_DEC ? 0
               : idpflags & IDP_GR_HEX ? 1
               : idpflags & IDP_GR_BIN ? 2
               :                         3;

  QASSERT(10079, style != 3);

  msg("General register print style: %s\n",
        style == 0 ? "decimal"
      : style == 1 ? "hexadecimal"
      :              "binary");

  CASSERT(sizeof(RegNames) == sizeof(src_RegNames));
  memcpy(RegNames, src_RegNames, sizeof(src_RegNames));
  dynamic_rgnames.resize(rR255 - rR1 + 1);
  for ( int i = rR1; i <= rR255; i++ )
  {
    switch ( style )
    {
      // decimal
      case 0:
        qsnprintf(b, sizeof b, "R%d", i);
        break;

      // hexadecimal
      case 1:
        qsnprintf(b, sizeof b, "R0x%X", i);
        break;

      // binary
      case 2:
        {
          static const int bits[] = { 128, 64, 32, 16, 8, 4, 2, 1 };
          b[0] = 'R';
          for ( int k = 0; k < 8; k++ )
            b[k + 1] = (i & bits[k]) ? '1' : '0';
          b[9] = 'b';
          b[10] = '\0';
        }
        break;
    }
    dynamic_rgnames[i-rR1] = b;
    RegNames[i] = dynamic_rgnames[i-rR1].begin();
  }
  ph.reg_names = RegNames;
}

//----------------------------------------------------------------------
// read all procmod data from the idb
void st9_t::load_from_idb()
{
  idpflags = (uint32)helper.altval(-1);
  ioh.restore_device();
}

//----------------------------------------------------------------------
const char *st9_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool idb_loaded)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;

  static const char form[] =
    "HELP\n"
    "ST9 Related options :\n"
    "\n"
    " General registers print style\n"
    "\n"
    "       Select the format which will be used by IDA to\n"
    "       to print general registers.\n"
    "\n"
    "       For example,\n"
    "\n"
    "           R10                    (decimal) \n"
    "           R0x0A                (hexadecimal) \n"
    "           R00001010b      (binary) \n"
    "\n"
    "ENDHELP\n"
    "ST9 related options\n"
    "<##General registers print style##~D~ecimal (default):R>\n"
    "<~H~exadecimal:R>\n"
    "<~B~inary:R>>\n";

  CASSERT(sizeof(print_style) == sizeof(ushort));
  if ( ask_form(form, &print_style) )
  {
    idpflags = 0;
    switch ( print_style )
    {
      case 0: idpflags |= IDP_GR_DEC; break;
      case 1: idpflags |= IDP_GR_HEX; break;
      case 2: idpflags |= IDP_GR_BIN; break;
    }
    if ( idpflags )
      patch_general_registers();
  }
  if ( idb_loaded )
    save_idpflags();
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
// get reference data from ri,
// check compliance of opval and the full value
static bool idaapi dpr_calc_reference_data(
        ea_t *target,
        ea_t *base,
        ea_t from,
        const refinfo_t &ri,
        adiff_t opval)
{
  if ( ri.base == BADADDR || ri.is_subtract() )
    return false;

  int dpr_reg = rDPR0 + ((opval >> 14) & 3);
  sel_t page = get_sreg(from, dpr_reg);
  if ( page == BADSEL )
    return false;

  ea_t addr = (page << 14) + (opval & 0x3FFF);
  ea_t op_target = ri.base - ri.tdelta + addr;
  if ( ri.target != BADADDR && ri.target != op_target )
    return false;

  *target = op_target;
  *base = ri.base;
  return true;
}

// complex format with DPR prefix
//lint -e{818} ... parameter 'opval' could be declared as pointing to const
static int idaapi dpr_gen_expr(
        qstring * /*buf*/,
        qstring *format,
        ea_t /*ea*/,
        int /*numop*/,
        const refinfo_t &/*ri*/,
        ea_t /*from*/,
        adiff_t *opval,
        ea_t * /*target*/,
        ea_t * /*fullvalue*/,
        int /*getn_flags*/)
{
  int dpr_reg_num = (*opval >> 14) & 3;
  format->sprnt(COLSTR("DPR%d:pof", SCOLOR_KEYWORD) "(%%s)", dpr_reg_num);
  return 4; // continue standard processing
}

static const custom_refinfo_handler_t ref_dpr =
{
  sizeof(custom_refinfo_handler_t),
  "DPR",
  "16-bit offset using DPRx register",
  RHF_TGTOPT,               // properties: the target can be BADADDR
  dpr_gen_expr,             // gen_expr
  dpr_calc_reference_data,  // calc_reference_data
  nullptr,                     // get_format
};


//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(st9_t));
  return 0;
}

//----------------------------------------------------------------------
// The kernel event notifications
// Here you may take desired actions upon some kernel events
ssize_t idaapi st9_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      // this processor is big endian
      inf_set_be(true);
      helper.create(PROCMOD_NODE_NAME);
      ref_dpr_id = register_custom_refinfo(&ref_dpr);
      break;

    case processor_t::ev_term:
      unregister_custom_refinfo(ref_dpr_id);
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      if ( inf_like_binary()
        && ask_yn(ASKBTN_YES,
                  "Do you want to split the loaded file contents into 64K banks?") == ASKBTN_YES )
      {
        segment_t *s = get_first_seg();
        if ( s != nullptr )
        {
          ssize_t total = (ssize_t)s->size();
          ea_t ea = s->start_ea;
          // align the segment start at the memory bank start
          if ( (ea & 0xFFFF) != 0 )
          {
            ea_t start = ea & ~0xFFFF;
            set_segm_start(ea, start, 0);
            ea = start;
          }
          // each memory bank gets its own segment
          while ( 1 )
          {
            set_segm_end(ea, ea+0x10000, 0);
            total -= 0x10000;
            ea    += 0x10000;
            if ( total <= 0 )
              break;
            add_segm(ea>>4, ea, ea+total, nullptr, "CODE");
            s = getseg(ea);
            if ( !s->is_16bit() )
            {
              s->bitness = 0;   // use 16-bit segments
              s->update();
            }
          }
        }
        // check that a segment at 0...10000 exists
        // if not, create it
        s = get_first_seg();
        if ( s == nullptr || s->start_ea > 0x10000 )
          add_segm(0, 0, 0x10000, nullptr, "DATA");
      }
      // select_device(inf_like_binary() ? IORESP_ALL : (IORESP_ALL & ~IORESP_AREA));
      // file_loaded = true;
      save_idpflags();
      patch_general_registers();
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_creating_segm:
      {
        segment_t *s = va_arg(va, segment_t *);
        // set RW/RP segment registers initial values
        s->defsr[rRW-ph.reg_first_sreg] = 0;
        s->defsr[rRP-ph.reg_first_sreg] = BADSEL;
      }
      break;

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        st9_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        st9_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        st9_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        st9_assumes(*ctx);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return st9_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return st9_emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_set_idp_options:
      {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const char *value = va_arg(va, const char *);
        const char **errmsg = va_arg(va, const char **);
        bool idb_loaded = va_argi(va, bool);
        const char *ret = set_idp_options(keyword, value_type, value, idb_loaded);
        if ( ret == IDPOPT_OK )
          return 1;
        if ( errmsg != nullptr )
          *errmsg = ret;
        return -1;
      }

    case processor_t::ev_is_switch:
      {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return st9_is_switch(si, *insn) ? 1 : -1;
      }

    case processor_t::ev_is_cond_insn:
      ///< Is conditional instruction?
       ///< \param insn (const ::insn_t)    instruction address
       ///< \retval  1 yes
       ///< \retval  0 not implemented
       ///< \retval -1 no
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return is_jmp_cc(insn->itype) ? 1 : -1;
      }

    case processor_t::ev_is_indirect_jump:
      {
        // jp, call, calls can have indirect register operands (rr), (RR)
        const insn_t *insn = va_arg(va, insn_t *);
        if ( insn->Op1.type != o_reg || !is_ind(insn->Op1) )
          return 1; // no
        if ( insn->itype == st9_jp || insn->itype == st9_call || insn->itype == st9_calls )
          return 2; // yes
        else
          return 1; // no
      }

    case processor_t::ev_create_merge_handlers:
      {
        merge_data_t *md = va_arg(va, merge_data_t *);
        create_std_procmod_handlers(*md);
      }
      break;

    case processor_t::ev_privrange_changed:
      // recreate node as it was migrated
      helper.create(PROCMOD_NODE_NAME);
      break;

#ifdef CVT64
    case processor_t::ev_cvt64_supval:
      {
        static const cvt64_node_tag_t node_info[] =
        {
          CVT64_NODE_DEVICE,
          CVT64_NODE_IDP_FLAGS,
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
  return code;
}

//----------------------------------------------------------------------
//
// GNU ST9+ Assembler description
//

// gets a function name
static bool gnu_get_func_name(qstring *name, const func_t *pfn)
{
  ea_t ea = pfn->start_ea;
  if ( get_demangled_name(name, ea, inf_get_long_demnames(), DEMNAM_NAME) <= 0 )
    return false;

  tag_addr(name, ea, true);
  return true;
}

//----------------------------------------------------------------------
// prints function header
static void idaapi gnu_func_header(outctx_t &ctx, func_t *pfn)
{
  ctx.gen_func_header(pfn);

  qstring name;
  if ( gnu_get_func_name(&name, pfn) )
  {
    int saved_flags = ctx.forbid_annotations();
    ctx.gen_printf(DEFAULT_INDENT,
                    COLSTR(".desc %s, %s", SCOLOR_ASMDIR),
                    name.begin(),
                    pfn->is_far() ? "far" : "near");
    ctx.restore_ctxflags(saved_flags);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".proc %s", SCOLOR_ASMDIR), name.begin());
    ctx.ctxflags |= CTXF_LABEL_OK;
  }
  ctx.gen_printf(0, COLSTR("%s:", SCOLOR_ASMDIR), name.begin());
}

//----------------------------------------------------------------------
// prints function footer
//lint -esym(818,pfn)
static void idaapi gnu_func_footer(outctx_t &ctx, func_t *pfn)
{
  qstring name;
  if ( gnu_get_func_name(&name, pfn) )
  {
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".endproc", SCOLOR_ASMDIR) COLSTR("%s %s", SCOLOR_ASMDIR), ASH.cmnt, name.begin());
  }
}

//----------------------------------------------------------------------
static const asm_t gnu_asm =
{
  AS_COLON
 |ASH_HEXF3     // hex 0x123 format
 |ASB_BINF0     // bin 0110b format
 |ASO_OCTF1     // oct 012345 format
 |AS_ASCIIZ     // don't display the final 0 in string declarations
 |AS_ASCIIC     // allow C-style escape sequences
 |AS_1TEXT,     // 1 text per line, no bytes
  0,
  "ST9 GNU Assembler",
  0,
  nullptr,         // no headers
  ".org",       // origin directive
  nullptr,         // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".string",    // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)

//  XXX
//
//  .float and .double directives are supposed to be supported by the
//  assembler, but when we try to assemble a file including those directives,
//  we get this error message :
//
//  /vob/st9plus/toolset/src/binutils/gas/config/tc-st9.c(4167): !!! STOP !!!
//  -> !(Floating point convertion)

  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  nullptr,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  gnu_func_header,     // func_header
  gnu_func_footer,     // func_footer
  ".global",    // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  nullptr,         // sizeof
  0,            // flag2 ???
  nullptr,         // comment close string
  nullptr,         // low8 op
  nullptr,         // high8 op
  nullptr,         // low16 op
  nullptr          // high16 op
};

//----------------------------------------------------------------------
//
//  Alfred Arnold's Macro Assembler definition
//

static const asm_t asw_asm =
{
  AS_COLON
 |ASH_HEXF0     // hex 123h format
 |ASB_BINF3     // bin 0b010 format
 |ASO_OCTF5     // oct 123q format
 |AS_1TEXT,     // 1 text per line, no bytes
  UAS_ASW,
  "Alfred Arnold's Macro Assembler",
  0,
  nullptr,         // no headers
  "ORG",        // origin directive
  "END",        // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "DB",         // ascii string directive
  "DB",         // byte directive (alias: DB)
  "DW",         // word directive (alias: DW)
  "DD",         // dword  (4 bytes, alias: DD)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  nullptr,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  nullptr,         // sizeof
  0,            // flag2 ???
  nullptr,         // comment close string
  nullptr,         // low8 op
  nullptr,         // high8 op
  nullptr,         // low16 op
  nullptr          // high16 op
};

static const asm_t *const asms[] = { &gnu_asm, &asw_asm, nullptr };

//
// Short and long name for our module
//
#define FAMILY "ST9 Family:"

static const char *const shnames[] =
{
  "st9",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"SGS-Thomson ST9",
  nullptr
};

static const uchar retcode_1[] = { 0x46 };    // ret
static const uchar retcode_2[] = { 0xD3 };    // iret
static const uchar retcode_3[] = { 0xF6, 01 };  // rets
static const uchar retcode_4[] = { 0xEF, 31 };  // eret

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { sizeof(retcode_4), retcode_4 },
  { 0, nullptr }                            // nullptr terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_ST9,               // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM             // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
  | PR_SEGS               // has segment registers?
  | PR_SGROTHER,          // the segment registers don't contain
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  src_RegNames,         // Regsiter names
  qnumber(src_RegNames),// Number of registers

  rRW, rDPR3,
  0,                    // size of a segment register
  rCSR, rDPR0,

  nullptr,                 // No known code start sequences
  retcodes,

  0, st9_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  st9_ret,              // Icode of return instruction. It is ok to give any of possible return instructions
};

/*
 *  This is a sample plugin module
 *  It extends the IBM PC processor module to disassemble some NEC V20 instructions
 *  This is a sample file, it supports just two instructions!
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <mergemod.hpp>
int data_id;

//--------------------------------------------------------------------------
// Context data for the plugin. This object is created by the init()
// function and hold all local data.
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  ea_t ea = 0; // current address within the instruction

  netnode nec_node;
  bool hooked = false;

  plugin_ctx_t();
  ~plugin_ctx_t();

  // This function is called when the user invokes the plugin.
  virtual bool idaapi run(size_t) override;
  // This function is called upon some events.
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  size_t ana(insn_t &insn);
  void process_rm(insn_t &insn, op_t &x, uchar postbyte);
};

static const char node_name[] = "$ sample NEC processor extender parameters";

//--------------------------------------------------------------------------
static const idbattr_info_t idpopts_info[] =
{
  IDI_ALTENTRY(0, atag, sizeof(uint32), uint32(-1), nullptr, "enabled"),
};

SIMPLE_MODDATA_DIFF_HELPER(plugin_helper, "procext", node_name, idpopts_info);

//--------------------------------------------------------------------------
void create_merge_handlers(merge_data_t &md)
{
  DEFINE_PLUGIN_MH_PARAMS("NEC V20 processor extender", MH_TERSE);
  create_std_modmerge_handlers(mhp, data_id, plugin_helper);
}

//--------------------------------------------------------------------------
// Some definitions from IBM PC:

#define segrg specval_shorts.high  // IBM PC expects the segment address
                                   // to be here
#define aux_short       0x0020  // short (byte) displacement used
#define aux_basess      0x0200  // SS based instruction

#define R_ss  18
#define R_ds  19
//--------------------------------------------------------------------------
// This plugin supports just 2 instructions:
// Feel free to add more...

// 0FH 20H                      ADD4S       ; Addition for packed BCD strings
// 0FH 12H Postbyte     CLEAR1  reg/mem8,CL ; Clear one bit

enum nec_insn_type_t
{
  NEC_add4s = CUSTOM_INSN_ITYPE,
  NEC_clear1,
};

//----------------------------------------------------------------------
static int get_dataseg(insn_t &insn, int defseg)
{
  if ( defseg == R_ss )
    insn.auxpref |= aux_basess;
  return defseg;
}

//--------------------------------------------------------------------------
//
//              process r/m byte of the instruction
//
void plugin_ctx_t::process_rm(insn_t &insn, op_t &x, uchar postbyte)
{
  int Mod = (postbyte >> 6) & 3;
  x.reg = postbyte & 7;
  if ( Mod == 3 )               // register
  {
    if ( x.dtype == dt_byte )
      x.reg += 8;
    x.type = o_reg;
  }
  else                          // memory
  {
    if ( Mod == 0 && x.reg == 6 )
    {
      x.type = o_mem;
      x.offb = uchar(ea-insn.ea);
      x.addr = get_word(ea); ea+=2;
      x.segrg = (uint16)get_dataseg(insn, R_ds);
    }
    else
    {
      x.type = o_phrase;        // x.phrase contains the base register
      x.addr = 0;
      int reg = (x.phrase == 2 || x.phrase == 3 || x.phrase == 6) ? R_ss : R_ds;
      x.segrg = (uint16)get_dataseg(insn, reg);
                                // [bp+si],[bp+di],[bp] by SS
      if ( Mod != 0 )
      {
        x.type = o_displ;       // i.e. phrase + offset
        x.offb = uchar(ea-insn.ea);
        if ( Mod == 1 )
        {
          x.addr = char(get_byte(ea++));
          insn.auxpref |= aux_short;
        }
        else
        {
          x.addr = get_word(ea); ea+=2;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Analyze an instruction and fill the 'insn' structure
size_t plugin_ctx_t::ana(insn_t &insn)
{
  int code = get_byte(ea++);
  if ( code != 0x0F )
    return 0;
  code = get_byte(ea++);
  switch ( code )
  {
    case 0x20:
      insn.itype = NEC_add4s;
      return 2;
    case 0x12:
      insn.itype = NEC_clear1;
      {
        uchar postbyte = get_byte(ea++);
        process_rm(insn, insn.Op1, postbyte);
        insn.Op2.type = o_reg;
        insn.Op2.reg  = 9; // 9 is CL for IBM PC
        return size_t(ea - insn.ea);
      }
    default:
      return 0;
  }
}

//--------------------------------------------------------------------------
// Return the instruction mnemonics
const char *get_insn_mnem(const insn_t &insn)
{
  if ( insn.itype == NEC_add4s )
    return "add4s";
  return "clear1";
}

//--------------------------------------------------------------------------
// This function can be hooked to various kernel events.
// In this particular plugin we hook to the HT_IDP group.
// As soon the kernel needs to decode and print an instruction, it will
// generate some events that we intercept and provide our own response.
//
// We extend the processor module to disassemble opcode 0x0F
// (This is a hypothetical example)
// There are 2 different possible approaches for the processor extensions:
//  A. Quick & dirty
//       Implement reaction to ev_ana_insn and ev_out_insn.
//       The first checks if the instruction is valid.
//       The second generates its text.
//  B. Thourough and clean
//       Implement all relevant callbacks.
//       ev_ana_insn fills the 'insn' structure.
//       ev_emu_insn creates all xrefs using ua_add_[cd]ref functions.
//       ev_out_insn generates the textual representation of the instruction.
//          It is required only if the instruction requires special processing
//          or the processor module cannot handle the custom instruction for
//          any reason.
//       ev_out_operand generates the operand representation (only if the
//          operand requires special processing).
//       ev_out_mnem generates the instruction mnemonics.
// The main difference between these 2 approaches is in the creation of
// cross-references and the amount of special processing required by the
// new instructions.

// The quick & dirty approach.
// We just produce the instruction mnemonics along with its operands.
// No cross-references are created. No special processing.
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case processor_t::ev_ana_insn:
      {
        insn_t *insn = va_arg(va, insn_t *);
        ea = insn->ea;
        size_t length = ana(*insn);
        if ( length )
        {
          insn->size = (uint16)length;
          return insn->size;       // event processed
        }
      }
      break;
    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const insn_t &insn = ctx->insn;
        if ( insn.itype >= CUSTOM_INSN_ITYPE )
        {
          ctx->out_line(get_insn_mnem(insn), COLOR_INSN);
          return 1;
        }
      }
      break;
    case processor_t::ev_create_merge_handlers:
      {
        merge_data_t *md = va_arg(va, merge_data_t *);
        create_merge_handlers(*md);
      }
      break;
    case processor_t::ev_privrange_changed:
      // recreate node as it was migrated
      if ( nec_node != BADNODE )
        nec_node.create(node_name);
      break;
  }
  return 0;                     // event is not processed
}

//--------------------------------------------------------------------------
// Initialize the plugin.
// IDA will call this function only once.
// If this function returns nullptr, IDA will unload the plugin.
// Otherwise the plugin returns a pointer to a newly created context structure.
//
// In this example we check the processor type and make the decision.
// You may or may not check any other conditions to decide what you do:
// whether your plugin wants to work with the database or not.

static plugmod_t *idaapi init()
{
  processor_t &ph = PH;
  if ( ph.id != PLFM_386 )
    return nullptr;
  auto plugmod = new plugin_ctx_t;
  set_module_data(&data_id, plugmod);
  return plugmod;
}

//-------------------------------------------------------------------------
plugin_ctx_t::plugin_ctx_t()
{
  nec_node.create(node_name);
  hooked = nec_node.altval(0) != 0;
  if ( hooked )
  {
    hook_event_listener(HT_IDP, this);
    msg("NEC V20 processor extender is enabled\n");
  }
}

//--------------------------------------------------------------------------
// Terminate the plugin.
// This destructor will be called before unloading the plugin.
plugin_ctx_t::~plugin_ctx_t()
{
  clr_module_data(data_id);
  // listeners are uninstalled automatically
  // when the owner module is unloaded
}

//--------------------------------------------------------------------------
// The plugin method
// This is the main function of plugin.
// It will be called when the user selects the plugin from the menu.
// The input argument is usually zero. Non-zero values can be specified
// by using load_and_run_plugin() or through plugins.cfg file (discouraged).
bool idaapi plugin_ctx_t::run(size_t)
{
  if ( hooked )
    unhook_event_listener(HT_IDP, this);
  else
    hook_event_listener(HT_IDP, this);
  hooked = !hooked;
  nec_node.create(node_name);
  nec_node.altset(0, hooked);
  info("AUTOHIDE NONE\n"
       "NEC V20 processor extender now is %s", hooked ? "enabled" : "disabled");
  return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "NEC V20 processor extender";
static const char help[] =
  "A sample plugin module\n"
  "\n"
  "This module shows you how to create plugin modules.\n"
  "\n"
  "It supports some NEC V20 instructions\n"
  "and shows the current address.\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overridden in plugins.cfg file

static const char desired_name[] = "NEC V20 processor extender";

// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overridden in plugins.cfg file

static const char desired_hotkey[] = "";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC           // this is a processor extension plugin
| PLUGIN_MULTI,         // this plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin. not used.
  help,                 // multiline help about the plugin. not used.
  desired_name,         // the preferred short name of the plugin
  desired_hotkey        // the preferred hotkey to run the plugin
};

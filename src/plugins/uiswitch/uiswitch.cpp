/*

        Plugin that allows the user to specify the exact
        address and shape of a jump table (switch idiom).

        It displays a dialog box with the most important
        attributes of the switch idiom. If the idiom is
        complex and has more attributes, then more
        dialog boxes are displayed.

        All collected information is validated and then
        stored in the database in the switch_info_t structure.
        The last step is to reanalyze the switch idiom.

        Please note that this plugin supports the most
        common switch idiom but some idiom types are not
        handled, for example, custom switches are not.

*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <jumptable.hpp>

//-------------------------------------------------------------------------
struct plugin_ctx_t;
#define ACTION_NAME "uiswitch:SpecSwitchIdiom"
struct uiswitch_ah_t : public action_handler_t
{
  plugin_ctx_t &plg;
  uiswitch_ah_t(plugin_ctx_t &_plg) : plg(_plg) {}
  virtual int idaapi activate(action_activation_ctx_t *) override;
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return ctx->widget_type == BWN_DISASM
         ? AST_ENABLE_FOR_WIDGET
         : AST_DISABLE_FOR_WIDGET;
  }
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public ignore_micro_t
{
  uiswitch_ah_t uiswitch_ah = uiswitch_ah_t(*this);
  plugin_ctx_t();
  virtual bool idaapi run(size_t) override;
  bool callback();
};

//-------------------------------------------------------------------------
int idaapi uiswitch_ah_t::activate(action_activation_ctx_t *)
{
  return plg.callback();
}

//---------------------------------------------------------------------------
// The main form
// hotkeys: abdefginpstu
static const char main_form[] =
  "HELP\n"
  "Please specify the jump table address, the number of its\n"
  "elements and their widths(1,2,4,8). The element shift amount and base value\n"
  "should be specified only if the table elements are not\n"
  "plain target addresses but must be converted using the following\n"
  "formula:\n"
  "\n"
  "        target = base +/- (table_element << shift)\n"
  "\n"
  "(only this formula is supported by the kernel; other cases must be\n"
  "handled by plugins and 'custom' switch idioms).\n"
  "\n"
  "If you specify BADADDR as the element base then the base of the\n"
  "switch segment will be used\n"
  "\n"
  "The start of the switch idiom is the address of the first instruction\n"
  "in the switch idiom.\n"
  "\n"
  "Subtraction is used instead of addition if \"Subtract table elements\"\n"
  "is selected.\n"
  "\n"
  "When table element is an instruction then you should select\n"
  "\"Table element is insn\".\n"
  "\n"
  "If you specify that a separate value table is present, an additional\n"
  "dialog box with its attributes will be displayed.\n"
  "ENDHELP\n"
  // ansebtifdpgul
  "Manual switch declaration - Main features\n"
  "\n"
  "<~A~ddress of jump table    :N::18::>\n"
  "<~N~umber of elements       :D::18::>\n"
  "<~S~ize of table element    :D::18::>\n"
  "<~E~lement shift amount     :D::18::>\n"
  "<Element ~b~ase value       :N::18::>\n"
  "\n"
  "<S~t~art of the switch idiom:N::18::>\n"
  "<~I~nput register of switch :q:511:18::>\n"
  "<~F~irst(lowest) input value:D::18::>(if value table is absent)\n"
  "<~D~efault jump address     :N::18::>\n"
  "\n"
  "<Se~p~arate value table is present:C>\n"
  "<Si~g~ned jump table elements     :C>\n"
  "<S~u~btract table elements        :C>\n"
  "<Tab~l~e element is insn          :C>>\n"
  "\n"
  "\n";

// this form displayed if the value table is present
// shortcuts: afinus
static const char value_form[] =
  "HELP\n"
  "Direct value table holds values of the switch 'case's.\n"
  "Each value maps to the corresponding target of the jump table\n"
  "Indirect value table holds indexes into jump table.\n"
  "\n"
  "Inversed value table maps the first element of the value table\n"
  "to the last element of the jump table.\n"
  "\n"
  "For direct table the size of the value table is equal\n"
  "to the size of the jump table.\n"
  "\n"
  "Example of switch idiom with indirect value table:\n"
  "\n"
  "  cmp     ecx, 0Fh\n"
  "  ja      short defjump\n"
  "  movzx   ecx, ds:indirect_value_table[ecx]\n"
  "  jmp     ds:jump_table[ecx*4]\n"
  "\n"
  " jump_table      dd offset target_1\n"
  "                 dd offset target_2\n"
  " indirect_value_table db      0,     0,     1,     0\n"
  "                 db      1,     1,     1,     0\n"
  "                 db      1,     1,     1,     1\n"
  "                 db      1,     1,     1,     0\n"
  "\n"
  "ENDHELP\n"
  "Manual switch declaration - Value table\n"
  "\n"
  "<~I~ndirect value table:C>\n"
  "<I~n~versed value table:C>>\n"
  "<~A~ddress of value table:N::18::>\n"
  "<N~u~mber of elements    :D::18::> (only for indirect table)\n"
  "<~S~ize of table element :D::18::>\n"
  "<~F~irst(lowest) input value:D::18::> (only for indirect table)\n"
  "\n"
  "\n";

//---------------------------------------------------------------------------
// Validate table attributes
static bool check_table(ea_t table, uval_t elsize, uval_t tsize)
{
  flags64_t F;
  if ( getseg(table) == nullptr || is_code((F=get_flags(table))) || is_tail(F) )
  {
    warning("AUTOHIDE NONE\nIncorrect table address %a", table);
    return false;
  }
  if ( elsize != 1 && elsize != 2 && elsize != 4 && elsize != 8 )
  {
    warning("AUTOHIDE NONE\nIncorrect table element size %" FMT_EA "u", elsize);
    return false;
  }
  flags64_t DF = get_flags_by_size((size_t)elsize);
  if ( !can_define_item(table, elsize*tsize, DF) )
  {
    warning("AUTOHIDE NONE\nCannot create table at %a size %" FMT_EA "u", table, tsize);
    return false;
  }
  return true;
}

//---------------------------------------------------------------------------
// The main function - called when the user selects the menu item
bool plugin_ctx_t::callback()
{
  // Calculate the default values to display in the form
  ea_t screen_ea = get_screen_ea();
  segment_t *s = getseg(screen_ea);
  if ( s == nullptr || !is_code(get_flags(screen_ea)) )
  {
    warning("AUTOHIDE NONE\nThe cursor must be on the table jump instruction");
    return false;
  }

  // If switch information is present in the database, use it for defaults
  switch_info_t si;
  if ( get_switch_info(&si, screen_ea) <= 0 )
  {
    si.jumps = get_first_dref_from(screen_ea);
    unsigned int jsize = (int)s->abytes();
    si.set_jtable_element_size(jsize);
    // calculate NCASES
    if ( si.jumps != BADADDR )
    {
      const segment_t *jtable_seg = getseg(si.jumps);
      ea_t jtable_end = jtable_seg != nullptr ? jtable_seg->end_ea : BADADDR;
      int size = int((jtable_end - si.jumps) / jsize);
      si.ncases = size > USHRT_MAX ? USHRT_MAX : size;
      trim_jtable(&si, screen_ea, false);
    }
    // calculate STARTEA
    si.startea = screen_ea;
    while ( true )
    {
      ea_t prev = prev_not_tail(si.startea);
      if ( !is_switch_insn(prev) )
        break;
      si.startea = prev;
    }
  }

  ea_t jumps = si.jumps;
  uval_t jtsize = si.ncases;
  ea_t startea = si.startea;
  uval_t elbase = si.elbase;
  uval_t jelsize = si.get_jtable_element_size();
  uval_t shift = si.get_shift();
  ea_t defea = si.defjump;
  qstring input;
  if ( si.regnum != -1 )
    get_reg_name(&input, si.regnum, get_dtype_size(si.regdtype));
  ushort jflags = 0;
  if ( si.flags & SWI_SIGNED )
    jflags |= 2;
  if ( si.flags & SWI_SUBTRACT )
    jflags |= 4;
  if ( si.flags & SWI_JMPINSN )
    jflags |= 8;
  uval_t lowcase = 0;
  ushort vflags = 0;
  ea_t vtable = BADADDR;
  ea_t vtsize = 0;
  ea_t velsize = 0;
  ea_t vlowcase = 0;
  if ( si.flags & SWI_SPARSE )
  {
    jflags |= 1;
    vtable = si.values;
    vtsize = jtsize;
    velsize = si.get_vtable_element_size();
    if ( si.flags & SWI_INDIRECT )
    {
      vlowcase = si.get_lowcase();
      vflags |= 1;
      jtsize = si.jcases;
    }
    if ( si.flags & SWI_JMP_INV )
      vflags |= 2;
  }
  else
  {
    lowcase = si.lowcase;
  }
  // TODO allow to change these fields
  ea_t expr_ea = si.expr_ea;
  eavec_t marks = si.marks;

  // Now display the form and let the user edit the attributes
  while ( ask_form(main_form, &jumps, &jtsize, &jelsize, &shift, &elbase,
                  &startea, &input, &lowcase, &defea, &jflags) )
  {
    if ( !check_table(jumps, jelsize, jtsize) )
      continue;
    if ( shift > 3 )
    {
      warning("AUTOHIDE NONE\nInvalid shift value (allowed values are 0..3)");
      continue;
    }
    if ( !is_code(get_flags(startea)) )
    {
      warning("AUTOHIDE NONE\nInvalid switch idiom start %a (must be an instruction", startea);
      continue;
    }
    reg_info_t ri;
    ri.reg = -1;
    ri.size = 0;
    if ( !input.empty() && !parse_reg_name(&ri, input.c_str()) )
    {
      warning("AUTOHIDE NONE\nUnknown input register: %s", input.c_str());
      continue;
    }
    if ( defea != BADADDR && !is_code(get_flags(defea)) )
    {
      warning("AUTOHIDE NONE\nInvalid default jump %a (must be an instruction", defea);
      continue;
    }
    if ( jflags & 1 ) // value table is present
    {
      bool vok = false;
      while ( ask_form(value_form, &vflags, &vtable, &vtsize, &velsize, &vlowcase) )
      {
        if ( (vflags & 1) == 0 )
          vtsize = jtsize;
        if ( check_table(vtable, velsize, vtsize) )
        {
          vok = true;
          break;
        }
      }
      if ( !vok )
        break;
    }
    // ok, got and validated all params -- fill the structure
    si.clear();
    if ( jflags & 2 )
      si.flags |= SWI_SIGNED;
    if ( jflags & 4 )
      si.flags |= SWI_SUBTRACT;
    if ( jflags & 8 )
      si.flags |= SWI_JMPINSN;
    si.jumps = jumps;
    si.ncases = ushort(jtsize);
    si.startea = startea;
    if ( elbase != BADADDR )
      si.set_elbase(elbase);
    si.set_jtable_element_size((int)jelsize);
    si.set_shift((int)shift);
    si.defjump = defea;
    if ( ri.reg != -1 )
      si.set_expr(ri.reg, get_dtype_by_size(ri.size));
    if ( jflags & 1 ) // value table is present
    {
      si.flags |= SWI_SPARSE;
      si.values = vtable;
      si.set_vtable_element_size((int)velsize);
      if ( (vflags & 1) != 0 )
      {
        si.flags |= SWI_INDIRECT;
        si.jcases = (int)jtsize;
        si.ncases = (ushort)vtsize;
        si.ind_lowcase = vlowcase;
      }
      if ( (vflags & 2) != 0 )
        si.flags |= SWI_JMP_INV;
    }
    else
    {
      si.lowcase = lowcase;
    }
    si.expr_ea = expr_ea;
    si.marks = marks;
    si.flags |= SWI_USER;
    // ready, store it
    set_switch_info(screen_ea, si);
    create_switch_table(screen_ea, si);
    create_insn(screen_ea);
    info("AUTOHIDE REGISTRY\nSwitch information has been stored");
    break;
  }
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_ctx_t::plugin_ctx_t()
{
  register_and_attach_to_menu(
          "Edit/Other/Create", ACTION_NAME, "Specify switch idiom...",
          nullptr, SETMENU_INS,
          &uiswitch_ah,
          this,
          ADF_OT_PLUGMOD);
  init_ignore_micro();
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  callback();
  return true;
}

//--------------------------------------------------------------------------
static const char help[] = "";
static const char comment[] = "";
static const char wanted_name[] = "Specify switch idiom";
static const char wanted_hotkey[] = "";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI          // The plugin can work with multiple idbs in parallel
  | PLUGIN_HIDE,        // Plugin should not appear in the Edit, Plugins menu
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

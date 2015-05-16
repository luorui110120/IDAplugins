/*

        Plugin that allows the user to specify the exact
        address and shape of a jump table (switch idiom).

        It displays a dialog box with the most important
        attributes of the switch idiom. If the idiom is
        complex and has more attributes, then more
        dialog boxes are displayed.

        All collected information is validated and then
        stored in the database in the switch_info_ex_t structure.
        The last step is to reanalyze the switch idiom.

        Please note that this plugin supports the most
        common switch idiom but some idiom types are not
        handled, for example, custom switches are not.

*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include "../../include/intel.hpp"

netnode ignore_micro;
//---------------------------------------------------------------------------
// The main form
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
    "The start of the switch idiom is the address of the first instruction\n"
    "in the switch idiom.\n"
    "\n"
    "Subtraction is used instead of addition if \"Subtract table elements\"\n"
    "is selected.\n"
    "\n"
    "If you specify that a separate value table is present, an additional\n"
    "dialog box with its attributes will be displayed.\n"
    "ENDHELP\n"
    "Manual switch declaration - Main features\n"
    "\n"
    "<Address of jump table:N:511:16::>\n"
    "<Number of elements   :D:511:16::>\n"
    "<Size of table element:D:511:16::>\n"
    "<Element shift amount :D:511:16::>\n"
    "<Element base value   :N:511:16::>\n"
    "\n"
    "<Start of the switch idiom:N:511:16::>\n"
    "<Input register of switch :A:511:16::>\n"
    "<First(lowest) input value:D:511:16::>(if value table is absent)\n"
    "<Default jump address     :N:511:16::>\n"
    "\n"
    "<Separate value table is present:C>\n"
    "<Signed jump table elements     :C>\n"
    "<Subtract table elements        :C>>\n"
    "\n"
    "\n";

// this form displayed if the value table is present
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
    "<Indirect value table:C>\n"
    "<Inversed value table:C>>\n"
    "<Address of value table:N:511:16::>\n"
    "<Number of elements    :D:511:16::> (only for indirect table)\n"
    "<Size of table element :D:511:16::>\n"
    "\n"
    "\n";

//---------------------------------------------------------------------------
// Validate table attributes
static bool check_table(ea_t table, uval_t elsize, uval_t tsize)
{
  flags_t F;
  if ( getseg(table) == NULL || isCode((F=get_flags_novalue(table))) || isTail(F) )
  {
    warning("AUTOHIDE NONE\nIncorrect table address %a", table);
    return false;
  }
  if ( elsize != 1 && elsize != 2 && elsize != 4 && elsize != 8 )
  {
    warning("AUTOHIDE NONE\nIncorrect table element size %"FMT_EA"d", elsize);
    return false;
  }
  flags_t DF = get_flags_by_size((size_t)elsize);
  if ( !can_define_item(table, elsize*tsize, DF) )
  {
    warning("AUTOHIDE NONE\nCan not create table at %a size %"FMT_EA"d", table, tsize);
    return false;
  }
  return true;
}

//---------------------------------------------------------------------------
// The main function - called when the user selects the menu item
static bool idaapi callback(void *)
{
  // Calculate the default values to display in the form
  ea_t screen_ea = get_screen_ea();
  segment_t *s = getseg(screen_ea);
  if ( s == NULL || !isCode(get_flags_novalue(screen_ea)) )
  {
    warning("AUTOHIDE NONE\nThe cursor must be on the table jump instruction");
    return false;
  }
  ea_t startea = screen_ea;
  while ( true )
  {
    ea_t prev = prev_not_tail(startea);
    if ( !is_switch_insn(prev) )
      break;
    startea = prev;
  }
  ea_t jumps = get_first_dref_from(screen_ea);
  uval_t jelsize = s->abytes();
  uval_t jtsize = 0;
  if ( jumps != BADADDR )
  {
    decode_insn(screen_ea);
    jtsize = guess_table_size(jumps);
  }
  uval_t shift = 0;
  uval_t elbase = 0;
  char input[MAXSTR];
  input[0] = '\0';
  ea_t defea = BADADDR;
  uval_t lowcase = 0;
  ushort jflags = 0;
  ushort vflags = 0;
  ea_t vtable = BADADDR;
  ea_t vtsize = 0;
  ea_t velsize = s->abytes();
  reg_info_t ri;
  ri.size = 0;
  // If switch information is present in the database, use it for defaults
  switch_info_ex_t si;
  if ( get_switch_info_ex(screen_ea, &si, sizeof(si)) > 0 )
  {
    jumps = si.jumps;
    jtsize = si.ncases;
    startea = si.startea;
    elbase = si.elbase;
    jelsize = si.get_jtable_element_size();
    shift = si.get_shift();
    defea = (si.flags & SWI_DEFAULT) ? si.defjump : BADADDR;
    if ( si.regnum != -1 )
      get_reg_name(si.regnum, get_dtyp_size(si.regdtyp), input, sizeof(input));
    if ( si.flags & SWI_SIGNED )
      jflags |= 2;
    if ( si.flags2 & SWI2_SUBTRACT )
      jflags |= 4;
    if ( si.flags & SWI_SPARSE )
    {
      jflags |= 1;
      vtable = si.values;
      vtsize = jtsize;
      velsize = si.get_vtable_element_size();
      if ( si.flags2 & SWI2_INDIRECT )
      {
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
  }
  // Now display the form and let the user edit the attributes
  while ( AskUsingForm_c(main_form, &jumps, &jtsize, &jelsize, &shift, &elbase,
                         &startea, input, &lowcase, &defea, &jflags) )
  {
    if ( !check_table(jumps, jelsize, jtsize) )
      continue;
    if ( shift > 3 )
    {
      warning("AUTOHIDE NONE\nInvalid shift value (allowed values are 0..3)");
      continue;
    }
    if ( !isCode(get_flags_novalue(startea)) )
    {
      warning("AUTOHIDE NONE\nInvalid switch idiom start %a (must be an instruction", startea);
      continue;
    }
    ri.reg = -1;
    if ( input[0] != '\0' && !parse_reg_name(input, &ri) )
    {
      warning("AUTOHIDE NONE\nUnknown input register: %s", input);
      continue;
    }
    if ( defea != BADADDR && !isCode(get_flags_novalue(defea)) )
    {
      warning("AUTOHIDE NONE\nInvalid default jump %a (must be an instruction", defea);
      continue;
    }
    if ( jflags & 1 ) // value table is present
    {
      bool vok = false;
      while ( AskUsingForm_c(value_form, &vflags, &vtable, &vtsize, &velsize) )
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
    si.flags = SWI_EXTENDED;
    si.flags2 = 0;
    if ( jflags & 2 )
      si.flags |= SWI_SIGNED;
    if ( jflags & 4 )
      si.flags2 |= SWI2_SUBTRACT;
    si.jumps = jumps;
    si.ncases = ushort(jtsize);
    si.startea = startea;
    si.elbase = elbase;
    if ( elbase != 0 )
      si.flags |= SWI_ELBASE;
    si.set_jtable_element_size((int)jelsize);
    si.set_shift((int)shift);
    if ( defea != BADADDR )
    {
      si.flags |= SWI_DEFAULT;
      si.defjump = defea;
    }
    if ( ri.reg != -1 )
      si.set_expr(ri.reg, get_dtyp_by_size(ri.size));
    if ( jflags & 1 ) // value table is present
    {
      si.flags |= SWI_SPARSE;
      si.values = vtable;
      si.set_vtable_element_size((int)velsize);
      if ( (vflags & 1) != 0 )
      {
        si.flags2 |= SWI2_INDIRECT;
        si.jcases = (int)jtsize;
        si.ncases = (ushort)vtsize;
      }
      if ( (vflags & 2) != 0 )
        si.flags |= SWI_JMP_INV;
    }
    else
    {
      si.lowcase = lowcase;
    }
    // ready, store it
    set_switch_info_ex(screen_ea, &si);
    create_switch_table(screen_ea, &si);
    setFlbits(screen_ea, FF_JUMP);
    create_insn(screen_ea);
    info("AUTOHIDE REGISTRY\nSwitch information has been stored");
    break;
  }
  return true;
}


//--------------------------------------------------------------------------
static int idaapi init(void)
{
  add_menu_item("Edit/Other/Create", "Specify switch idiom", "", SETMENU_INS, callback, NULL);
  ignore_micro = netnode("$ ignore micro");
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
static void idaapi term(void)
{
  del_menu_item("Edit/Other/Specify switch idiom");
}

//--------------------------------------------------------------------------
static void idaapi run(int)
{
  callback(NULL);
}

//--------------------------------------------------------------------------
static char help[] = "";
static char comment[] = "";
static char wanted_name[] = "Specify switch idiom";
static char wanted_hotkey[] = "";
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE,          // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

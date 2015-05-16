/*
 * Disassembler for Samsung SAM87 processors
 */

#include "sam8.hpp"

static bool flow;               // does the current instruction pass
                                // execution to the next instruction?


extern char* altCcNames[];



//----------------------------------------------------------------------
// Handle an operand. What this function usually does:
//      - creates cross-references from the operand
//        (the kernel deletes all xrefs before calling emu())
//      - creates permanent comments
//      - if possible, specifies the operand type (for example, it may
//        create stack variables)
//      - anything else you might need to emulate or trace
static void handle_operand(op_t &x,int loading) {
  switch ( x.type ) {
  case o_phrase:              // no special handling for these types
  case o_reg:
  case o_reg_bit:
    break;

  case o_imm:
    // this can't happen!
    if ( !loading ) goto BAD_LOGIC;

    // set immediate flag
    doImmd(cmd.ea);

    // if the value was converted to an offset, then create a data xref:
    if ( isOff(uFlag, x.n) )
      ua_add_off_drefs2(x, dr_O, 0);
    break;

  case o_displ:
    if ( x.phrase == fIdxCAddr ) {
      ua_dodata2(x.offb, x.addr, x.dtyp);
      doVar(x.addr);
      ua_add_dref(x.offb, x.addr, loading ? dr_R : dr_W);
    } else {
      // create name
      char buf[256];
      qsnprintf(buf, sizeof(buf), "emem_%a", x.addr);
      set_name(SAM8_EDATASEG_START + x.addr, buf, SN_AUTO);

      // setup data xrefs etc
      ua_dodata2(x.offb, SAM8_EDATASEG_START + x.addr, x.dtyp);
      doVar(SAM8_EDATASEG_START + x.addr);
      ua_add_dref(x.offb, SAM8_EDATASEG_START + x.addr, loading ? dr_R : dr_W);
    }
    break;

  case o_emem: {
    // create variable name
    char buf[256];
    qsnprintf(buf, sizeof(buf), "emem_%a", x.addr);
    set_name(SAM8_EDATASEG_START + x.addr, buf, SN_AUTO);

    // setup data xrefs etc
    ua_dodata2(x.offb, SAM8_EDATASEG_START + x.addr, x.dtyp);
    ua_add_dref(x.offb, SAM8_EDATASEG_START + x.addr, loading ? dr_R : dr_W);
    break;
  }

  case o_cmem:
    ua_dodata2(x.offb, x.addr, x.dtyp);
    doVar(x.addr);
    ua_add_dref(x.offb, x.addr, loading ? dr_R : dr_W);
    break;

  case o_near: {
    // work out if it is a CALL, and add in a code xref
    bool iscall = InstrIsSet(cmd.itype, CF_CALL);
    ua_add_cref(x.offb, x.addr, iscall ? fl_CN : fl_JN);

    // if dest is a non-returning function, don't flow onto next op
    if ( flow && iscall ) {
      if ( !func_does_return(x.addr) )
        flow = false;
    }
    break;
  }

  case o_cmem_ind: {
    // setup code xref/variable
    ua_dodata2(x.offb, x.addr, dt_word);
    ua_add_dref(x.offb, x.addr, loading ? dr_R : dr_W);

    // Now, since we KNOW this is an indirect code jump, turn
    // the word at the x.addr into an offset into a subroutine
    if ( isEnabled(x.addr) ) {
      // get value stored in that address
      ushort destAddr = get_word(x.addr);

      // add in cref & turn into offset
      add_cref(x.addr, destAddr, fl_JN);
      set_offset(x.addr, 0, 0);
    }
    break;
  }

  default:
  BAD_LOGIC:
    warning("%a (%s): bad optype", cmd.ea, cmd.get_canon_mnem());
    break;
  }
}

//----------------------------------------------------------------------
// Emulate an instruction
// This function should:
//      - create all xrefs from the instruction
//      - perform any additional analysis of the instruction/program
//        and convert the instruction operands, create comments, etc.
//      - create stack variables
//      - analyze the delayed branches and similar constructs
// The kernel calls ana() before calling emu(), so you may be sure that
// the 'cmd' structure contains a valid and up-to-date information.
// You are not allowed to modify the 'cmd' structure.
// Upon entering this function, the 'uFlag' variable contains the flags of
// cmd.ea. If you change the characteristics of the current instruction, you
// are required to refresh 'uFlag'.
// Usually the kernel calls emu() with consecutive addresses in cmd.ea but
// you can't rely on this - for example, if the user asks to analyze an
// instruction at arbirary address, his request will be handled immediately,
// thus breaking the normal sequence of emulation.
// If you need to analyze the surroundings of the current instruction, you
// are allowed to save the contents of the 'cmd' structure and call ana().
// For example, this is a very common pattern:
//  {
//    insn_t saved = cmd;
//    if ( decode_prev_insn(cmd.ea) != BADADDR )
//    {
//      ....
//    }
//    cmd = saved;
//  }
//
// This sample emu() function is a very simple emulation engine.

int idaapi emu(void) {
  // setup
  uint32 Feature = cmd.get_canon_feature();
  flow = true;

  // disable flow if CF_STOP set
  if ( Feature & CF_STOP ) {
    flow = false;
  }

  // you may emulate selected instructions with a greater care:
  switch ( cmd.itype ) {
  case SAM8_JR: case SAM8_JP:
    // Do extended condition code checking on these instructions
    if ( (cmd.c_condition == ccNone) || (cmd.c_condition == ccT) ) {
      flow = false;
    }
    break;
  }

  // deal with operands
  if ( Feature & CF_USE1) handle_operand(cmd.Op1, 1 );
  if ( Feature & CF_USE2) handle_operand(cmd.Op2, 1 );
  if ( Feature & CF_USE3) handle_operand(cmd.Op3, 1 );
  if ( Feature & CF_JUMP) QueueMark(Q_jumps, cmd.ea );
  if ( Feature & CF_CHG1) handle_operand(cmd.Op1, 0 );
  if ( Feature & CF_CHG2) handle_operand(cmd.Op2, 0 );
  if ( Feature & CF_CHG3) handle_operand(cmd.Op3, 0 );

  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyze the next instruction.
  if ( flow ) {
    ua_add_cref(0, cmd.ea + cmd.size, fl_F);
  }

  // OK (actual code unimportant)
  return 1;
}

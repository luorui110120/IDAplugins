/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "i51.hpp"
#include <frame.hpp>

static bool flow;               // does the current instruction pass
                                // execution to the next instruction?

//------------------------------------------------------------------------
// Handle an operand with an immediate value:
//      - mark it with FF_IMMD flag
//      - for bit logical instructions specify the operand type as a number
//        because such an operand is likely a plain number rather than
//        an offset or of another type.

static void doImmdValue(void)
{
  doImmd(cmd.ea);
  switch ( cmd.itype )
  {
    case I51_anl:
    case I51_orl:
    case I51_xrl:
      op_num(cmd.ea,1);
      break;
  }
}

//----------------------------------------------------------------------
static void attach_bit_comment(ea_t addr, int bit)
{
  const ioport_bit_t *predef = find_bit(addr, bit);
  if ( predef != NULL && get_cmt(cmd.ea, false, NULL, 0) <= 0 )
    set_cmt(cmd.ea, predef->cmt, false);
}

//----------------------------------------------------------------------
// Calculate the target data address
ea_t map_addr(asize_t off, int opnum, bool isdata)
{
  if ( isdata )
  {
    if ( isOff(uFlag, opnum) ) return get_offbase(cmd.ea, opnum) >> 4;
    return ((off >= 0x80 && off < 0x100) ? sfrmem : intmem) + off;
  }
  return toEA(codeSeg(off, opnum), off);
}

//----------------------------------------------------------------------
// Handle an operand. What this function usually does:
//      - creates cross-references from the operand
//        (the kernel deletes all xrefs before calling emu())
//      - creates permanent comments
//      - if possible, specifies the operand type (for example, it may
//        create stack variables)
//      - anything else you might need to emulate or trace

static void handle_operand(op_t &x,int loading)
{
  switch ( x.type )
  {
    case o_phrase:              // no special hanlding for these types
    case o_reg:
      break;

    case o_imm:                         // an immediate number as an operand
      if ( !loading ) goto BAD_LOGIC;   // this can't happen!
      doImmdValue();                    // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN);

      break;

    case o_displ:
      doImmdValue();                    // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, loading?dr_R:dr_W, OOFS_IFSIGN|OOF_ADDR);
      break;

    case o_bit:                         // 8051 specific operand types - bits
    case o_bitnot:
      x.addr = (x.reg & 0xF8);
      if( (x.addr & 0x80) == 0 ) x.addr = x.addr/8 + 0x20;
      attach_bit_comment(x.addr, x.reg & 7);  // attach a comment if necessary
      goto MEM_XREF;

    case o_bit251:
      attach_bit_comment(x.addr, x.b251_bit);
      /* no break */

    case o_mem:                         // an ordinary memory data reference
MEM_XREF:
      {
        ea_t dea = map_addr(x.addr, x.n, true);
        ua_dodata2(x.offb, dea, x.dtyp);
        if ( !loading )
          doVar(dea);     // write access
        ua_add_dref(x.offb, dea, loading ? dr_R : dr_W);
      }
      break;

    case o_near:                        // a code reference
      {
        ea_t ea = map_addr(x.addr, x.n, false);
        int iscall = InstrIsSet(cmd.itype, CF_CALL);
        ua_add_cref(x.offb, ea, iscall ? fl_CN : fl_JN);
        if ( flow && iscall )
          flow = func_does_return(ea);
      }
      break;

    default:
BAD_LOGIC:
      warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static void add_stkpnt(sval_t v)
{
  if ( !may_trace_sp() )
    return;

  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return;

  add_auto_stkpnt2(pfn, cmd.ea+cmd.size, v);
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

int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  // you may emulate selected instructions with a greater care:
  switch ( cmd.itype )
  {
    case I51_mov:
      if ( cmd.Op1.type == o_mem && cmd.Op1.addr == 0x81 )  // mov SP, #num
      {
        if ( cmd.Op2.type == o_imm && !isDefArg(uFlag,1) )
          set_offset(cmd.ea,1,intmem);             // convert it to an offset
      }
      break;
    case I51_trap:
      ua_add_cref(0, 0x7B, fl_CN);
      break;
    case I51_pop:
      add_stkpnt(1);
      break;
    case I51_push:
      add_stkpnt(-1);
      break;
  }

  if ( Feature & CF_USE1 ) handle_operand(cmd.Op1, 1);
  if ( Feature & CF_USE2 ) handle_operand(cmd.Op2, 1);
  if ( Feature & CF_USE3 ) handle_operand(cmd.Op3, 1);
  if ( Feature & CF_JUMP ) QueueMark(Q_jumps,cmd.ea);

  if ( Feature & CF_CHG1 ) handle_operand(cmd.Op1, 0);
  if ( Feature & CF_CHG2 ) handle_operand(cmd.Op2, 0);
  if ( Feature & CF_CHG3 ) handle_operand(cmd.Op3, 0);

  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyze the next instruction.

  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  return 1;    // actually the return value is unimportant, but let's it be so
}

//----------------------------------------------------------------------
bool idaapi is_sane_insn(bool no_crefs)
{
  if ( no_crefs )
  {
    switch ( cmd.itype )
    {
      case I51_mov:
        if ( get_byte(cmd.ea) == 0xFF )
          return false;
        break;
    }
  }
  return true;
}

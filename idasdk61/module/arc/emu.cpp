/*
 *                      Interactive disassembler (IDA).
 *                      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                      ALL RIGHTS RESERVED.
 *                                                                                                                      E-mail: ig@estar.msk.su, ig@datarescue.com
 *                                                                                                                      FIDO:    2:5020/209
 *
 */

#include "arc.hpp"
#include <frame.hpp>
static int islast;

// does the expression [reg, xxx] point to the stack?
static bool is_stkptr(int reg)
{
  if ( reg == SP ) return true;
  if ( reg == FP )
  {
    func_t *pfn = get_func(cmd.ea);
    if ( pfn != NULL && (pfn->flags & FUNC_FRAME) != 0 )
      return true;
  }
  return false;
}

static void handle_operand(op_t &x, int loading)
{
  if ( may_create_stkvars() && !isDefArg(uFlag,x.n) )
  {
    func_t *pfn = get_func(cmd.ea);
    if ( pfn != NULL )
      if ( (x.n==2) && (cmd.itype<=ARC_store_instructions) )    // so it might be an offset to something
        if ( (cmd.Op2.type==o_reg) && is_stkptr(cmd.Op2.reg) )  // if it's [sp, xxx] we make a stackvar out of it
          if ( ua_stkvar2(x, x.value, STKVAR_VALID_SIZE) )
            op_stkvar(cmd.ea, x.n);
  }

        switch ( x.type )
        {
        case o_reg:
                break;
        case o_imm:
                doImmd(cmd.ea);
                if ( isOff(get_flags_novalue(cmd.ea), x.n) )
                        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN);
                break;
        case o_mem:
        {
                ua_dodata2(x.offb, x.addr, x.dtyp);
                if ( !loading )
                        doVar(x.addr);
                ua_add_dref(x.offb, x.addr, loading?dr_R:dr_W);
                break;
        }
        case o_near:
        {
                int iscall=InstrIsSet(cmd.itype, CF_CALL);
                ua_add_cref(x.offb, toEA(cmd.cs, x.addr), iscall ? fl_CN : fl_JN);
                if ( (!islast) && iscall )
                {
                  if ( !func_does_return(x.addr) )              // delay slot?!
                        islast=1;
                }
        }
        }
}

//----------------------------------------------------------------------
// Emulate an instruction
// This function should:
//                      - create all xrefs from the instruction
//                      - perform any additional analysis of the instruction/program
//                              and convert the instruction operands, create comments, etc.
//                      - create stack variables
//                      - analyze the delayed branches and similar constructs
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
//      {
//              insn_t saved = cmd;
//              if ( decode_prev_insn(cmd.ea) != BADADDR )
//              {
//                      ....
//              }
//              cmd = saved;
//      }
//
// This sample emu() function is a very simple emulation engine.

int idaapi emu(void)
{
        uint32 Feature = cmd.get_canon_feature();

        islast=Feature&CF_STOP;

        insn_t last=cmd;
        if ( decode_prev_insn(cmd.ea) != BADADDR )
        {
                switch ( cmd.itype )
                {
                case ARC_j:
                case ARC_b:
                {
                        int ccode=cmd.auxpref&31;
                        int ncode=(cmd.auxpref>>5)&3;
                        if ( (!ccode) && ncode) // branch always and (maybe ) delay slot?
                                islast=1;
                        break;
                }
                }
        }

        cmd=last;

        // you may emulate selected instructions with a greater care:
        switch ( cmd.itype )
        {
        case ARC_j:
        case ARC_b:
        {
                int ccode=cmd.auxpref&31;
                int ncode=(cmd.auxpref>>5)&3;
                if ( (!ccode) && (!ncode) )     // branch always and no delay slot?
                        islast=1;
                break;
        }
        }

        if ( (cmd.Op1.type==o_reg) && (cmd.Op1.reg==28) && may_trace_sp() )     // access to the stackpointer
        {
                func_t *pfn = get_func(cmd.ea);
                if ( pfn != NULL && (cmd.Op2.type==o_reg) && (cmd.Op2.reg==28) && (cmd.Op3.type==o_imm) )       // currently we're only trace add/sub sp, sp, imm
                        switch ( cmd.itype )
                        {
                        case ARC_add:
                                add_auto_stkpnt2(pfn, cmd.ea+cmd.size, cmd.Op3.value);
                                break;
                        case ARC_sub:
                                add_auto_stkpnt2(pfn, cmd.ea+cmd.size, -cmd.Op3.value);
                                break;
                        default:
                                msg("??? unknown cmd sp @ %a\n", cmd.ea);
                                break;
                        }
                else
                        msg("??? illegal access mode sp @ %a\n", cmd.ea);
        }

        if ( Feature & CF_USE1 ) handle_operand(cmd.Op1, 1);
        if ( Feature & CF_USE2 ) handle_operand(cmd.Op2, 1);
        if ( Feature & CF_USE3 ) handle_operand(cmd.Op3, 1);

        if ( Feature & CF_CHG1 ) handle_operand(cmd.Op1, 0);
        if ( Feature & CF_CHG2 ) handle_operand(cmd.Op2, 0);
        if ( Feature & CF_CHG3 ) handle_operand(cmd.Op3, 0);

        // if the execution flow is not stopped here, then create
        // a xref to the next instruction.
        // Thus we plan to analyze the next instruction.

        if ( !islast )
          ua_add_cref(0,cmd.ea+cmd.size,fl_F);
        else if ( auto_state == AU_USED )
          recalc_spd(cmd.ea);

        return 1;               // actually the return value is unimportant, but let's it be so
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  ea_t ea = pfn->startEA;
  for ( int i=0; i < 10 && ea < pfn->endEA; i++ )
  {
    if ( !decode_insn(ea) ) break;
    if ( cmd.itype == ARC_move
      && cmd.Op1.type == o_reg && cmd.Op1.reg == FP
      && cmd.Op2.type == o_reg && cmd.Op2.reg == SP )
    {
      pfn->flags |= FUNC_FRAME;
      update_func(pfn);
    }
    if ( cmd.itype == ARC_sub
      && cmd.Op1.type == o_reg && cmd.Op1.reg == SP
      && cmd.Op2.type == o_reg && cmd.Op2.reg == SP
      && cmd.Op3.type == o_imm )
    {
      return add_frame(pfn, cmd.Op2.value, 0, 0);
    }
    ea += cmd.size;
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const op_t &x)
{
  return OP_SP_ADD | (x.reg == SP ? OP_SP_BASED : OP_FP_BASED);
}

//----------------------------------------------------------------------
int idaapi arc_get_frame_retsize(func_t * /*pfn*/)
{
  return 4;
}

/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c54.hpp"
#include <srarea.hpp>
#include <frame.hpp>

static bool flow;

//------------------------------------------------------------------------
ea_t calc_code_mem(ea_t ea, bool is_near)
{
  ea_t rv;
  if ( is_near )
  {
    sel_t xpc = getSR(cmd.ea, XPC);
    if ( xpc == BADSEL )
      xpc = 0;
    rv = ((xpc & 0x7F) << 16) | (ea & 0xFFFF);
  }
  else
  {
    rv = toEA(cmd.cs, ea);
  }
  return use_mapping(rv);
}

//------------------------------------------------------------------------
ea_t calc_data_mem(ea_t ea, bool is_mem)
{
  ea_t rv;
  if ( is_mem )
  {
    sel_t dp = getSR(cmd.ea, DP);
    if ( dp == BADSEL )
      return BADSEL;
    rv = ((dp & 0x1FF) << 7) | (ea & 0x7F);
  }
  else
  {
    rv = ea;
  }
  rv += dataseg;
  return use_mapping(rv);
}

//----------------------------------------------------------------------
regnum_t get_mapped_register(ea_t ea)
{
  if ( idpflags & TMS320C54_MMR )
  {
    switch ( ea-dataseg )
    {
      case 0x00: return IMR;
      case 0x01: return IFR;
      case 0x06: return ST0;
      case 0x07: return ST1;
      case 0x08: return AL;
      case 0x09: return AH;
      case 0x0A: return AG;
      case 0x0B: return BL;
      case 0x0C: return BH;
      case 0x0D: return BG;
      case 0x0E: return T;
      case 0x0F: return TRN;
      case 0x10: return AR0;
      case 0x11: return AR1;
      case 0x12: return AR2;
      case 0x13: return AR3;
      case 0x14: return AR4;
      case 0x15: return AR5;
      case 0x16: return AR6;
      case 0x17: return AR7;
      case 0x18: return SP;
      case 0x19: return BK;
      case 0x1A: return BRC;
      case 0x1B: return RSA;
      case 0x1C: return REA;
      case 0x1D: return PMST;
      case 0x1E: return XPC;
      default:   return rnone;
    }
  }
  else
    return rnone;
}

//----------------------------------------------------------------------
static void process_imm(op_t &x)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,x.n) ) return; // if already defined by user
  switch ( cmd.itype )
  {
    case TMS320C54_cmpm:
    case TMS320C54_bitf:
    case TMS320C54_andm:
    case TMS320C54_orm:
    case TMS320C54_xorm:
    case TMS320C54_addm:
    case TMS320C54_st:
    case TMS320C54_stm:
    case TMS320C54_rpt:
    case TMS320C54_ld3:
    case TMS320C54_mpy2:
    case TMS320C54_rptz:
    case TMS320C54_add3:
    case TMS320C54_sub3:
    case TMS320C54_and3:
    case TMS320C54_or3:
    case TMS320C54_xor3:
    case TMS320C54_mac2:
      op_num(cmd.ea, x.n);
  }
}

//----------------------------------------------------------------------
static void process_operand(op_t &x, int use)
{
  switch ( x.type )
  {
    case o_bit:
    case o_reg:
    case o_cond8:
    case o_cond2:
      return;

    case o_near:
    case o_far:
      {
        if ( cmd.itype != TMS320C54_rptb && cmd.itype != TMS320C54_rptbd )
        {
          cref_t ftype = fl_JN;
          ea_t ea = calc_code_mem(x.addr, x.type == o_near);
          if ( InstrIsSet(cmd.itype, CF_CALL) )
          {
            if ( !func_does_return(ea) )
              flow = false;
            ftype = fl_CN;
          }
#ifndef TMS320C54_NO_NAME_NO_REF
          if ( x.dtyp == dt_byte )
            ua_add_dref(x.offb, ea, dr_R);
          else
            ua_add_cref(x.offb, ea, ftype);
#endif
        }
#ifndef TMS320C54_NO_NAME_NO_REF
        else // evaluate RPTB[D] loops as dref
          ua_add_dref(x.offb, calc_code_mem(x.addr), dr_I);
#endif
      }
      break;

    case o_imm:
      if ( !use ) error("interr: emu");
      process_imm(x);
#ifndef TMS320C54_NO_NAME_NO_REF
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, x.Signed ? OOF_SIGNED : 0);
#endif
      break;

    case o_mem:
    case o_farmem:
    case o_mmr:
      {
        ea_t ea = calc_data_mem(x.addr, x.type == o_mem);
        if ( ea != BADADDR )
        {
#ifndef TMS320C54_NO_NAME_NO_REF
          ua_add_dref(x.offb, ea, use ? dr_R : dr_W);
#endif
          ua_dodata2(x.offb, ea, x.dtyp);
          if ( !use )
            doVar(ea);
        }
      }
      break;

    case o_local: // local variables
      if ( may_create_stkvars()
        && (get_func(cmd.ea) != NULL)
        && ua_stkvar2(x, x.addr, STKVAR_VALID_SIZE) )
      {
        op_stkvar(cmd.ea, x.n);
      }
      break;

    case o_displ:
      doImmd(cmd.ea);
      break;

    default:
      warning("interr: emu2 address:%a operand:%d type:%d", cmd.ea, x.n, x.type);
  }
}

//----------------------------------------------------------------------
// is the previous instruction a delayed jump ?
//
// The following array shows all delayed instructions (xxx[D])
// who are required to always stop.
//
// Z = 1 : delay instruction bit
//
// BRANCH INSTRUCTIONS
//
// TMS320C54_bd,      // Branch Unconditionally                            1111 00Z0 0111 0011 16-bit constant      B[D] pmad
// TMS320C54_baccd,   // Branch to Location Specified by Accumulator       1111 01ZS 1110 0010                      BACC[D] src
// TMS320C54_fbd,     // Far Branch Unconditionally                        1111 10Z0 1 7bit constant=pmad(22-16) 16-bit constant=pmad(15-0)  FB[D] extpmad
// TMS320C54_fbaccd,  // Far Branch to Location Specified by Accumulator   1111 01ZS 1110 0110                      FBACC[D] src
//
// RETURN INSTRUCTIONS
//
// TMS320C54_fretd,   // Far Return                                        1111 01Z0 1110 0100                      FRET[D]
// TMS320C54_freted,  // Enable Interrupts and Far Return From Interrupt   1111 01Z0 1110 0101                      FRETE[D]
// TMS320C54_retd,    // Return                                            1111 11Z0 0000 0000                      RET[D]
// TMS320C54_reted,   // Enable Interrupts and Return From Interrupt       1111 01Z0 1110 1011                      RETE[D]
// TMS320C54_retfd,   // Enable Interrupts and Fast Return From Interrupt  1111 01Z0 1001 1011                      RETF[D]

bool delayed_stop(void)
{
  if ( !isFlow(uFlag) )
    return false;

  if ( cmd.size <= 0 || cmd.size > 2 )
    return false;

  int sub = 2 - cmd.size; // backward offset to skip the previous 1-word instruction in the case of 2 consecutive 1-word instructions

  // first, we analyze 1-word instructions
  ea_t ea = cmd.ea - sub - 1;
  if ( isCode(get_flags_novalue(ea)) )
  {
    int code = get_full_byte(ea); // get the instruction word
    switch ( code )
    {
      case 0xF6E2: // TMS320C54_baccd,   // Branch to Location Specified by Accumulator       1111 01ZS 1110 0010                      BACC[D] src
      case 0xF7E2:
      case 0xF6E6: // TMS320C54_fbaccd,  // Far Branch to Location Specified by Accumulator   1111 01ZS 1110 0110                      FBACC[D] src
      case 0xF7E6:
      case 0xF6E4: // TMS320C54_fretd,   // Far Return                                        1111 01Z0 1110 0100                      FRET[D]
      case 0xF6E5: // TMS320C54_freted,  // Enable Interrupts and Far Return From Interrupt   1111 01Z0 1110 0101                      FRETE[D]
      case 0xFE00: // TMS320C54_retd,    // Return                                            1111 11Z0 0000 0000                      RET[D]
      case 0xF6EB: // TMS320C54_reted,   // Enable Interrupts and Return From Interrupt       1111 01Z0 1110 1011                      RETE[D]
      case 0xF69B: // TMS320C54_retfd,   // Enable Interrupts and Fast Return From Interrupt  1111 01Z0 1001 1011                      RETF[D]
        return true;
    }
  }
  // else, we analyze 2-word instructions
  ea = cmd.ea - sub - 2;
  if ( isCode(get_flags_novalue(ea)) )
  {
    int code = get_full_byte(ea); // get the first instruction word
    if ( code == 0xF273             // TMS320C54_bd,      // Branch Unconditionally      1111 00Z0 0111 0011 16-bit constant      B[D] pmad
      || (code & 0xFF80) == 0xFA80) // TMS320C54_fbd,     // Far Branch Unconditionally  1111 10Z0 1 7bit constant=pmad(22-16) 16-bit constant=pmad(15-0)  FB[D] extpmad
        return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool is_basic_block_end(void)
{
  if ( delayed_stop() )
    return true;
  return ! isFlow(get_flags_novalue(cmd.ea+cmd.size));
}

//----------------------------------------------------------------------
static bool add_stkpnt(sval_t delta)
{
  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return false;

  return add_auto_stkpnt2(pfn, cmd.ea+cmd.size, delta);
}

//----------------------------------------------------------------------
static void trace_sp(void)
{
  // trace SP changes
  switch ( cmd.itype )
  {
    case TMS320C54_fret:
    case TMS320C54_fretd:
    case TMS320C54_frete:
    case TMS320C54_freted:
      add_stkpnt(2);
      break;
    case TMS320C54_ret:
    case TMS320C54_retd:
    case TMS320C54_rete:
    case TMS320C54_reted:
    case TMS320C54_retf:
    case TMS320C54_retfd:
      add_stkpnt(1);
      break;
    case TMS320C54_frame:
      add_stkpnt(cmd.Op1.value);
      break;
    case TMS320C54_popd:
    case TMS320C54_popm:
      add_stkpnt(1);
      break;
    case TMS320C54_pshd:
    case TMS320C54_pshm:
      add_stkpnt(-1);
      break;
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 feature = cmd.get_canon_feature();
  flow = (feature & CF_STOP) == 0;

  if ( feature & CF_USE1 ) process_operand(cmd.Op1, 1);
  if ( feature & CF_USE2 ) process_operand(cmd.Op2, 1);
  if ( feature & CF_USE3 ) process_operand(cmd.Op3, 1);

  if ( feature & CF_CHG1 ) process_operand(cmd.Op1, 0);
  if ( feature & CF_CHG2 ) process_operand(cmd.Op2, 0);
  if ( feature & CF_CHG3 ) process_operand(cmd.Op3, 0);

  // check for CPL changes
  if ( (cmd.itype == TMS320C54_rsbx1 || cmd.itype == TMS320C54_ssbx1)
    && cmd.Op1.type == o_reg && cmd.Op1.reg == CPL )
  {
    splitSRarea1(get_item_end(cmd.ea), CPL, cmd.itype == TMS320C54_rsbx1 ? 0 : 1, SR_auto);
  }

  // check for DP changes
  if (cmd.itype == TMS320C54_ld2 && cmd.Op1.type == o_imm && cmd.Op1.dtyp == dt_byte
    && cmd.Op2.type == o_reg && cmd.Op2.reg == DP)
      splitSRarea1(get_item_end(cmd.ea), DP, cmd.Op1.value & 0x1FF, SR_auto);

  // determine if the next instruction should be executed
  if ( segtype(cmd.ea) == SEG_XTRN )
    flow = false;
  if ( flow && delayed_stop() )
    flow = false;
  if ( flow )
    ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(cmd.ea);     // recalculate SP register for the next insn
    else
      trace_sp();
  }

  return 1;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn != NULL )
  {
    if ( pfn->frame == BADNODE )
    {
      ea_t ea = pfn->startEA;
      int regsize = 0;
      while ( ea < pfn->endEA ) // check for register pushs
      {
        if ( !decode_insn(ea) )
          break;
        if ( cmd.itype != TMS320C54_pshm )
          break;
        if ( cmd.Op1.type != o_mem && cmd.Op1.type != o_mmr )
          break;
        if ( get_mapped_register(cmd.Op1.addr) == rnone )
          break;
        regsize++;
        ea += cmd.size;
      }
      int localsize = 0;
      while ( ea < pfn->endEA ) // check for frame creation
      {
        if ( cmd.itype == TMS320C54_frame && cmd.Op1.type == o_imm )
        {
          localsize = -(int)cmd.Op1.value;
          break;
        }
        ea += cmd.size;
        if ( !decode_insn(ea) )
          break;
      }
      add_frame(pfn, localsize+regsize, 0, 0);
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi tms_get_frame_retsize(func_t * /*pfn*/)
{
  return 1;     // 1 'byte' for the return address
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) )
    return 0;
  switch ( cmd.itype )
  {
    case TMS320C54_nop:
      break;
    default:
      return 0;
  }
  return cmd.size;
}


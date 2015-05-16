/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "pic.hpp"
#include <srarea.hpp>
#include <frame.hpp>

static int flow;

//------------------------------------------------------------------------
static bool is_banked_reg(ea_t addr, int value)
{
  // on PIC12, bank size is 0x20
  // on PIC14, bank size is 0x80
  if ( ptype == PIC12 ) 
    return (addr & 0x1F ) == value;
  if ( ptype == PIC14 ) 
    return (addr & 0x7F ) == value;
  return false;
}

//------------------------------------------------------------------------
// is pcl register?
static bool is_pcl(void)
{
  if ( cmd.Op1.type == o_mem )
  {
    switch ( ptype )
    {
      case PIC12:
      case PIC14: return is_banked_reg(cmd.Op1.addr, 0x2);
      case PIC16: return cmd.Op1.addr == PIC16_PCL;
    }
  }
  return false;
}

//------------------------------------------------------------------------
// is bank (status or bsr (PIC18Cxx)) register?
bool is_bank(void)
{
  if ( cmd.Op1.type == o_mem )
  {
    switch ( ptype )
    {
      case PIC12:
      case PIC14: return is_banked_reg(cmd.Op1.addr, 0x3);
      case PIC16: return cmd.Op1.addr == PIC16_BANK;
    }
  }
  return false;
}

//------------------------------------------------------------------------
// is pclath register?
static bool is_pclath(void)
{
  if ( cmd.Op1.type == o_mem )
  {
    switch ( ptype )
    {
      case PIC12: return false;
      case PIC14: return is_banked_reg(cmd.Op1.addr, 0xA);
      case PIC16: return cmd.Op1.addr == PIC16_PCLATH;
    }
  }
  return false;
}

//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {
    case PIC_iorlw:
    case PIC_andlw:
    case PIC_xorlw:
      op_num(cmd.ea, n);
      break;
    case PIC_lfsr2:
      // FSRs are used to address the data memory
      if ( dataseg != BADADDR )
        op_offset(cmd.ea, n, REF_OFF16, BADADDR, dataseg);
      break;
  }
}

//----------------------------------------------------------------------
static void destroy_if_unnamed_array(ea_t ea)
{
  flags_t F = get_flags_novalue(ea);
  if ( isTail(F) && segtype(ea) == SEG_IMEM )
  {
    ea_t head = prev_not_tail(ea);
    if ( !has_user_name(get_flags_novalue(head)) )
    {
      do_unknown(head, DOUNK_SIMPLE);
      doByte(head, ea-head);
      ea_t end = nextthat(ea, inf.maxEA, f_isHead, NULL);
      if ( end == BADADDR ) end = getseg(ea)->endEA;
      doByte(ea+1, end-ea-1);
    }
  }
}

//----------------------------------------------------------------------
// propagate the bank/pclath register value to the destination
static void propagate_sreg(ea_t ea, int reg)
{
  if ( isLoaded(ea) )
  {
    sel_t v = getSR(cmd.ea, reg);
    splitSRarea1(ea, reg, v, SR_auto);
  }
}

//----------------------------------------------------------------------
static void process_operand(op_t &x,int ,int isload)
{
  if ( cmd.Op2.type == o_reg && cmd.Op2.reg == F || cmd.itype == PIC_swapf ) isload = 0;
  switch ( x.type )
  {
    case o_reg:
      return;
    case o_imm:
      if ( !isload ) error("interr: emu");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, calc_outf(x));
      break;
    case o_near:
      {
        cref_t ftype = fl_JN;
        ea_t ea = calc_code_mem(x.addr);
        if ( InstrIsSet(cmd.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        ua_add_cref(x.offb, ea, ftype);
        propagate_sreg(ea, BANK);
        propagate_sreg(ea, PCLATH);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_data_mem(x.addr);
        destroy_if_unnamed_array(ea);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload )
          doVar(ea);
        if ( may_create_stkvars())
        {
          if ( x.addr == PIC16_INDF2 )
          {
            func_t *pfn = get_func(cmd.ea);
            if ( pfn != NULL && (pfn->flags & FUNC_FRAME) != 0 )
            {
              ua_stkvar2(cmd.Op1, 0, STKVAR_VALID_SIZE);
            }
          }
          else if ( x.addr == PIC16_PLUSW2 )
          {
            insn_t saved = cmd;
            if ( decode_prev_insn(cmd.ea) != BADADDR && cmd.itype == PIC_movlw )
            {
              func_t *pfn = get_func(cmd.ea);
              if ( pfn != NULL && (pfn->flags & FUNC_FRAME) != 0 )
              {
                if ( ua_stkvar2(cmd.Op1, cmd.Op1.value, STKVAR_VALID_SIZE) )
                  op_stkvar(cmd.ea, cmd.Op1.n);
              }
            }
            cmd = saved;
          }
        }




      }
      break;
    default:
      warning("interr: emu2 %a", cmd.ea);
  }
}

//----------------------------------------------------------------------
// change value of virtual register "BANK" and switch to another bank
static void split(int reg, sel_t v)
{
  if ( reg == -1 )
  {
    flow = 0;
    if ( v != BADSEL )
    {
      sel_t pclath = getSR(cmd.ea, PCLATH) & 0x1F;
      ea_t ea = calc_code_mem(uchar(v) | (pclath<<8));
      ua_add_cref(0, ea, fl_JN);
      propagate_sreg(ea, BANK);
      propagate_sreg(ea, PCLATH);
    }
  }
  else
  {
    if ( v == BADSEL ) v = 0;     // assume bank0 if bank is unknown
    if ( reg == BANK )
    {
      if ( ptype != PIC16 ) v &= 3;
      else v &= 0xF;
    }
    splitSRarea1(get_item_end(cmd.ea), reg, v, SR_auto);
  }
}

//----------------------------------------------------------------------
//   tris PORTn  (or movwf TRISn)
static bool is_load_tris_reg(void)
{
  ea_t addr;
  const char *key;
  switch ( cmd.itype )
  {
    case PIC_tris:
      addr = cmd.Op1.value;
      key = "port";
      break;
    case PIC_movwf:
      addr = cmd.Op1.addr;
      key = "tris";
      break;
    default:
      return false;
  }
  char nbuf[MAXSTR];
  char *name = get_name(BADADDR, calc_data_mem(addr), nbuf, sizeof(nbuf));
  return name != NULL && strnicmp(name, key, 4) == 0;
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  uint32 Feature = cmd.get_canon_feature();
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);
  int flag3 = is_forced_operand(cmd.ea, 2);

  flow = (Feature & CF_STOP) == 0;

  if ( Feature & CF_USE1 ) process_operand(cmd.Op1, flag1, 1);
  if ( Feature & CF_USE2 ) process_operand(cmd.Op2, flag2, 1);
  if ( Feature & CF_USE3 ) process_operand(cmd.Op3, flag3, 1);

  if ( Feature & CF_CHG1 ) process_operand(cmd.Op1, flag1, 0);
  if ( Feature & CF_CHG2 ) process_operand(cmd.Op2, flag2, 0);
  if ( Feature & CF_CHG3 ) process_operand(cmd.Op3, flag3, 0);

//
//      Check for:
//        - the register bank changes
//        - PCLATH changes
//        - PCL changes
//
  for ( int i=0; i < 3; i++ )
  {
    int reg = 0;
    switch ( i )
    {
      case 0:
        reg = BANK;
        if ( !is_bank() ) continue;
        break;
      case 1:
        reg = PCLATH;
        if ( !is_pclath() ) continue;
        break;
      case 2:
        reg = -1;
        if ( !is_pcl() ) continue;
        break;
    }
    sel_t v = (reg == -1) ? cmd.ip : getSR(cmd.ea, reg);
    if ( cmd.Op2.type == o_reg && cmd.Op2.reg == F )
    {
//      split(reg, v);
    }
    else
    {
      switch ( cmd.itype )
      {
        case PIC_bcf:
        case PIC_bcf3:
        case PIC_bsf:
        case PIC_bsf3:
          if ( ((ptype == PIC12) && (cmd.Op2.value == 5) )  // bank selector (PA0)
           || ((ptype == PIC14) && (
               (reg == BANK && (cmd.Op2.value == 5 || cmd.Op2.value == 6)) // bank selector (RP1:RP0)
           || (reg == PCLATH && (cmd.Op2.value == 3 || cmd.Op2.value == 4))))
           || ((ptype == PIC16) && (sval_t(cmd.Op2.value) >= 0 && cmd.Op2.value <= 3)))
          {
            if ( v == BADSEL )
              v = 0;
            int shift = 0;
            if ( (ptype == PIC14 || ptype == PIC12) && reg == BANK ) // we use bank selector bits as the bank value
              shift = 5;
            if ( cmd.itype == PIC_bcf )
              v = v & ~(1 << (cmd.Op2.value-shift));
            else
              v = v | sel_t(1 << (cmd.Op2.value-shift));
            split(reg, v);
          }
          break;
        case PIC_clrf:
        case PIC_clrf2:
          split(reg, 0);
          break;
        case PIC_swapf:
        case PIC_swapf3:
          split(reg, ((v>>4) & 15) | ((v & 15) << 4));
          break;
        case PIC_movwf:
        case PIC_movwf2:
        case PIC_addlw:
        case PIC_andlw:
        case PIC_iorlw:
        case PIC_sublw:
        case PIC_xorlw:
          {
            insn_t saved = cmd;
            if ( decode_prev_insn(cmd.ea) != BADADDR
              && ( cmd.itype == PIC_movlw ) )
            {
              switch ( saved.itype )
              {
                case PIC_movwf:
                case PIC_movwf2:
                  v = cmd.Op1.value;
                  break;
                case PIC_addlw:
                  v += cmd.Op1.value;
                  break;
                case PIC_andlw:
                  v &= cmd.Op1.value;
                  break;
                case PIC_iorlw:
                  v |= cmd.Op1.value;
                  break;
                case PIC_sublw:
                  v -= cmd.Op1.value;
                  break;
                case PIC_xorlw:
                  v ^= cmd.Op1.value;
                  break;
              }
            }
            else
            {
              v = BADSEL;
            }
            cmd = saved;
          }
          split(reg, v);
          break;
        case PIC_movlw:
          split(reg, cmd.Op2.value);
          break;
      }
    }
  }

// Such as , IDA doesn't seem to convert the following:
// tris 6
// into
// tris PORTB ( or whatever )

  if ( cmd.itype == PIC_tris && !isDefArg0(uFlag) )
    set_offset(cmd.ea, 0, dataseg);

//   movlw value
// followed by a
//   movwf FSR
// should convert value into an offset , because FSR is used as a pointer to
// the INDF (indirect addressing file)

  if ( cmd.itype == PIC_movwf
    && cmd.Op1.type == o_mem
    && is_banked_reg(cmd.Op1.addr, 0x4) )    // FSR
  {
    insn_t saved = cmd;
    if ( decode_prev_insn(cmd.ea) != BADADDR
      && cmd.itype == PIC_movlw )
    {
      set_offset(cmd.ea, 0, dataseg);
    }
    cmd = saved;
  }

// Also - it seems to make sense to me that a
//   movlw value
// followed by a
//   tris PORTn  (or movwf TRISn)
// should convert value into a binary , because the bits indicate whether a
// port is defined for input or output.

  if ( is_load_tris_reg() )
  {
    insn_t saved = cmd;
    if ( decode_prev_insn(cmd.ea) != BADADDR
      && cmd.itype == PIC_movlw )
    {
      op_bin(cmd.ea, 0);
    }
    cmd = saved;
  }

// Move litteral to BSR

  if ( cmd.itype == PIC_movlb1 ) split(BANK, cmd.Op1.value);

//
//      Determine if the next instruction should be executed
//
  if ( !flow ) flow = conditional_insn();
  if ( segtype(cmd.ea) == SEG_XTRN ) flow = 0;
  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

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
      if ( ea + 12 < pfn->endEA) // minimum 4 + 4 + 2 + 2 bytes needed
      {
        insn_t insn[4];
        for (int i=0; i<4; i++)
        {
          decode_insn(ea);
          insn[i] = cmd;
          ea += cmd.size;
        }
        if ( insn[0].itype == PIC_movff2 // movff FSR2L,POSTINC1
          && insn[0].Op1.addr == PIC16_FSR2L && insn[0].Op2.addr == PIC16_POSTINC1
          && insn[1].itype == PIC_movff2 // movff FSR1L,FSR2L
          && insn[1].Op1.addr == PIC16_FSR1L && insn[1].Op2.addr == PIC16_FSR2L
          && insn[2].itype == PIC_movlw  // movlw <size>
          && insn[3].itype == PIC_addwf3 // addwf FSR1L,f
          && insn[3].Op1.addr == PIC16_FSR1L && insn[3].Op2.reg == F)
        {
          setflag((uint32 &)pfn->flags,FUNC_FRAME,1);
          return add_frame(pfn, insn[2].Op1.value, 0, 0);
        }
      }
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const op_t &)
{
  return OP_SP_ADD | OP_FP_BASED;
}

//----------------------------------------------------------------------
int idaapi PIC_get_frame_retsize(func_t *)
{
  return 0;
}

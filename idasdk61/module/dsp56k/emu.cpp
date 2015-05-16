
#include "dsp56k.hpp"
#include <frame.hpp>

static bool flow;
//----------------------------------------------------------------------
ea_t calc_mem(op_t &x)
{
  if ( x.amode & (amode_x|amode_l) ) return xmem == BADADDR ? BADADDR : xmem+x.addr;
  if ( x.amode & amode_y ) return ymem == BADADDR ? BADADDR : ymem+x.addr;
  return toEA(cmd.cs, x.addr);
}

//------------------------------------------------------------------------
inline bool is_stkreg(int r)
{
  return r == SP;
}

//------------------------------------------------------------------------
int idaapi is_sp_based(const op_t &x)
{
  return OP_SP_ADD | (x.phrase == SP ? OP_SP_BASED : OP_FP_BASED);
}

//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {
//      case DSP56_asl:
//      case DSP56_asr:
    case DSP56_bchg:
    case DSP56_bclr:
    case DSP56_brclr:
    case DSP56_brset:
    case DSP56_bsclr:
    case DSP56_bset:
    case DSP56_bsset:
    case DSP56_btst:
    case DSP56_jclr:
    case DSP56_jset:
    case DSP56_jsclr:
    case DSP56_jsset:
//      case DSP56_lsl:
//      case DSP56_lsr:

      op_dec(cmd.ea, n);
      break;


    case DSP56_add:
    case DSP56_and:
    case DSP56_andi:
    case DSP56_cmp:
    case DSP56_eor:
    case DSP56_extract:
    case DSP56_extractu:
    case DSP56_insert:
    case DSP56_mac:
    case DSP56_maci:
    case DSP56_macr:
    case DSP56_macri:
    case DSP56_mpy:
    case DSP56_mpyi:
    case DSP56_mpyr:
    case DSP56_mpyri:
    case DSP56_or:
    case DSP56_ori:
    case DSP56_sub:
    case DSP56_do:
    case DSP56_dor:
    case DSP56_rep:

      op_num(cmd.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
static void add_near_ref(op_t &x, ea_t ea)
{
  cref_t ftype = fl_JN;
  if ( InstrIsSet(cmd.itype, CF_CALL) )
  {
    if ( !func_does_return(ea) )
      flow = false;
    ftype = fl_CN;
  }
  ua_add_cref(x.offb, ea, ftype);
}

//----------------------------------------------------------------------
static void process_operand(op_t &x,int isAlt,int isload)
{
  switch ( x.type )
  {
    case o_reg:
      break;
    default:
//      interr("emu");
      break;
    case o_imm:
//      if ( !isload ) interr("emu2");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN);
      break;
    case o_phrase:
      if ( !isAlt && isOff(uFlag, x.n) )
      {
        ua_add_off_drefs2(x, isload ? dr_R : dr_W, OOF_ADDR);
        ea_t ea = calc_target(cmd.ea+x.offb, cmd.ea, x.n, x.addr);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload )
          doVar(ea);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_mem(x);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload )
          doVar(ea);
        if ( x.amode & amode_l )
        {
          ea = ymem + x.addr;
          ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
          ua_dodata2(x.offb, ea, x.dtyp);
        }
      }
      break;
    case o_near:
      add_near_ref(x, calc_mem(x));
      break;
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  if ( segtype(cmd.ea) == SEG_XTRN ) return 1;

  uint32 Feature = cmd.get_canon_feature();
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);
  int flag3 = is_forced_operand(cmd.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) process_operand(cmd.Op1, flag1, 1);
  if ( Feature & CF_USE2 ) process_operand(cmd.Op2, flag2, 1);
  if ( Feature & CF_USE3 ) process_operand(cmd.Op3, flag3, 1);

  if ( Feature & CF_CHG1 ) process_operand(cmd.Op1, flag1, 0);
  if ( Feature & CF_CHG2 ) process_operand(cmd.Op2, flag2, 0);
  if ( Feature & CF_CHG3 ) process_operand(cmd.Op3, flag3, 0);

  fill_additional_args();
  for ( int i=0; i < aa.nargs; i++ )
  {
    op_t *x = aa.args[i];
    for ( int j=0; j < 2; j++,x++ )
    {
      if ( x->type == o_void ) break;
      process_operand(*x, 0, j==0);
    }
  }

//
//      Determine if the next instruction should be executed
//
  if ( Feature & CF_STOP ) flow = 0;
  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

  return 1;
}

//----------------------------------------------------------------------
int may_be_func(void)           // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
{
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(int /*nocrefs*/)
{
  // disallow jumps to nowhere
  if ( cmd.Op1.type == o_near && !isEnabled(calc_mem(cmd.Op1)) )
    return 0;

  // disallow many nops in a now
  int i = 0;
  for ( ea_t ea=cmd.ea; i < 32; i++,ea++ )
    if ( get_byte(ea) != 0 )
      break;
  if ( i == 32 )
    return 0;

  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) ) return 0;
  switch ( cmd.itype )
  {
    case DSP56_nop:
      break;
    default:
      return 0;
  }
  return cmd.size;
}



#include "kr1878.hpp"
#include <frame.hpp>
#include <srarea.hpp>

static bool flow;
//----------------------------------------------------------------------
ea_t calc_mem(op_t &x)
{
  return toEA(cmd.cs, x.addr);
}

//------------------------------------------------------------------------
ea_t calc_data_mem(op_t &x, ushort segreg)
{
    sel_t dpage = getSR(cmd.ea, segreg);
    if ( dpage == BADSEL )
      return BADSEL;
    return xmem + (((dpage & 0xFF) << 3) | (x.value));
}

//------------------------------------------------------------------------
inline bool is_stkreg(int r)
{
  return r == DSP;
}

//------------------------------------------------------------------------
int idaapi is_sp_based(const op_t &x)
{
  return OP_SP_ADD | (x.phrase == DSP ? OP_SP_BASED : OP_FP_BASED);
}

//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {

    case KR1878_movl:
    case KR1878_cmpl:     // Compare
    case KR1878_addl:     // Addition
    case KR1878_subl:     // Subtract
    case KR1878_bic:
    case KR1878_bis:
    case KR1878_btg:
    case KR1878_btt:
    case KR1878_ldr:
    case KR1878_sst:
    case KR1878_cst:

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
static void process_operand(op_t &x, bool isAlt, bool isload)
{
  switch ( x.type )
  {
    case o_reg:
      break;
    default:
//      interr("emu");
      break;
    case o_imm:
      if ( !isload ) interr("emu2");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN);
      break;
   case o_mem:
      if ( !isAlt )
      {
        ea_t ea = calc_mem(x);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload ) doVar(ea);
      }
      break;
    case o_phrase:
      if ( !isAlt )
      {
       if ( ( x.reg != SR3 ) || ( x.value < 6 ) )
        {
                ea_t ea = calc_data_mem(x, as + x.reg);
                ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
                ua_dodata2(x.offb, ea, x.dtyp);
                if ( !isload ) doVar(ea);
        }
      }
      break;
    case o_near:
      if ( !isAlt )
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

// check for Segment changes
  if ( cmd.itype == KR1878_ldr
    && cmd.Op1.type == o_reg
    && cmd.Op1.reg < SR4 )
  {
    splitSRarea1(get_item_end(cmd.ea), as + cmd.Op1.reg, cmd.Op2.value & 0xFF, SR_auto);
  }
//
//      Determine if the next instruction should be executed
//
  if ( Feature & CF_STOP ) flow = false;
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
  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) ) return 0;
  switch ( cmd.itype )
  {
    case KR1878_nop:
      break;
    default:
      return 0;
  }
  return cmd.size;
}


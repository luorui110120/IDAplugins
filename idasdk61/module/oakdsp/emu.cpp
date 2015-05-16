
#include "oakdsp.hpp"
#include <srarea.hpp>
#include <frame.hpp>

static bool flow;
static bool delayed;
static int  cycles;
//----------------------------------------------------------------------
ea_t calc_mem(op_t &x)
{
  uint xaddr;

  if ( x.amode & amode_x )
  {
          if ( x.amode & amode_short )
          {
                sel_t dpage = getSR(cmd.ea, PAGE);
                if ( dpage == BADSEL ) return BADSEL;
                xaddr = ((dpage & 0xFF) << 8) | uint(x.addr);
          }
          else
                xaddr = (uint)x.addr;

          return xmem == BADADDR ? BADADDR : xmem + xaddr;
  }

  return toEA(cmd.cs, x.addr);

}
//------------------------------------------------------------------------

void init_emu(void)
{
   delayed = false;
   cycles = 0;
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
    case OAK_Dsp_shfi:
    case OAK_Dsp_movsi:

      op_dec(cmd.ea, n);
      uFlag = getFlags(cmd.ea);
      break;

    case OAK_Dsp_lpg:
    case OAK_Dsp_mpyi:
    case OAK_Dsp_mov:
    case OAK_Dsp_rets:
    case OAK_Dsp_rep:
    case OAK_Dsp_load:
    case OAK_Dsp_push:
    case OAK_Dsp_bkrep:
    case OAK_Dsp_msu:
    case OAK_Dsp_tstb:
    case OAK_Dsp_or:
    case OAK_Dsp_and:
    case OAK_Dsp_xor:
    case OAK_Dsp_add:
    case OAK_Dsp_alm_tst0:
    case OAK_Dsp_alm_tst1:
    case OAK_Dsp_cmp:
    case OAK_Dsp_sub:
    case OAK_Dsp_alm_msu:
    case OAK_Dsp_addh:
    case OAK_Dsp_addl:
    case OAK_Dsp_subh:
    case OAK_Dsp_subl:
    case OAK_Dsp_sqr:
    case OAK_Dsp_sqra:
    case OAK_Dsp_cmpu:
    case OAK_Dsp_set:
    case OAK_Dsp_rst:
    case OAK_Dsp_chng:
    case OAK_Dsp_addv:
    case OAK_Dsp_alb_tst0:
    case OAK_Dsp_alb_tst1:
    case OAK_Dsp_cmpv:
    case OAK_Dsp_subv:
    case OAK_Dsp_mpy:
    case OAK_Dsp_mpysu:
    case OAK_Dsp_mac:
    case OAK_Dsp_macus:
    case OAK_Dsp_maa:
    case OAK_Dsp_macuu:
    case OAK_Dsp_macsu:
    case OAK_Dsp_maasu:

      op_num(cmd.ea, n);
      uFlag = getFlags(cmd.ea);
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
          ua_add_off_drefs2(x, dr_O, x.amode & amode_signed ? OOF_SIGNED : 0);
        break;

    case o_phrase:
      if ( !isAlt && isOff(uFlag, x.n) )
      {
        ua_add_off_drefs2(x, isload ? dr_R : dr_W, OOF_ADDR);
        ea_t ea = calc_target(cmd.ea+x.offb, cmd.ea, x.n, x.addr);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload ) doVar(ea);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_mem(x);
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload ) doVar(ea);
      }
      break;
    case o_near:
      add_near_ref(x, calc_mem(x));
      break;
    case o_textphrase:
      break;

    case o_local: // local variables
      if ( may_create_stkvars() )
      {
         func_t *pfn = get_func(cmd.ea);
         if ( (pfn != NULL) && (pfn->flags & FUNC_FRAME) && ua_stkvar2(x, x.addr, STKVAR_VALID_SIZE) )
                        op_stkvar(cmd.ea, x.n);
      }
      break;

  }
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

  int16 frame;

  // trace SP changes

  switch ( cmd.itype )
  {
    case OAK_Dsp_reti_u:
    case OAK_Dsp_retid:
    case OAK_Dsp_reti:
      add_stkpnt(1);
      break;

    case OAK_Dsp_ret_u:
    case OAK_Dsp_retd:
    case OAK_Dsp_ret:
      add_stkpnt(1);
      break;

    case OAK_Dsp_rets:
      add_stkpnt(1 + cmd.Op1.value);
      break;

    case OAK_Dsp_pop:
      add_stkpnt(1);
      break;

    case OAK_Dsp_push:
      add_stkpnt(-1);
      break;

    case OAK_Dsp_addv:
            if ( (cmd.Op1.type == o_imm) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == SP) )
            {
                    frame = (uint16)cmd.Op1.value;
                    add_stkpnt(frame);
            }
      break;

    case OAK_Dsp_subv:
            if ( (cmd.Op1.type == o_imm) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == SP) )
            {
                    frame = (uint16)cmd.Op1.value;
                    add_stkpnt(-frame);
            }
      break;


  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  if ( segtype(cmd.ea) == SEG_XTRN ) return 1;

  //uint32 Feature = cmd.get_canon_feature();
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);
  int flag3 = is_forced_operand(cmd.ea, 2);

//      Determine if the next instruction should be executed
  flow = (InstrIsSet(cmd.itype, CF_STOP) != true);



  if ( InstrIsSet(cmd.itype,CF_USE1) ) process_operand(cmd.Op1, flag1, 1);
  if ( InstrIsSet(cmd.itype,CF_USE2) ) process_operand(cmd.Op2, flag2, 1);
  if ( InstrIsSet(cmd.itype,CF_USE3) ) process_operand(cmd.Op3, flag3, 1);

  if ( InstrIsSet(cmd.itype,CF_CHG1) ) process_operand(cmd.Op1, flag1, 0);
  if ( InstrIsSet(cmd.itype,CF_CHG2) ) process_operand(cmd.Op2, flag2, 0);
  if ( InstrIsSet(cmd.itype,CF_CHG3) ) process_operand(cmd.Op3, flag3, 0);


  // check for DP changes
  if ( cmd.itype == OAK_Dsp_lpg )
                splitSRarea1(get_item_end(cmd.ea), PAGE, cmd.Op1.value & 0xFF, SR_auto);
  if ( ( cmd.itype == OAK_Dsp_mov ) && (cmd.Op1.type == o_imm) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == ST1) )
                splitSRarea1(get_item_end(cmd.ea), PAGE, cmd.Op1.value & 0xFF, SR_auto);


  //Delayed Return

  insn_t saved = cmd;
  cycles = cmd.cmd_cycles;
  delayed = false;

  if ( decode_prev_insn(cmd.ea) != BADADDR )
  {
          if  ( (cmd.itype == OAK_Dsp_retd) || (cmd.itype == OAK_Dsp_retid) )
                  delayed = true;
          else
                  cycles += cmd.cmd_cycles;

          if ( !delayed )
                if ( decode_prev_insn(cmd.ea) != BADADDR )
                        if ( (cmd.itype == OAK_Dsp_retd) || (cmd.itype == OAK_Dsp_retid) )
                                delayed = true;
  }

  if ( delayed && (cycles > 1)  )
          flow = 0;

  cmd = saved;

  //mov #imm, pc

  if ( ( cmd.itype == OAK_Dsp_mov ) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == PC) )
     flow = 0;

  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);

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
    case OAK_Dsp_nop:
      break;
    default:
      return 0;
  }
  return cmd.size;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)     // create frame of newly created function
{
  bool std_vars_func = true;

  if ( pfn != NULL )
  {
    if ( pfn->frame == BADNODE )
    {
      ea_t ea = pfn->startEA;
      int regsize = 0;

      while ( ea < pfn->endEA ) // check for register pushs
      {
        decode_insn(ea);
        ea += cmd.size;         // считаем кол-во push
        if ( (cmd.itype == OAK_Dsp_push) && (cmd.Op1.type == o_reg) )
            regsize++;
        else
            break;
      }


      ea = pfn->startEA;
      int16 localsize = 0;
      while ( ea < pfn->endEA ) // check for frame creation
      {
        decode_insn(ea);
        ea += cmd.size; // Попытка определить команду типа      ADDV    #,SP
        if ( (cmd.itype == OAK_Dsp_addv) && (cmd.Op1.type == o_imm) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == SP) )
        {
          localsize = (uint16)cmd.Op1.value;
          break;
        }

        // Если встретили команду mov #, rb  --> не надо создавать фрейм такой ф-ции, и объявлять локальные переменные
        if ( (cmd.itype == OAK_Dsp_mov) && (cmd.Op1.type == o_imm) && (cmd.Op2.type == o_reg) && (cmd.Op2.reg == RB) )
        {
          std_vars_func = false;
          break;
        }

      }

      if ( std_vars_func )
      {
         pfn->flags |= FUNC_FRAME;
         update_func(pfn);
      }

      add_frame(pfn, -localsize, (ushort)regsize, 0);

    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi OAK_get_frame_retsize(func_t * /*pfn*/)
{
  return 1;     // 1 'byte' for the return address
}

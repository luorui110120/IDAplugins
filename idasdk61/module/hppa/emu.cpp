/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "hppa.hpp"
#include <frame.hpp>
#include <struct.hpp>
#include <typeinf.hpp>

static bool flow;
//----------------------------------------------------------------------
// map virtual to physical ea
ea_t calc_mem(ea_t ea)
{
  return ea;
}

//------------------------------------------------------------------------
static ea_t get_dp(void)
{
  if ( got == BADADDR )
    return BADADDR;
  sel_t delta = getSR(cmd.ea, DPSEG);
  if ( delta == BADSEL )
    return BADADDR;
  // calculate the return value
  // if we don't do it in a separate statement, bcb6 generates
  // wrong code with __EA64__
  ea_t dp = got + delta;
  return dp;
}

//-------------------------------------------------------------------------
// returns:
//      -1: doesn't spoil anything
//      -2: spoils everything
//     >=0: the number of the register which is spoiled
static int spoils(const uint32 *regs, int n)
{
  switch ( cmd.itype )
  {
    case HPPA_call:
    case HPPA_blr:
      for ( int i=0; i < n; i++ )
        if ( regs[i] >= 23 && regs[i] != DP ) // assume the first 8 registers are not spoiled
          return i;                           // dp is never spoiled
  }
  return get_spoiled_reg(regs, n);
}

//----------------------------------------------------------------------
static bool find_addil_or_ldil(uint32 r, ea_t dp, uval_t *pv)
{
  func_item_iterator_t fii(get_func(cmd.ea), cmd.ea);
  uval_t v;
  while ( fii.decode_prev_insn() )
  {
    switch ( cmd.itype )
    {
      case HPPA_addil:
        if ( cmd.Op3.reg == r )
        {
          if ( cmd.Op2.reg == R0 )
          {
            v = cmd.Op1.value;
RETTRUE:
            *pv = v;
            return true;
          }
          if ( cmd.Op2.reg == DP )
          {
            v = dp + cmd.Op1.value;
            goto RETTRUE;
          }
        }
        continue;
      case HPPA_ldil:
        if ( cmd.Op2.reg == r )
        {
          v = cmd.Op1.value;
          goto RETTRUE;
        }
      case HPPA_copy:
        if ( cmd.Op2.reg == r )
        {
          r = cmd.Op1.reg;
          if ( r == R0 )
          {
            v = 0;
            goto RETTRUE;
          }
        }
        continue;
    }
    if ( spoils(&r, 1) != -1 )
      break;
  }
  return false;
}

//----------------------------------------------------------------------
//      addil           -0x2800, %dp, %r1
//      stw             %r5, 0x764(%sr0,%r1)
ea_t calc_possible_memref(op_t &x)
{
  ea_t dp = get_dp();
  if ( dp != BADADDR )
  {
    if ( x.phrase == DP )
    {
      dp += x.addr;
    }
    else
    {
      insn_t saved = cmd;
      int r = x.phrase;
      uval_t v = x.addr;
      uval_t v2 = 0;
      if ( find_addil_or_ldil(r, dp, &v2) )
      {
        dp = v + v2;
      }
      else
        dp = BADADDR;
      cmd = saved;
    }
  }
  return dp;
}

//------------------------------------------------------------------------
inline bool is_stkreg(int r)
{
  return r == SP;
}

//------------------------------------------------------------------------
int idaapi is_sp_based(const op_t &x)
{
  return OP_SP_ADD | (is_stkreg(x.phrase) ? OP_SP_BASED : OP_FP_BASED);
}

//------------------------------------------------------------------------
// is the register the frame pointer?
static bool is_frreg(int reg)
{
  if ( reg != 0 )
  {
    func_t *pfn = get_func(cmd.ea);
    if ( pfn != NULL )
    {
      ea_t ea = pfn->startEA;
      static ea_t oldea = BADADDR;
      static int oldreg;
      if ( ea != oldea )
      {
        oldea = ea;
        oldreg = (int)helper.altval(oldea);
      }
      return reg == oldreg;
    }
  }
  return false;
}

//------------------------------------------------------------------------
inline bool stldwm(void)
{
  return cmd.itype == HPPA_ldo && cmd.Op2.reg == SP     // ldo .., %sp
      || (opcode(get_long(cmd.ea)) & 0x13) == 0x13;     // st/ldw,m
}

//------------------------------------------------------------------------
inline void remove_unwanted_typeinfo(int n)
{
  if ( isDefArg(uFlag,n) )
    noType(cmd.ea, n);
}

//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {
    case HPPA_depd:
    case HPPA_depw:
    case HPPA_extrd:
    case HPPA_extrw:
    case HPPA_hshl:
    case HPPA_hshladd:
    case HPPA_hshr:
    case HPPA_hshradd:
    case HPPA_shladd:
    case HPPA_shrpd:
    case HPPA_shrpw:
    case HPPA_shrd:
    case HPPA_shrw:
    case HPPA_shld:
    case HPPA_shlw:
      op_dec(cmd.ea, n);
      break;
    case HPPA_depdi:
    case HPPA_depwi:
      if ( n == 0 )
        op_num(cmd.ea, n);
      else
        op_dec(cmd.ea, n);
      break;
    case HPPA_popbts:
    case HPPA_rsm:
    case HPPA_ssm:
      op_num(cmd.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
enum nullicode_t { NEVER, SKIP, NULLIFY };
static nullicode_t may_skip_next_insn(ea_t ea)
{
  nullicode_t may = NEVER;
  insn_t saved = cmd;
  if ( decode_insn(ea) )
  {
    switch ( cmd.itype )
    {
      case HPPA_pmdis:    // format 55
      case HPPA_spop0:    // format 34
      case HPPA_spop1:    // format 35
      case HPPA_spop2:    // format 36
      case HPPA_spop3:    // format 37
      case HPPA_copr:     // format 38
        may = (get_long(ea) & BIT26) != 0 ? SKIP : NEVER;
        break;
      case HPPA_addb:     // format 17
      case HPPA_addib:
      case HPPA_cmpb:
      case HPPA_cmpib:
      case HPPA_movb:
      case HPPA_movib:
      case HPPA_bb:       // format 18
      case HPPA_be:       // format 19
      case HPPA_b:        // format 20
      case HPPA_blr:      // format 21
      case HPPA_bv:
      case HPPA_call:     // pseudo-op
      case HPPA_bve:      // format 22
      case HPPA_ret:      // pseudo-op
        may = ((get_long(ea) & BIT30) != 0) ? NULLIFY : NEVER;
        break;
      default:
        may = (cmd.auxpref & aux_cndc) != 0 ? SKIP : NEVER;
        break;
    }
  }
  cmd = saved;
  return may;
}

//----------------------------------------------------------------------
static bool is_cond_branch(uint32 code)
{
  switch ( opcode(code) )
  {
    case 0x20:  // cmpb
    case 0x22:  // cmpb
    case 0x27:  // cmpb
    case 0x2F:  // cmpb
    case 0x28:  // addb
    case 0x2A:  // addb
    case 0x32:  // movb
    case 0x21:  // cmpib
    case 0x23:  // cmpib
    case 0x3B:  // cmpib
    case 0x29:  // addib
    case 0x2B:  // addib
    case 0x33:  // movib
    case 0x30:  // bb
    case 0x31:  // bb
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool is_uncond_branch(uint32 code)
{
  int sub;
  switch ( opcode(code) )
  {
    case 0x38:          // be
      return true;
    case 0x3A:
      sub = (code>>13) & 7;
      switch ( sub )
      {
        case 0:     // b,l
        case 1:     // b,gate
        case 2:     // blr
          return r06(code) == R0;
        case 6:     // bv/bve
          return true;
      }
      break;
    case 0x22:            // cmpb
    case 0x23:            // cmpib
    case 0x2F:            // cmpb
    case 0x2A:            // addb
    case 0x2B:            // addib
      return ((code>>13) & 7) == 0;
    case 0x32:            // movb
    case 0x33:            // movib
      return ((code>>13) & 7) == 4;
  }
  return false;
}

//----------------------------------------------------------------------
static bool is_call_branch(uint32 code)
{
  int sub;
  switch ( opcode(code) )
  {
    case 0x39:          // be,l
      return true;
    case 0x3A:
      sub = (code>>13) & 7;
      switch ( sub )
      {
        case 0:     // b,l
        case 1:     // b,gate
        case 2:     // blr
          return r06(code) != R0;
        case 4:     // b,l,push
        case 5:     // b,l
        case 7:     // bve,l
          return true;
      }
      break;
  }
  return false;
}

//----------------------------------------------------------------------
static nullicode_t may_be_skipped(ea_t ea)
{
  if ( !isFlow(get_flags_novalue(ea)) )
    return NEVER;
  return may_skip_next_insn(ea-4);
}

//----------------------------------------------------------------------
static ea_t calc_branch_target(ea_t ea)
{
  ea_t res = BADADDR;
  insn_t saved = cmd;
  if ( decode_insn(ea) )
  {
    for ( int i=0; i < UA_MAXOP; i++ )
    {
      if ( cmd.Operands[i].type == o_near )
      {
        res = cmd.Operands[i].addr;
        break;
      }
    }
  }
  cmd = saved;
  return res;
}

//----------------------------------------------------------------------
inline bool is_stop(uint32 code, bool include_calls_and_conds)
{
  return is_uncond_branch(code)
      || include_calls_and_conds
                && (is_cond_branch(code) || is_call_branch(code));
}

//----------------------------------------------------------------------
// does the specified address have a delay slot?
static bool has_delay_slot(ea_t ea, bool include_calls_and_conds)
{
  if ( (include_calls_and_conds || may_be_skipped(ea) != SKIP)
    && calc_branch_target(ea) != ea+4 )
  {
    uint32 code = get_long(ea);
    return is_stop(code, include_calls_and_conds)  && (code & BIT30) == 0;
  }
  return false;
}

//----------------------------------------------------------------------
// is the current insruction in a delay slot?
static bool is_delayed_stop(bool include_calls_and_conds)
{
  uint32 code = get_long(cmd.ea);
  if ( (code & BIT30) != 0              // ,n
    && is_stop(code, include_calls_and_conds)
    && (include_calls_and_conds || may_be_skipped(cmd.ea) != SKIP) )
  {
    // seems to be a branch which nullifies the next instruction
    return true;
  }

  if ( !isFlow(uFlag) )
    return false;

  return has_delay_slot(cmd.ea-4, include_calls_and_conds);
}

//----------------------------------------------------------------------
static void add_near_ref(op_t &x, ea_t ea)
{
  cref_t ftype = fl_JN;
  if ( is_call_branch(get_long(cmd.ea)) )
    ftype = fl_CN;
  if ( InstrIsSet(cmd.itype, CF_CALL) )
  {
    if ( !func_does_return(ea) )
      flow = false;
    ftype = fl_CN;
  }
  ua_add_cref(x.offb, ea, ftype);
  if ( ftype == fl_CN )
    auto_apply_type(cmd.ea, ea);
}

//----------------------------------------------------------------------
inline dref_t calc_dref_type(bool isload)
{
  if ( cmd.itype == HPPA_ldo ) return dr_O;
  return isload ? dr_R : dr_W;
}

//----------------------------------------------------------------------
static bool create_lvar(op_t &x, uval_t v)
{
  struct lvar_info_t
  {
    int delta;
    const char *name;
  };
  static const lvar_info_t linfo[] =
  {
    { -4,   "prev_sp"     },
    { -8,   "rs_rp"       },    // RP'' (relocation stub RP)
    { -12,  "cleanup"     },
    { -16,  "static_link" },
    { -20,  "cur_rp"      },
    { -24,  "es_rp"       },    // RP' (external/stub RP)
    { -28,  "LPT_"        },    // (external SR4/LT pointer)
    { -32,  "LPT"         },    // (external Data/LT pointer)
  };

  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return false;

  sval_t delta;
  member_t *mptr = get_stkvar(x, v, &delta);
  if ( mptr == NULL )
  {
    if ( !ua_stkvar2(x, v, STKVAR_VALID_SIZE) )
      return false;
    mptr = get_stkvar(x, v, &delta);
    if ( mptr == NULL )
      return false;   // should not happen but better check
    delta -= pfn->frsize;
    // delta contains real offset from SP
    for ( size_t i=0; i < qnumber(linfo); i++ )
    {
      if ( delta == linfo[i].delta )
      {
        set_member_name(get_frame(pfn), delta+pfn->frsize, linfo[i].name);
        break;
      }
    }
    if ( delta <= -0x34 )       // seems to be an argument in the stack
    {                           // this means that the current function
                                // has at least 4 register arguments
      func_t *pfn = get_func(cmd.ea);
      const type_t t_int[] = { BT_INT, 0 };
      while ( pfn->regargqty < 4 )
        add_regarg(pfn, R26-pfn->regargqty, t_int, NULL);
    }
  }

  return op_stkvar(cmd.ea, x.n);
}

//----------------------------------------------------------------------
// recognize the following code:
// 20 20 08 01                 ldil            -0x40000000, %r1
// E4 20 E0 08                 be,l            4(%sr7,%r1), %sr0, %r31 # C0000004
// followed by:
//                             ldi             NNN, %r22
// as a system call number NNN.
// return -1 if not found
static int get_syscall_number(ea_t ea)
{
  int syscall = -1;
  if ( get_long(ea) == 0x20200801
    && get_long(ea+4) == 0xE420E008 )
  {
    insn_t saved = cmd;
    decode_insn(ea+8);
    if ( cmd.itype == HPPA_ldi && cmd.Op2.reg == R22 )
      syscall = (int)cmd.Op1.value;
    cmd = saved;
  }
  return syscall;
}

//----------------------------------------------------------------------
static void process_operand(op_t &x,int isAlt,int isload)
{
  switch ( x.type )
  {
    case o_reg:
/*      if ( x.reg == GP
        && cmd.itype != ALPHA_lda
        && cmd.itype != ALPHA_ldah
        && cmd.itype != ALPHA_br
        && !isload ) splitSRarea1(cmd.ea+cmd.size, GPSEG, BADSEL, SR_auto);*/
      break;
    default:
      if ( cmd.itype == HPPA_fcmp
        || cmd.itype == HPPA_b
        || cmd.itype == HPPA_ftest ) return;
      interr("emu");
      break;
    case o_based:     // (%r5)
      break;
    case o_imm:
//      if ( !isload ) interr("emu2");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOF_SIGNED);
      break;
    case o_displ:
      process_immediate_number(x.n);
      if ( is_stkreg(x.reg) || is_frreg(x.reg) )
      {
        if ( may_create_stkvars() && !isDefArg(uFlag, x.n) )
        {
          if ( stldwm() )
            op_num(cmd.ea, -1);
          else
            create_lvar(x, x.addr);
        }
      }
      else
      {
        ea_t ea = calc_possible_memref(x);
        if ( ea != BADADDR )
        {
          if ( cmd.itype == HPPA_be )
            add_near_ref(x, ea);
          else
            ua_add_dref(x.offb, ea, calc_dref_type(isload));
          ua_dodata2(x.offb, ea, x.dtyp);
          if ( !isload )
          {
            doVar(ea);
          }
          else
          {
            ea_t ea2 = get_long(ea);
            if ( isEnabled(ea2) ) ua_add_dref(x.offb, ea2, dr_O);
          }
        }
      }
      // no break
    case o_phrase:
      if ( isAlt ) break;
      if ( isOff(uFlag, x.n) )
      {
        ua_add_off_drefs2(x, isload ? dr_R : dr_W, OOF_SIGNED|OOF_ADDR);
        ea_t ea = calc_target(cmd.ea+x.offb, cmd.ea, x.n, x.addr);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload ) doVar(ea);
      }
      break;
    case o_near:
      add_near_ref(x, calc_mem(x.addr));
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
  switch ( cmd.itype )
  {
    // stw,m           %r3, 0x80(%sr0,%sp)
    case HPPA_stw:
      if ( opcode(get_long(cmd.ea)) == 0x1B     // stw,m
        && is_stkreg(cmd.Op2.reg) )
      {
        add_stkpnt(cmd.Op2.addr);
      }
      break;
    // ldw,m           -0x80(%sr0,%sp), %r3
    case HPPA_ldw:
      if ( opcode(get_long(cmd.ea)) == 0x13     // ldw,m
        && is_stkreg(cmd.Op1.reg) )
      {
        add_stkpnt(cmd.Op1.addr);
      }
      break;
    case HPPA_ldo:
      if ( is_stkreg(cmd.Op2.reg) )
      {
        // ldo -0x80(%sp), %sp
        if ( is_stkreg(cmd.Op1.reg) )
        {
          add_stkpnt(cmd.Op1.addr);
        }
        else if ( is_frreg(cmd.Op1.reg) )
        {
          // analog of the 'leave' instruction
          // (restores the original value of sp + optional delta
          // using the frame pointer register)
          // ldo 4(%r4), %sp
          func_t *pfn = get_func(cmd.ea);
          if ( pfn != NULL )
          {
            sval_t delta = cmd.Op1.addr + pfn->frregs - get_spd(pfn,cmd.ea);
            add_stkpnt(-delta);
          }
        }
      }
      break;
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{

  if ( segtype(cmd.ea) == SEG_XTRN ) return 1;

  uint32 Feature = cmd.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  int i;
  for ( i=0; i < UA_MAXOP; i++ )
    if ( Feature & (CF_USE1<<i) )
      process_operand(cmd.Operands[i], is_forced_operand(cmd.ea, i), true);

  for ( i=0; i < UA_MAXOP; i++ )
    if ( Feature & (CF_CHG1<<i) )
      process_operand(cmd.Operands[i], is_forced_operand(cmd.ea, i), false);

//
//      Determine if the next instruction should be executed
//
  if ( Feature & CF_STOP ) flow = false;
  if ( is_delayed_stop(false) ) flow = false;
  if ( flow )
    ua_add_cref(0,cmd.ea+cmd.size,fl_F);

//
//      Handle SP modifications
//
  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(cmd.ea);     // recalculate SP register for the next insn
    else
      trace_sp();
  }

// Handle system calls
  if ( cmd.itype == HPPA_ldi && !has_cmt(uFlag) )
  {
    int syscall = get_syscall_number(cmd.ea-8);
    if ( syscall >= 0 )
    {
      const char *syscall_name = get_syscall_name(syscall);
      if ( syscall_name != NULL )
      {
        append_cmt(cmd.ea, syscall_name, false);
        flags_t F = get_flags_novalue(cmd.ea-8);
        if ( hasRef(F) && !has_user_name(F) )
          set_name(cmd.ea-8, syscall_name, SN_NOWARN);
      }
    }
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
//      ldah    $gp, 0x2000($27)
//  if ( cmd.itype == ALPHA_ldah && cmd.Op1.reg == GP ) return 100;
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(int /*nocrefs*/)
{
  // disallow jumps to nowhere
  if ( cmd.Op1.type == o_near && !isEnabled(calc_mem(cmd.Op1.addr)) )
    return 0;
  // don't disassemble 0 as break 0,0 automatically
  if ( cmd.itype == HPPA_break && get_long(cmd.ea) == 0 ) return 0;
  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) ) return 0;
  switch ( cmd.itype )
  {
    case HPPA_break:
      if ( get_long(cmd.ea) ) return 0;
      break;
    case HPPA_nop:
      break;
    default:
      return 0;
  }
  return cmd.size;
}

//----------------------------------------------------------------------
int idaapi hppa_get_frame_retsize(func_t *)
{
  return 0;     // ALPHA doesn't use stack for function return addresses
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  ea_t ea = pfn->startEA;
  int frame_reg = 0;
  for ( int i=0; i < 16; i++ )
  {
    decode_insn(ea);
    if ( cmd.itype == HPPA_copy && is_stkreg(cmd.Op1.reg) )
      frame_reg = cmd.Op2.reg;
    if ( opcode(get_long(ea)) == 0x1B )    // stw,m
    {
      if ( frame_reg != 0 )
        helper.altset(pfn->startEA, frame_reg);
      return true;//add_frame(pfn, 0, 0, 0);
//      return add_frame(pfn, cmd.Op2.addr, 0, 0);
    }
    ea += 4;
  }
  return 0;
}

//----------------------------------------------------------------------
bool is_basic_block_end(void)
{
  if ( is_delayed_stop(true) ) return true;
  return !isFlow(get_flags_novalue(cmd.ea+cmd.size));
}

//-------------------------------------------------------------------------
int hppa_calc_arglocs(const type_t *type, cm_t /*cc*/, uint32 *arglocs)
{
  skip_type(idati, type);       // return type
  int n = get_dt(type);
  if ( n < 0 )
    return -1;

  // first of all, calculate rounded sizes of all arguments and put then into the array
  const type_t *tp = type;
  int r = 0;
  int i;
  for ( i=0; i <= n; i++ )
  {
    size_t a = 0;
    if ( i < n )
    {
      a = get_funcarg_size(idati, tp);
      if ( a == BADSIZE )
        return -1;
      a = align_up(a, inf.cc.size_i);
    }
    if ( r < 4 )        // first 4 arguments are in %r26, 25, 24, 23
      arglocs[i] = ARGLOC_REG | (26 - r);
    else
      arglocs[i] = 0x24 + r * 4;
    r += int(a / 4);
  }
  return 2;
}

//-------------------------------------------------------------------------
static bool hppa_set_op_type(op_t &x, const type_t *type, const char *name, eavec_t &visited)
{
  switch ( x.type )
  {
    case o_imm:
      if ( is_type_ptr(type[0])
        && x.value != 0
        && !isDefArg(get_flags_novalue(cmd.ea), x.n) )
      {
        return set_offset(cmd.ea, x.n, 0);
      }
      break;
    case o_mem:
      {
        ea_t dea = calc_mem(x.addr);
        return apply_once_type_and_name(dea, type, name);
      }
    case o_displ:
      return apply_type_to_stkarg(x, x.addr, type, name);
    case o_reg:
      {
        uint32 r = x.reg;
        func_t *pfn = get_func(cmd.ea);
        if ( pfn == NULL ) return false;
        bool ok;
        bool farref;
        func_item_iterator_t fii;
        for ( ok=fii.set(pfn, cmd.ea);
              ok && (ok=fii.decode_preceding_insn(&visited, &farref)) != false; )
        {
          if ( farref )
            continue;
          switch ( cmd.itype )
          {
            case HPPA_ldo:
              if ( cmd.Op2.reg != r ) continue;
              remove_type_pointer(idati, &type, &name);
              // no break
            case HPPA_copy:
            case HPPA_ldw:
            case HPPA_ldi:
            case HPPA_ldil:
              if ( cmd.Op2.reg != r ) continue;
              return hppa_set_op_type(cmd.Op1, type, name, visited);
            default:
              {
                int code = spoils(&r, 1);
                if ( code == -1 ) continue;
              }
              break;
          }
          break;
        }
        if ( !ok && cmd.ea == pfn->startEA )
        { // reached the function start, this looks like a register argument
          add_regarg(pfn, r, type, name);
          break;
        }
      }
      break;
  }
  return false;
}

//-------------------------------------------------------------------------
static bool idaapi set_op_type(op_t &x, const type_t *type, const char *name)
{
  eavec_t visited;
  return hppa_set_op_type(x, type, name, visited);
}

//-------------------------------------------------------------------------
int hppa_use_regvar_type(ea_t ea,
                         const type_t * const *types,
                         const char * const *names,
                         const uint32 *regs,
                         int n)
{
  int idx = -1;
  if ( decode_insn(ea) )
  {
    idx = spoils(regs, n);
    if ( idx >= 0 )
    {
      const type_t *type = types[idx];
      const char *name = names[idx];
      switch ( cmd.itype )
      {
        case HPPA_ldo:
          remove_type_pointer(idati, &type, &name);
          // no break
        case HPPA_copy:
        case HPPA_ldw:
        case HPPA_ldi:
        case HPPA_ldil:
          set_op_type(cmd.Op1, type, name);
        case HPPA_depw:
        case HPPA_depwi:
        case HPPA_depd:
        case HPPA_depdi:
        case HPPA_extrw:
        case HPPA_extrd:
          break;
        default: // unknown instruction changed the register, stop tracing it
          idx |= REG_SPOIL;
          break;
      }
    }
  }
  return idx;
}

//-------------------------------------------------------------------------
static bool idaapi has_delay_slot(ea_t ea)
{
  return has_delay_slot(ea, true);
}

static bool idaapi is_stkarg_load(int *src, int *dst)
{
  if ( cmd.itype == HPPA_stw )
  {
    *src = 0;
    *dst = 1;
    return true;
  }
  return false;
}

//-------------------------------------------------------------------------
int hppa_use_arg_types(ea_t caller,
                       const type_t * const *types,
                       const char * const *names,
                       const uint32 *arglocs,
                       int n,
                       const type_t **rtypes,
                       const char **rnames,
                       uint32 *rlocs,
                       int rn)
{
  return gen_use_arg_types(caller, types, names, arglocs, n,
                           rtypes, rnames, rlocs, rn,
                           set_op_type,
                           is_stkarg_load,
                           has_delay_slot);
}

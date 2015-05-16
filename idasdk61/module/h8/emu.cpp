/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"
#include <frame.hpp>
#include <limits.h>

static int flow;
static bool check_for_table_jump(void);
static bool check_for_generic_indirect_jump(void);
static bool check_for_generic_indirect_call(void);
//------------------------------------------------------------------------
static void process_immediate_number(int n)
{
  doImmd(cmd.ea);
  if ( isDefArg(uFlag,n) ) return;
  switch ( cmd.itype )
  {
    case H8_shal:
    case H8_shar:
    case H8_shll:
    case H8_shlr:
    case H8_rotl:
    case H8_rotr:
    case H8_rotxl:
    case H8_rotxr:
      op_dec(cmd.ea, n);
      break;
    case H8_and:
    case H8_or:
    case H8_xor:
      op_num(cmd.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
inline bool issp(int x)
{
  return x == SP || x == ER7;
}

inline bool isbp(int x)
{
  return x == R6 || x == ER6;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const op_t &x)
{
  return OP_SP_ADD |
    ((x.type != o_displ || x.type != o_phrase) && issp(x.phrase) ? OP_SP_BASED : OP_FP_BASED);
}

//----------------------------------------------------------------------
static void add_stkpnt(ssize_t value)
{
  func_t *pfn = get_func(cmd.ea);
  if ( pfn == NULL )
    return;

  if ( value & 1 )
    value++;

  add_auto_stkpnt2(pfn, cmd.ea+cmd.size, value);
}

//----------------------------------------------------------------------
static bool get_op_value(op_t &x, int *value)
{
  if ( x.type == o_imm )
  {
    *value = (int)x.value;
    return true;
  }
  bool ok = false;
  if ( x.type == o_reg )
  {
    int reg = x.reg;
    insn_t saved = cmd;
    if ( decode_prev_insn(cmd.ea) != BADADDR
      && cmd.itype == H8_mov
      && cmd.Op1.type == o_imm
      && cmd.Op2.type == o_reg
      && cmd.Op2.reg  == reg )
    {
      *value = (int)cmd.Op1.value;
      ok = true;
    }
    cmd = saved;
  }
  return ok;
}

//----------------------------------------------------------------------
static void trace_sp(void)
{
  // @sp++
  if ( cmd.Op1.type == o_phrase
    && issp(cmd.Op1.reg)
    && cmd.Op1.phtype == ph_post )
  {
    ssize_t size = get_dtyp_size(cmd.Op2.dtyp);
    if ( cmd.Op2.type == o_reglist )
      size *= cmd.Op2.nregs;
    add_stkpnt(size);
    return;
  }

  // @--sp
  if ( cmd.Op2.type == o_phrase
    && issp(cmd.Op2.reg)
    && cmd.Op2.phtype == ph_pre )
  {
    ssize_t size = get_dtyp_size(cmd.Op1.dtyp);
    if ( cmd.Op1.type == o_reglist )
      size *= cmd.Op1.nregs;
    add_stkpnt(-size);
    return;
  }

  int v;
  switch ( cmd.itype )
  {
    case H8_add:
    case H8_adds:
      if ( !issp(cmd.Op2.reg) )
        break;
      if ( get_op_value(cmd.Op1, &v) )
        add_stkpnt(v);
      break;
    case H8_sub:
    case H8_subs:
      if ( !issp(cmd.Op2.reg) )
        break;
      if ( get_op_value(cmd.Op1, &v) )
        add_stkpnt(-v);
      break;
    case H8_push:
      add_stkpnt(-get_dtyp_size(cmd.Op1.dtyp));
      break;
    case H8_pop:
      add_stkpnt( get_dtyp_size(cmd.Op1.dtyp));
      break;
  }
}

//----------------------------------------------------------------------
static void add_code_xref(op_t &x, ea_t ea)
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
    case o_phrase:
    case o_reglist:
      return;
    case o_imm:
      if ( !isload ) interr("emu");
      process_immediate_number(x.n);
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, OOFS_IFSIGN|OOFW_IMM);
      break;
    case o_displ:
      process_immediate_number(x.n);
      if ( isAlt ) break;
      if ( isOff(uFlag, x.n) )
      {
        ua_add_off_drefs2(x, isload ? dr_R : dr_W, get_displ_outf(x));
        ea_t ea = calc_target(cmd.ea+x.offb, cmd.ea, x.n, x.addr);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( !isload ) doVar(ea);
      }
      // create stack variables if required
      if ( may_create_stkvars() && !isDefArg(uFlag, x.n) )
      {
        func_t *pfn = get_func(cmd.ea);
        if ( pfn != NULL
          && (issp(x.phrase)
              || isbp(x.phrase) && (pfn->flags & FUNC_FRAME) != 0) )
        {
          if ( ua_stkvar2(x, x.addr, STKVAR_VALID_SIZE) )
            op_stkvar(cmd.ea, x.n);
        }
      }
      break;
    case o_near:
      add_code_xref(x, calc_mem(x.addr));
      break;
    case o_mem:
    case o_memind:
      {
        ea_t ea = calc_mem(x.addr);
        if ( !isEnabled(ea) && find_sym(ea) ) break;    // address not here
        ua_add_dref(x.offb, ea, isload ? dr_R : dr_W);
        ua_dodata2(x.offb, ea, x.dtyp);
        if ( x.type == o_memind )
        {
          ssize_t size = get_dtyp_size(x.dtyp);
          flags_t F = getFlags(ea);
          if ( (isWord(F) || isDwrd(F))
            && (!isDefArg0(F) || isOff0(F)) )
          {
            ea_t target = calc_mem(size == 2
                                ? get_word(ea)
                                : (get_long(ea) & 0xFFFFFFL));
            if ( isEnabled(target) ) add_code_xref(x, target);
            if ( !isOff0(F) )
              set_offset(ea, 0, calc_mem(0));
          }
          break;
        }
        if ( !isload ) doVar(ea);
      }
      break;
    default:
      interr("emu");
  }
}


//----------------------------------------------------------------------
int idaapi emu(void)
{
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

//
//      Check for table and generic indirect jumps
//
  if ( cmd.itype == H8_jmp && cmd.Op1.type == o_phrase )
  {
    if ( !check_for_table_jump() )
      check_for_generic_indirect_jump();
  }

  if ( cmd.itype == H8_jsr && cmd.Op1.type == o_phrase )
  {
    check_for_generic_indirect_call();
  }
//
//      Determine if the next instruction should be executed
//
  if ( segtype(cmd.ea) == SEG_XTRN ) flow = 0;
  if ( flow ) ua_add_cref(0,cmd.ea+cmd.size,fl_F);


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

  return 1;
}

//----------------------------------------------------------------------
int is_jump_func(const func_t * /*pfn*/, ea_t *jump_target)
{
  *jump_target = BADADDR;
  return 1; // means "no"
}

//----------------------------------------------------------------------
int may_be_func(void)           // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
{
  if ( cmd.itype == H8_push && isbp(cmd.Op1.reg) ) return 100;  // push.l er6
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(int /*nocrefs*/)
{
  if ( cmd.itype == H8_nop )
  {
    for ( int i=0; i < 8; i++ )
      if ( get_word(cmd.ea-i*2) != 0 ) return 1;
    return 0; // too many nops in a row
  }
  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  if ( !decode_insn(ea) ) return 0;
  switch ( cmd.itype )
  {
    case H8_nop:
      break;
    case H8_mov:
    case H8_or:
      if ( cmd.Op1.type == cmd.Op2.type && cmd.Op1.reg == cmd.Op2.reg ) break;
    default:
      return 0;
  }
  return cmd.size;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  int code = 0;
  if ( pfn->frame == BADNODE )
  {
    size_t regs = 0;
    ea_t ea = pfn->startEA;
    bool bpused = false;
    while ( ea < pfn->endEA )                 // skip all pushregs
    {                                         // (must test that ea is lower
                                              // than pfn->endEA)
      decode_insn(ea);
      ea += cmd.size;
      switch ( cmd.itype )
      {
        case H8_nop:
          continue;
        case H8_push:
          regs += get_dtyp_size(cmd.Op1.dtyp);
          continue;
        case H8_stm:
          if ( !issp(cmd.Op2.reg) ) break;
          regs += cmd.Op1.nregs * get_dtyp_size(cmd.Op1.dtyp);
          continue;
        case H8_mov:  // mov.l er6, sp
          if ( cmd.Op1.type == o_reg && issp(cmd.Op1.reg)
            && cmd.Op2.type == o_reg && isbp(cmd.Op2.reg) )
              bpused = true;
          break;
        default:
          break;
      }
      break;
    }
    uint32 frsize  = 0;
    uint32 argsize = 0;
    if ( frsize != 0 || argsize != 0 || regs != 0 || bpused )
    {
      setflag((uint32 &)pfn->flags,FUNC_FRAME,bpused);
      return add_frame(pfn, frsize, (ushort)regs, argsize);
    }
  }
  return code;
}

//----------------------------------------------------------------------
int idaapi h8_get_frame_retsize(func_t *)
{
  return advanced() ? 4 : 2;
}

//----------------------------------------------------------------------
//      These are the recognized jump table sizing patterns
//0100                cmp.b   #7, r0l
//0102                bls     loc_108:8
//0104                bra     def_200:8
//0106      loc_108:  ; jump table lookup
//0200      def_200:  ; default jump target
//      Or
//0100                cmp.b   #7, r0l
//0102                bls     loc_108:8
//0104                jmp     def_2000:16
//0108      loc_108:  ; jump table lookup
//2000      def_2000: ; default jump target
//      Or
//0100                mov.w   #7, r3
//0104                cmp.w   r3, r0
//0106                bls     loc_10C:8
//0108                bra     def_200:8
//010A      loc_10C:  ; jump table lookup
//0200      def_200:  ; default jump target
//      Or
//0100                mov.w   #7, r3
//0104                cmp.w   r3, r0
//0106                bls     loc_10C:8
//0108                jmp     def_2000:16
//010C      loc_10C:  ; jump table lookup
//2000      def_2000: ; default jump target
//      Or
//0100                cmp.b   #7, r0l
//0102                bhi     def_200:8
//0104                ; jump table lookup
//0200      def_200:  ; default jump target
//      Or
//0100                mov.w   #7, r3
//0104                cmp.w   r3, r0
//0106                bhi     def_200:8
//0108                ; jump table lookup
//0200      def_200:  ; default jump target
//----------------------------------------------------------------------
static bool find_table_size(ea_t *defea, int *size, int rlx, ea_t code_ip)
{
  *defea = BADADDR;
  *size  = INT_MAX;
  if ( decode_prev_insn(cmd.ea) == BADADDR ) return true;

  if ( cmd.itype == H8_bhi )                    // bhi default
  {
    *defea = cmd.Op1.addr;
  }
  else
  {
    if ( cmd.itype != H8_jmp                    // jmp default
      && cmd.itype != H8_bra ) return true;     // bra default
    *defea = cmd.Op1.addr;

    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype != H8_bls                    // bls code_ip
      || cmd.Op1.addr != code_ip ) return true;
  }

  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype    != H8_cmp                   // cmp.b #size, rlx
    || cmd.Op2.type != o_reg ) return true;
  if ( cmd.Op1.type == o_imm )
  {
    if ( (cmd.auxpref &  aux_byte) == 0
      || cmd.Op2.reg  != rlx ) return true;
  }
  else
  {
    if ( cmd.Op1.type != o_reg                  // cmp.w RX, rx
      || cmd.Op2.reg  != (rlx - 24) ) return true;
    int rx = cmd.Op1.reg;
    if ( decode_prev_insn(cmd.ea) == BADADDR
      || cmd.itype    != H8_mov                 // mov.w #size, RX
      || cmd.Op2.type != o_reg
      || cmd.Op2.reg  != rx
      || cmd.Op1.type != o_imm ) return true;
  }

  *size = int(cmd.Op1.value + 1);
  return true;
}

//----------------------------------------------------------------------
//      This is jump table pattern #1
//0100                sub.b   r0h, r0h
//0102                mov.b   @(jpt_10a:16,r0), r0l
//0106                add.b   #loc_10C & 0xFF, r0l
//0108                addx    #loc_10C >> 8, r0h
//010A                jmp     @r0
//010C      loc_10C:  ; base address of jump table
//      Or
//0100                mov.b   @(jpt_10a:16,r0), r0l
//0104                sub.b   r0h, r0h
//0106                add.b   #loc_10C & 0xFF, r0l
//0108                addx    #loc_10C >> 8, r0h
//010A                jmp     @r0
//010C      loc_10C:  ; base address of jump table
//----------------------------------------------------------------------
static bool is_jump_pattern1(ea_t *base, ea_t *table, ea_t *defea, int *size, int *elsize)
{
  int reg = cmd.Op1.phrase;
  int rh  = reg + 16;
  int rl  = rh  + 8;
  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_addx                     // addx #baseh, rh
    || cmd.Op1.type != o_imm
    || cmd.Op2.reg  != rh     ) return false;
  int baseh = (int)cmd.Op1.value;       // msb of base
  ea_t eah = cmd.ea;

  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_add                      // add.b #basel, rl
    || (cmd.auxpref & aux_byte) == 0
    || cmd.Op1.type != o_imm
    || cmd.Op2.reg  != rl     ) return false;
  int basel = (int)cmd.Op1.value;       // lsb of base
  ea_t eal = cmd.ea;

  int rx, rhx, rlx;
  ea_t obase;
  if ( decode_prev_insn(cmd.ea) == BADADDR )
    return false;
  else
  {
    if ( cmd.itype == H8_mov )                     // mov.b @(table:16,rx), rl
    {
      if ( (cmd.auxpref & aux_byte) == 0
        || cmd.Op1.type != o_displ
        || cmd.Op2.reg  != rl     ) return false;

      *table  = cmd.Op1.addr;
      rx  = cmd.Op1.reg;
      rhx = rx + 16;
      rlx = rhx + 8;
      obase = toEA(cmd.cs, 0);
      set_offset(cmd.ea, 0, obase);

      if ( decode_prev_insn(cmd.ea) == BADADDR
        || (cmd.itype != H8_sub && cmd.itype != H8_xor) // sub.b rhx, rhx
        || (cmd.auxpref & aux_byte) == 0
        || cmd.Op1.type != o_reg
        || cmd.Op2.type != o_reg
        || cmd.Op1.reg  != rhx
        || cmd.Op2.reg  != rhx    ) return false;
    }
    else if ( cmd.itype == H8_sub || cmd.itype == H8_xor )  // sub.b rhx, rhx
    {
      if ( (cmd.auxpref & aux_byte) == 0
        || cmd.Op1.type != o_reg
        || cmd.Op2.type != o_reg
        || cmd.Op1.reg  != cmd.Op2.reg ) return false;

      rhx = cmd.Op1.reg;
      rlx = rhx + 8;
      rx = rhx - 16;

      if ( decode_prev_insn(cmd.ea) == BADADDR
        || (cmd.itype != H8_mov)                     // mov.b @(table:16,rx), rl
        || (cmd.auxpref & aux_byte) == 0
        || cmd.Op1.type != o_displ
        || cmd.Op2.reg  != rl
        || cmd.Op1.reg != rx ) return false;

      *table  = cmd.Op1.addr;
      obase = toEA(cmd.cs, 0);
      set_offset(cmd.ea, 0, obase);
    }
    else
      return false;
  }

  *base  = (baseh<<8) | basel;
  ea_t bea = toEA(cmd.cs, *base);
  op_offset(eah, 0, REF_HIGH8, bea, obase);
  op_offset(eal, 0, REF_LOW8,  bea, obase);

  // the jump table is found, try to determine its size
  *elsize = 1;
  return find_table_size(defea, size, rlx, cmd.ip);
}

//----------------------------------------------------------------------
//      This is jump table pattern #2
//      (*1* may be omitted...IE, this logic is located above jump table sizing instructions)
//0100    *1*          sub.b   r0h, r0h
//0102                 add.w   r0, r0
//0104                 mov.w   @(jpt_108:16,r0), r0
//0108                 jmp     @r0
//----------------------------------------------------------------------
static bool is_jump_pattern2(ea_t *base, ea_t *table, ea_t *defea, int *size, int *elsize)
{
  int reg = cmd.Op1.phrase;
  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_mov                      // mov.w   @(table:16,r0), r0
    || (cmd.auxpref & aux_word) == 0
    || cmd.Op1.type != o_displ
    || cmd.Op2.reg  != reg    ) return false;
  *table  = cmd.Op1.addr;
  int rx  = cmd.Op1.reg;
  *base   = 0;
  ea_t bea = toEA(cmd.cs, 0);
  set_offset(cmd.ea, 0, bea);

  if ( decode_prev_insn(cmd.ea) == BADADDR
    || cmd.itype != H8_add                      // add.w r0, r0
    || (cmd.auxpref & aux_word) == 0
    || cmd.Op1.type != o_reg
    || cmd.Op1.reg  != rx
    || cmd.Op2.reg  != rx     ) return false;
  int rhx = rx + 16;
  int rlx = rhx + 8;

  ea_t oldea = cmd.ea;
  ea_t oldip = cmd.ip;
  if ( decode_prev_insn(cmd.ea) == BADADDR
    || (cmd.itype != H8_sub && cmd.itype != H8_xor) // sub.b rhx, rhx
    || (cmd.auxpref & aux_byte) == 0
    || cmd.Op1.type != o_reg
    || cmd.Op2.type != o_reg
    || cmd.Op1.reg  != rhx
    || cmd.Op2.reg  != rhx    ) // return false;
  {
    cmd.ea = oldea; // forgive this...
    cmd.ip = oldip;
  }

  // the jump table is found, try to determine its size
  *elsize = 2;
  return find_table_size(defea, size, rlx, cmd.ip);
}

//----------------------------------------------------------------------
typedef bool is_pattern_t(ea_t *base, ea_t *table, ea_t *defea, int *size, int *elsize);

static is_pattern_t * const patterns[] = { is_jump_pattern1, is_jump_pattern2 };

static bool check_for_table_jump(void)
{
  ea_t base = BADADDR, table = BADADDR, defea = BADADDR;
  int size = 0, elsize = 0;

  int i;
  bool ok = false;
  insn_t saved = cmd;
  for ( i=0; !ok && i < qnumber(patterns); i++ )
  {
    ok = patterns[i](&base, &table, &defea, &size, &elsize);
    cmd = saved;
  }
  if ( !ok ) return false;

  if ( table != BADADDR ) table = toEA(cmd.cs, table);
  if ( base  != BADADDR ) base  = toEA(cmd.cs, base);
  if ( defea != BADADDR ) defea = toEA(cmd.cs, defea);

  // check the table contents
  int oldsize = size;
  segment_t *s = getseg(table);
  if ( s == NULL ) return false;
  int maxsize = int(s->endEA - table);
  if ( size > maxsize ) size = maxsize;

  for ( i=0; i < size; i++ )
  {
    ea_t ea = table+i*elsize;
    flags_t F = getFlags(ea);
    if ( !hasValue(F)
      || (i && (has_any_name(F) || hasRef(F))) ) break;
    int el = elsize == 1 ? get_byte(ea) : get_word(ea);
    flags_t F2 = get_flags_novalue(base+el);
    if ( isTail(F2)
      || isData(F2)
      || (!isCode(F2) && !decode_insn(base+el)) ) break;
  }
  cmd = saved;
  size = i;
  if ( size != oldsize )
    msg("Warning: jpt_%04a calculated size of %d forced to %d!\n",
                                      cmd.ip, oldsize, size);

  // create the table
  if ( size == 0 ) return false;
  for ( i=0; i < size; i++ )
  {
    ea_t ea = table + i*elsize;
    (elsize == 1 ? doByte : doWord)(ea, elsize);
    op_offset(ea, 0, elsize == 1 ? REF_OFF8 : REF_OFF16, BADADDR, base);
    ua_add_cref(0, base + (elsize==1?get_byte(ea):get_word(ea)), fl_JN);
  }
  char buf[MAXSTR];
  qsnprintf(buf, sizeof(buf), "def_%a", cmd.ip);
//  set_name(defea, buf, SN_NOWARN|SN_LOCAL);         // temporary kernel bug workaround
  set_name(defea, buf, SN_NOWARN);
  qsnprintf(buf, sizeof(buf), "jpt_%a", cmd.ip);
  set_name(table, buf, SN_NOWARN);
  return true;
}

//----------------------------------------------------------------------
static bool check_for_generic_indirect_jump(void)
{
  // Add code to handle the indirect jumps here
  // Ilfak, I don't have any of these... :)
  return false;
}

//----------------------------------------------------------------------
static bool check_for_generic_indirect_call(void)
{
  // Add code to handle the indirect calls here
  // However, I do have plenty of these... :(
  return false;
}

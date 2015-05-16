/*
        This module has been created by Petr Novak
 */

#include "xa.hpp"
#include <frame.hpp>
#include <segment.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <struct.hpp>


static bool flow;               // does the current instruction pass
                                // execution to the next instruction?

static void create_ext_ram_seg(ea_t &v)
{
  if ( (v & 0xFF0000L) >= 0x80000L ) // these are references to code
  {
    v = v & 0x7FFFFL;
    return;
  }

  if ( v && getseg(v) == NULL )
  {
    ea_t start = v & 0xFFFF0000L;
    segment_t *sreg;

    add_segm(start>>4, start, start+0x10000L, NULL, "DATA");
    sreg = getseg(start);
    set_segm_name(sreg, "RAM%02x", int((start&0xFF0000L)>>16));
  }
}

static int check_insn(int prev, int itype, optype_t op1type,
ea_t op1value, optype_t op2type, ea_t op2value)
{
  if ( prev && decode_prev_insn(cmd.ea) == BADADDR )
    return 0;

  switch ( itype )
  {
    case XA_mov:
      if ( cmd.itype != XA_mov && cmd.itype != XA_movs )
        return 0;
      break;
    case XA_add:
    case XA_sub:
      if ( cmd.itype != itype && cmd.itype != XA_adds )
        return 0;
      break;
    default:
      if ( cmd.itype != itype )
        return 0;
      break;
  }

  if ( op1type != o_last )
  {
    if ( cmd.Op1.type != op1type )
      return 0;

    if ( op1value != BADADDR )
    {
      switch ( op1type )
      {
        case o_imm:
          if ( cmd.Op1.value != op1value )
            return 0;
          break;
        case o_reg:
        case o_phrase:
          if ( cmd.Op1.reg != op1value )
            return 0;
          break;
        default:
          if ( cmd.Op1.addr != op1value )
            return 0;
          break;
      }
    }
  }

  if ( op2type != o_last )
  {
    if ( cmd.Op2.type != op2type )
      return 0;

    if ( op2value != BADADDR )
    {
      switch ( op2type )
      {
        case o_imm:
          if ( cmd.Op2.value != op2value )
            return 0;
          break;
        case o_reg:
        case o_phrase:
          if ( cmd.Op2.reg != op2value )
            return 0;
          break;
        default:
          if ( cmd.Op2.addr != op2value )
            return 0;
          break;
      }
    }
  }

  return 1;
}

//------------------------------------------------------------------------
// Handle an operand with an immediate value:
//      - mark it with FF_IMMD flag
//      - for bit logical instructions specify the operand type as a number
//        because such an operand is likely a plain number rather than
//        an offset or of another type.

static void doImmdValue(op_t &x)
{
  doImmd(cmd.ea);
  switch ( cmd.itype )
  {
    case XA_and:
    case XA_or:
    case XA_xor:
      op_num(cmd.ea,x.n);
      break;
  }
}

//----------------------------------------------------------------------
static void attach_bit_comment(int addr, int bit)
{
  predefined_t *predef = GetPredefined(ibits, addr, bit);
  if ( predef != NULL && get_cmt(cmd.ea, false, NULL, 0) <= 0 )
    set_cmt(cmd.ea,predef->cmt,0);
}

//----------------------------------------------------------------------
static void attach_name_comment(op_t &x, ea_t v)
{
  char buf[MAXSTR];
  if ( get_name_expr(cmd.ea, x.n, v, v&0xFFFF, buf, sizeof(buf)) > 0 )
    set_cmt(cmd.ea, buf, false);
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
    case o_reg:              // no special hanlding for these types
      break;

    case o_imm:                         // an immediate number as an operand
      if ( !loading ) goto BAD_LOGIC;   // this can't happen!
      doImmdValue(x);                   // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, dr_O, 0);

      break;

    case o_displ:
      if ( x.phrase != fRi )
        doImmdValue(x);                   // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( isOff(uFlag, x.n) )
        ua_add_off_drefs2(x, loading?dr_R:dr_W, OOF_SIGNED|OOF_ADDR);

      // Handle stack variables in a form [R7] and [R7+xx]
      // There is no frame pointer and all references are SP (R7) based
      if ( may_create_stkvars()
        && !isDefArg(uFlag,x.n)
        && x.indreg == rR7 &&
        !(x.n == 1 && check_insn(0, XA_lea, o_reg, rR7, o_last, BADADDR)))
      {
        func_t *pfn = get_func(cmd.ea);
        if ( pfn != NULL )
        {
          insn_t saved = cmd;
          int n = x.n;
          op_t fake = x;

          if ( decode_insn(cmd.ea+cmd.size) )
          {
            if ( fake.dtyp == dt_word ) {
              if (saved.itype == cmd.itype &&
                  saved.Operands[n].type == cmd.Operands[n].type &&
                  saved.Operands[n].phrase == cmd.Operands[n].phrase &&
                  saved.Operands[n].indreg == cmd.Operands[n].indreg &&
                  saved.Operands[n].addr + 2 == cmd.Operands[n].addr &&
                  saved.Operands[1-n].type == cmd.Operands[1-n].type &&
                  saved.Operands[1-n].reg + 1 == cmd.Operands[1-n].reg)
              {
                fake.dtyp = dt_dword;
              }
            } else { // dt_byte
              if (saved.itype == XA_mov && cmd.itype == XA_mov && n == 1 &&
                  cmd.Op2.type == o_reg &&
                  saved.Op1.reg == cmd.Op2.reg &&
                  cmd.Op1.type == o_mem && cmd.Op1.addr == ES &&
                  decode_insn(cmd.ea+cmd.size) &&
                  cmd.itype == XA_mov &&
                  cmd.Op1.type == o_reg && cmd.Op1.dtyp == dt_word &&
                  cmd.Op2.type == o_displ &&
                  cmd.Op2.addr + 2 == saved.Op2.addr)
              {
                fake.dtyp  = dt_dword;
                fake.addr -= 2;
              }
            }
          }

          cmd = saved;

          if ( ua_stkvar2(fake, fake.addr, STKVAR_VALID_SIZE) )
            op_stkvar(cmd.ea, x.n);
          else
          {
            if ( fake.dtyp == dt_dword )
            {
              fake.dtyp = dt_word;
              if ( ua_stkvar2(fake, fake.addr, STKVAR_VALID_SIZE) )
              {
                fake.dtyp = dt_dword;
                ua_stkvar2(fake, fake.addr, STKVAR_VALID_SIZE);
                op_stkvar(cmd.ea, x.n);
              }
            }
          }
        }
      }
      // fallthru

    case o_phrase:
      if ( x.indreg != rR7 && (x.phrase == fRi || x.phrase == fRip) ) // catch ES:offset references
      {
        int reg = x.indreg - rR0;
        insn_t saved = cmd;

        if ( check_insn(1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR) )
        {
          ea_t v = EXTRAMBASE + cmd.Op2.value;
          int dtyp;

          create_ext_ram_seg(v);
          if ( !isDefArg(uFlag, 1) )
            op_offset(cmd.ea, 1, REF_OFF16, v, v & 0xFFFF0000);

          cmd = saved;
          dtyp = x.dtyp;
          if ( dtyp == dt_word )
          {
            int n = x.n;
            if ( decode_insn(cmd.ea+cmd.size ) &&
              cmd.Operands[n].type == o_displ &&
              cmd.Operands[n].indreg == reg+rR0)
            {
              dtyp = dt_dword;
            }
            cmd = saved;
          }
          ua_dodata2(x.offb, v, dtyp);
          if ( !loading )
            doVar(v);     // write access
          ua_add_dref(x.offb, v, loading ? dr_R : dr_W);

          attach_name_comment(x, v);
        }
        else if ( check_insn(0, XA_setb, o_bit, 0x218+reg, o_last, BADADDR) )
        {
          if ( check_insn(1, XA_mov, o_mem, ES, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + (cmd.Op2.value << 16);
            if ( check_insn(1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR ) ||
                check_insn(0, XA_lea, o_reg, reg+rR0, o_displ, BADADDR))
            {
              int dtyp;
              v += (cmd.Op2.type == o_imm)?cmd.Op2.value:cmd.Op2.addr;
              create_ext_ram_seg(v);
              if ( !isDefArg(uFlag, 1) )
                op_offset(cmd.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
              cmd = saved;

              dtyp = x.dtyp;
              if ( dtyp == dt_word )
              {
                int n = x.n;
                if ( decode_insn(cmd.ea+cmd.size ) &&
                  cmd.Operands[n].type == o_displ &&
                  cmd.Operands[n].indreg == reg+rR0)
                {
                  dtyp = dt_dword;
                }
                cmd = saved;
              }

              ua_dodata2(x.offb, v, dtyp);
              if ( !loading )
                doVar(v);     // write access
              ua_add_dref(x.offb, v, loading ? dr_R : dr_W);

              attach_name_comment(x, v);
            }
          } else if ( check_insn(0, XA_mov, o_mem, ES, o_reg, 2*reg+rR1L ) ||
                     check_insn(0, XA_mov, o_mem, CS, o_reg, 2*reg+rR1L))
          { // MOV.B ES/CS,R1L
            int prev = 0;
            ea_t v = EXTRAMBASE;
            int ok = 0;
            if ( check_insn(1, XA_jb, o_bit, BADADDR, o_last, BADADDR ) &&
              (cmd.Op1.addr & 0xf) == 0xf && (cmd.Op1.addr & 0xFFF0) == ((reg+1)<<4))
            {
              prev = 1;
            }

            if ( check_insn(prev, XA_add, o_reg, reg+rR0, o_reg, BADADDR) )
              prev = 1;
            else
              prev = 0;

            if ( check_insn(prev, XA_mov, o_reg, 2*reg+rR1H, o_imm, 0) )
            {
              if ( check_insn(1, XA_mov, o_reg, 2*reg+rR1L, o_mem, DS) )
              {
                ok = 1;
              }
            } else if ( check_insn(0, XA_mov, o_reg, reg+rR1, o_imm, BADADDR ) ||
                       check_insn(0, XA_addc, o_reg, reg+rR1, o_imm, BADADDR))
            {
              v += (cmd.Op2.value << 16);
              ok = 1;
            }
            if ( ok && (check_insn(1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR ) ||
                      check_insn(0, XA_add, o_reg, reg+rR0, o_imm, BADADDR)))
            {
              int dtyp;
              v += cmd.Op2.value;
              create_ext_ram_seg(v);
              if ( !isDefArg(uFlag, 1) )
                op_offset(cmd.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
              cmd = saved;

              dtyp = x.dtyp;
              if ( dtyp == dt_word )
              {
                int n = x.n;
                if ( decode_insn(cmd.ea+cmd.size ) &&
                  cmd.Operands[n].type == o_displ &&
                  cmd.Operands[n].indreg == reg+rR0)
                {
                  dtyp = dt_dword;
                }
                cmd = saved;
              }

              ua_dodata2(x.offb, v, dtyp);
              if ( !loading )
                doVar(v);
              ua_add_dref(x.offb, v, loading ? dr_R : dr_W);
              attach_name_comment(x, v);
            }
          } else if ( check_insn(0, XA_mov, o_reg, reg+rR0, o_imm, BADADDR) )
          { // mov.w Rx,#xxxx
            ea_t v = cmd.Op2.value;
            if ( check_insn(1, XA_mov, o_mem, ES, o_reg, BADADDR) && cmd.Op1.dtyp == dt_byte )
            {
              int reg2 = cmd.Op2.reg;
              if ( check_insn(1, XA_mov, o_reg, reg2, o_imm, BADADDR) )
              {
                int dtyp;
                v += EXTRAMBASE + (cmd.Op2.value << 16);
                create_ext_ram_seg(v);
                cmd = saved;

                dtyp = x.dtyp;
                if ( dtyp == dt_word )
                {
                  int n = x.n;
                  if ( decode_insn(cmd.ea+cmd.size ) &&
                    cmd.Operands[n].type == o_displ &&
                    cmd.Operands[n].indreg == reg+rR0)
                  {
                    dtyp = dt_dword;
                  }
                  cmd = saved;
                }

                ua_dodata2(x.offb, v, dtyp);
                if ( !loading )
                  doVar(v);     // write access
                ua_add_dref(x.offb, v, loading ? dr_R : dr_W);
                attach_name_comment(x, v);
              }
            }
          }
        } else if ( // MOV.B ES,RxL
          check_insn(0, XA_mov, o_mem, ES, o_reg, BADADDR) && cmd.Op2.dtyp == dt_byte)
        {
          int reg2 = (cmd.Op2.reg - rR0L) >> 1;
          if ( check_insn(1, XA_jb, o_bit, BADADDR, o_last, BADADDR ) &&
            (cmd.Op1.addr & 0xf) == 0xf && (cmd.Op1.addr & 0xFFF0) == (reg2<<4) &&
            check_insn(1, XA_setb, o_bit, 0x218+reg, o_last, BADADDR))
          {
            int prev = 0;
            if ( check_insn(1, XA_add, o_reg, reg+rR0, o_last, BADADDR) )
              prev = 1;
            if ( check_insn(prev, XA_mov, o_reg, reg2+rR0, o_imm, BADADDR ) ||
                check_insn(0, XA_addc, o_reg, reg2+rR0, o_imm, BADADDR))
            {
              ea_t v = (cmd.Op2.value & 0x8000) ? 0 : EXTRAMBASE;
              v += (cmd.Op2.value & 0xff) << 16;
              if ( check_insn(1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR ) ||
                  check_insn(0, XA_add, o_reg, reg+rR0, o_imm, BADADDR))
              {
                int dtyp;
                v += cmd.Op2.value;
                create_ext_ram_seg(v);
                op_offset(cmd.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
                cmd = saved;

                dtyp = x.dtyp;
                if ( dtyp == dt_word )
                {
                  int n = x.n;
                  if ( decode_insn(cmd.ea+cmd.size ) &&
                    cmd.Operands[n].type == o_displ &&
                    cmd.Operands[n].indreg == reg+rR0)
                  {
                    dtyp = dt_dword;
                  }
                  cmd = saved;
                }

                ua_dodata2(x.offb, v, dtyp);
                if ( !loading )
                  doVar(v);     // write access
                ua_add_dref(x.offb, v, loading ? dr_R : dr_W);
                attach_name_comment(x, v);
              }
            }
          }
        }
        cmd = saved;
      }
      uFlag = get_flags_novalue(cmd.ea);
      break;

    case o_bit:                         // 8051 specific operand types - bits
    case o_bitnot:
      {
        int addr = int(x.addr >> 3);
        int bit = x.addr & 7;
        ea_t dea;

        if ( addr & 0x40 ) // SFR
        {
          addr += 0x3c0;
        } else if ( (x.addr & 0x20) == 0 ) // Register file
          break;

        attach_bit_comment(addr, bit);  // attach a comment if necessary
        dea = map_addr(addr);
        ua_dodata2(x.offb, dea, dt_byte);
        if ( !loading )
          doVar(dea);     // write access
        ua_add_dref(x.offb, dea, loading ? dr_R : dr_W);
      }
      break;

    case o_mem:                         // an ordinary memory data reference
      {
        ea_t dea = map_addr(x.addr);
        ua_dodata2(x.offb, dea, x.dtyp);
        if ( !loading )
          doVar(dea);     // write access
        ua_add_dref(x.offb, dea, loading ? dr_R : dr_W);
      }
      break;

    case o_near:                        // a code reference
      {
        ea_t ea = toEA(cmd.cs, x.addr);
        int iscall = InstrIsSet(cmd.itype, CF_CALL);
        ua_add_cref(x.offb, ea, iscall ? fl_CN : fl_JN);

        if ( flow && iscall )
        {
          if ( !func_does_return(ea) )
            flow = false;
        }
      }
      break;

    case o_far:                        // a code reference
      {
        ea_t ea = x.addr + (x.specval << 16);
        int iscall = InstrIsSet(cmd.itype, CF_CALL);
        ua_add_cref(x.offb, ea, iscall ? fl_CF : fl_JF);
        if ( flow && iscall )
        {
          if ( !func_does_return(ea) )
            flow = false;
        }
      }
      break;

    default:
BAD_LOGIC:
      warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n, x.type);
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

  int report = 0;

  // you may emulate selected instructions with a greater care:
  switch ( cmd.itype )
  {
    case XA_mov:
    case XA_movs:
// mov R7,#xxx
      if ( cmd.Op1.type == o_reg && cmd.Op1.reg == rR7)
      {
        if ( cmd.Op2.type == o_imm && !isDefArg(uFlag,1) )
          op_offset(cmd.ea, 1, REF_OFF16, INTMEMBASE + cmd.Op2.value, INTMEMBASE);
      }

// mov DS,#xx
      if ( check_insn(0, XA_mov, o_mem, DS, o_imm, BADADDR) )
      {
        ea_t v = EXTRAMBASE + (cmd.Op2.value << 16);
        create_ext_ram_seg(v);
      }

// mov ES,#xx
      if ( check_insn(0, XA_mov, o_mem, ES, o_last, BADADDR) ) // MOV ES,xx
      {
        insn_t saved = cmd;
        ea_t v = 0;

        if ( cmd.Op2.type == o_imm )
        {
          v = EXTRAMBASE + (cmd.Op2.value << 16);
        } else if ( cmd.Op2.type == o_reg && cmd.Op1.dtyp == dt_byte )
        {
          int reg = cmd.Op2.reg;
          if ( check_insn(1, XA_mov, o_reg, reg, o_imm, BADADDR) )
          {
            v = EXTRAMBASE + (cmd.Op2.value << 16);
          }
        }

        create_ext_ram_seg(v);

        if ( cmd.Op2.type == o_imm && check_insn(1, XA_mov, o_reg, BADADDR, o_imm, BADADDR) && cmd.Op1.dtyp == dt_word )
        {
          v += cmd.Op2.value;
          if ( !isDefArg(uFlag, 1) )
            op_offset(cmd.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
        }
        cmd = saved;
        uFlag = get_flags_novalue(cmd.ea);
      }

// mov CS,#xx
      if ( check_insn(0, XA_mov, o_mem, CS, o_imm, BADADDR) ) // MOV CS,#xx
      {
        insn_t saved = cmd;
        ea_t v = (cmd.Op2.value << 16);
        create_ext_ram_seg(v);

        if ( check_insn(1, XA_mov, o_reg, BADADDR, o_imm, BADADDR) && cmd.Op1.dtyp == dt_word )
        {
          v += cmd.Op2.value;
          if ( !isDefArg(uFlag, 1) )
            op_offset(cmd.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
        }
        cmd = saved;
        uFlag = get_flags_novalue(cmd.ea);
      }

// mov Rx,#xxxx
      if ( check_insn(0, XA_mov, o_reg, BADADDR, o_imm, BADADDR) && cmd.Op1.dtyp == dt_word )
      {
        insn_t saved =  cmd;

        if ( check_insn(1, XA_mov, o_mem, ES, o_reg, BADADDR) && cmd.Op1.dtyp == dt_byte )
        {
          int regL = cmd.Op2.reg - rR0L;
          if ( check_insn(1, XA_mov, o_reg, regL, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + (cmd.Op2.value << 16) + saved.Op2.value;
            create_ext_ram_seg(v);
            cmd = saved; uFlag = get_flags_novalue(cmd.ea);
            if ( !isDefArg(uFlag,1) )
              op_offset(saved.ea, 1, REF_OFF16, v, v & 0xFFFF0000L);
          }
        }
        cmd = saved;
        uFlag = get_flags_novalue(cmd.ea);
      }

// mov.b R1H, #0
      if ( check_insn(0, XA_mov, o_reg, BADADDR, o_imm, 0) )
      {
        int reg = (cmd.Op1.reg - rR1H) >> 1;
        insn_t saved = cmd;
        if ( check_insn(1, XA_mov, o_reg, 2*reg+rR1L, o_mem, DS) ) // mov rx,DS
        {
          if ( check_insn(1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + cmd.Op2.value;
            uFlag = get_flags_novalue(cmd.ea);
            if ( !isDefArg(uFlag,1) )
              op_offset(cmd.ea, 1, REF_OFF16, v, EXTRAMBASE);
          }
        }
        cmd = saved;
        uFlag = get_flags_novalue(cmd.ea);
      }

      break;

    case XA_push:
    case XA_pop:
      if (cmd.Op1.type == o_phrase &&
        (cmd.Op1.phrase == fRlistL || cmd.Op1.phrase == fRlistH))
      {
        func_t *pfn = get_func(cmd.ea);
        int bits = 0, firstreg = 0;

        for (int bit = 7; bit >= 0; bit--)
        {
          if ( cmd.Op1.indreg & (1<<bit) )
          {
            bits++;
            firstreg = bit;
          }
        }
        if ( bits && may_trace_sp() && pfn && !get_sp_delta(pfn, cmd.ea) )
          add_stkpnt((cmd.itype==XA_push)?-2*bits:2*bits);

        if (cmd.itype == XA_push &&
            bits == 2 && (cmd.Op1.indreg & (1<<(firstreg+1)))) // dword push
        {
          insn_t save = cmd;
          if ( check_insn(1, XA_mov, o_reg, firstreg+rR1, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + (cmd.Op2.value << 16);
            if ( check_insn(1, XA_mov, o_reg, firstreg+rR0, o_imm, BADADDR) )
            {
              v += cmd.Op2.value;
              create_ext_ram_seg(v);
              if ( !isDefArg(uFlag, 1) )
                op_offset(cmd.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
            }
          }
          cmd = save; uFlag = get_flags_novalue(cmd.ea);
        }
      } else if ( cmd.Op1.type == o_mem ) {
        func_t *pfn = get_func(cmd.ea);
        if ( may_trace_sp() && pfn && !get_sp_delta(pfn, cmd.ea) )
          add_stkpnt((cmd.itype==XA_push)?-2:2);
      } else {
        warning("emu: strange push/pop instruction operand at %a", cmd.ea);
      }
      break;

   case XA_add:
   case XA_sub:
   case XA_adds:
     if ( !may_trace_sp() )
       break;
     if ( cmd.Op1.type == o_reg && cmd.Op1.reg == rR7 )
     {
       if ( cmd.Op2.type == o_imm )
       {
         func_t *pfn = get_func(cmd.ea);

         sval_t offset = (cmd.Op2.value < 0x8000L || cmd.Op2.value > 0x80000000L) ? cmd.Op2.value : cmd.Op2.value-0x10000L;

         if ( may_trace_sp() && pfn && !get_sp_delta(pfn, cmd.ea) )
           add_stkpnt((cmd.itype==XA_sub)?-offset:offset);
       } else {
         warning("emu: add/adds/sub with R7 and non-imm operand at %a", cmd.ea);
       }
     }
     break;

   case XA_lea:
     if ( !may_trace_sp() )
       break;
     if ( cmd.Op1.type == o_reg && cmd.Op1.reg == rR7 )
     {
       if (cmd.Op2.type == o_displ &&
         cmd.Op2.indreg == rR7)
       {
         func_t *pfn = get_func(cmd.ea);
         if ( pfn && !get_sp_delta(pfn, cmd.ea) )
           add_stkpnt(cmd.Op2.addr);
       } else {
         warning("emu: lea with R7 and unknown 2nd operand at %a", cmd.ea);
       }
    }
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

  if ( report) warning("emu: leaving" );
  return 1;    // actually the return value is unimportant, but let's it be so
}

// Special functions for Hisoft XA C compiler

bool idaapi xa_create_func(func_t *pfn)
{
   ea_t prologue = pfn->startEA;
   bool prologue_at_end = false;
   uval_t frsize = 0;
   ushort regs = 0;

   if ( decode_insn(prologue) )
   {
     if ( cmd.itype == XA_jmp || cmd.itype == XA_br )
     {
       prologue = toEA(cmd.cs, cmd.Op1.addr);
       prologue_at_end = true;
     }
     bool more;
     do
     {
       more = false;
       if ( decode_insn(prologue) == 0 )
         break;
       if (cmd.itype == XA_push &&
         cmd.Op1.type == o_phrase &&
         (cmd.Op1.phrase == fRlistL || cmd.Op1.phrase == fRlistH))
       {
         for (int bit = 0; bit < 8; bit++)
         {
           if ( cmd.Op1.indreg & (1<<bit) )
             regs += 2;
         }
         more = true;
       }
       if (cmd.itype == XA_lea &&
         cmd.Op1.type == o_reg && cmd.Op1.reg == rR7 &&
         cmd.Op2.type == o_displ &&
         (cmd.Op2.phrase == fRid8 || cmd.Op2.phrase == fRid16) &&
         cmd.Op2.indreg == rR7)
       {
         sval_t offset = cmd.Op2.addr;
         if ( offset >= 0 )
         {
           warning("%a: positive offset %a", cmd.ea, offset);
           offset -= 0x10000L;
         }
         frsize -= offset;
         more = true;
       }
       if (cmd.itype == XA_sub &&
         cmd.Op1.type == o_reg && cmd.Op1.reg == rR7 &&
         cmd.Op2.type == o_imm)
       {
         frsize += cmd.Op2.value;
         more = true;
       }
       if (cmd.itype == XA_adds &&
         cmd.Op1.type == o_reg && cmd.Op1.reg == rR7 &&
         cmd.Op2.type == o_imm)
       {
         frsize -= cmd.Op2.value;
         more = true;
       }
       prologue += cmd.size;
     } while ( more );
   }
   add_frame(pfn, frsize, regs, 0);
   if ( prologue_at_end )
   {
     decode_insn(pfn->startEA);
     add_stkpnt(-frsize-regs);
   }

   return 1;
}

bool idaapi xa_is_switch ( switch_info_ex_t *si )
{
  int value = 0;
  int prev;

  if ( cmd.Op1.type == o_phrase && cmd.Op1.phrase == fRi )
  {
    insn_t saved = cmd;
    int jumpreg, datareg;

    jumpreg = cmd.Op1.indreg;
    if ( check_insn(1, XA_movc, o_reg, jumpreg, o_phrase, fRip ) &&
      cmd.Op2.indreg == jumpreg)
    {
      if ( check_insn(1, XA_add, o_reg, jumpreg, o_imm, BADADDR) )
      {
        si->jumps = (cmd.ea & 0xFFFF0000) + cmd.Op2.value;
        op_offset(cmd.ea, 1, REF_OFF16, si->jumps, cmd.ea & 0xFFFF0000);
        if ( check_insn(1, XA_asl, o_reg, jumpreg, o_imm, 1) )
        {
          if ( check_insn(1, XA_mov, o_reg, rR0H + 2*(jumpreg-rR0), o_imm, 0) )
          {
            datareg = cmd.Op1.reg - 1;
            prev = 0;
            if ( check_insn(1, XA_nop, o_last, BADADDR, o_last, BADADDR) )
              prev = 1;
            if ( check_insn(prev, XA_bg, o_last, BADADDR, o_last, BADADDR ) ||
                (check_insn(0, XA_jmp, o_last, BADADDR, o_last, BADADDR) &&
                 check_insn(1, XA_bl, o_last, BADADDR, o_last, BADADDR)))
            {
              if ( check_insn(1, XA_cmp, o_reg, datareg, o_imm, BADADDR) )
              {
                si->ncases = ushort(cmd.Op2.value+1);
                if ( check_insn(1, XA_bcs, o_last, BADADDR, o_last, BADADDR) )
                {
                  si->defjump = cmd.Op1.addr;
                  if ( check_insn(1, XA_sub, o_reg, datareg, o_imm, BADADDR ) ||
                      check_insn(0, XA_adds, o_reg, datareg, o_imm, BADADDR))
                  {
                    if ( cmd.itype == XA_sub )
                    {
                      si->lowcase = cmd.Op2.value;
                    } else {
                      si->lowcase = -cmd.Op2.value;
                    }
                    si->flags |= SWI_DEFAULT;
                    value = 1;
                    si->startea = cmd.ea;
                  } else {
                    warning("%a: no sub/add, may start with 0", cmd.ea);
                  }
                } else {
                  si->lowcase = 0;
                  si->flags |= SWI_DEFAULT;
                  value = 1;
                  si->startea = cmd.ea + cmd.size;
                }
              } else {
                warning("%a: no cmp", cmd.ea);
              }
            } else {
              warning("%a: no bg, may be signed", cmd.ea);
            }
          } else {
            prev = 0;
            if ( check_insn(0, XA_nop, o_last, BADADDR, o_last, BADADDR) )
              prev = 1;
            if ( check_insn(prev, XA_bg, o_last, BADADDR, o_last, BADADDR ) ||
                (check_insn(0, XA_jmp, o_last, BADADDR, o_last, BADADDR) &&
                 check_insn(1, XA_bl, o_last, BADADDR, o_last, BADADDR)))
            {
              if ( check_insn(1, XA_cmp, o_reg, BADADDR, o_imm, BADADDR) )
              {
                datareg = cmd.Op1.reg;
                si->ncases = ushort(cmd.Op2.value+1);
                if ( check_insn(1, XA_bcs, o_last, BADADDR, o_last, BADADDR) )
                {
                  si->defjump = cmd.Op1.addr;
                  if ( check_insn(1, XA_sub, o_reg, datareg, o_imm, BADADDR ) ||
                      check_insn(0, XA_adds, o_reg, datareg, o_imm, BADADDR))
                  {
                    if ( cmd.itype == XA_sub )
                    {
                      si->lowcase = cmd.Op2.value;
                    } else {
                      si->lowcase = -cmd.Op2.value;
                    }
                    si->flags |= SWI_DEFAULT;
                    value = 1;
                    si->startea = cmd.ea;
                  } else {
                    warning("no sub/add, may start with 0");
                  }
                } else {
                  si->lowcase = 0;
                  si->flags |= SWI_DEFAULT;
                  value = 1;
                  si->startea = cmd.ea + cmd.size;
                }
              } else {
                warning("%a: no cmp", cmd.ea);
              }
            } else {
              warning("%a: no bg, may be signed", cmd.ea);
            }
          }
        }
      }
    }

    if ( value )
    {
      if ( get_byte(si->jumps + 2*si->ncases) == 0xfe )
        ua_add_cref(int(saved.ea), si->jumps + 2*si->ncases, fl_F);
    }
    cmd = saved;
  }
  return value;
}

int idaapi xa_frame_retsize(func_t *pfn)
{
  return pfn->is_far() ? 2 : 4;
}

void idaapi xa_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v)
{
  char sign = '+';
  if ( v < 0 )
  {
    v = -v; sign = '-';
  }

  char name[MAXNAMELEN];
  name[0] = '\0';
  get_member_name(mptr->id, name, sizeof(name));

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  qsnprintf(buf, bufsize,
            COLSTR("%-*s", SCOLOR_LOCNAME)
            " "
            COLSTR("set     %c", SCOLOR_SYMBOL)
            COLSTR("%s",SCOLOR_DNUM),
            inf.indent-1, name, sign, vstr);
}

int idaapi xa_align_insn(ea_t ea)
{
  if ( get_byte(ea) == 0 ) return 1;
  return 0;
}

/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c54.hpp"
#include <frame.hpp>
#include <srarea.hpp>
#include <struct.hpp>

//----------------------------------------------------------------------
static void out_address(ea_t ea, op_t &x, bool mapping, bool at)
{
  regnum_t reg = get_mapped_register(ea);
  if ( mapping && reg != rnone) out_register(ph.regNames[reg] );
  else
  {
#ifndef TMS320C54_NO_NAME_NO_REF
    char buf[MAXSTR];
    // since tms320c54 uses memory mapping, we turn off verification
    // of name expression values (3d arg of get_name_expr is BADADDR)
    if ( get_name_expr(cmd.ea+x.offb, x.n, ea, BADADDR, buf, sizeof(buf)) > 0 )
    {
      if ( at)
        out_symbol('@' );
      OutLine(buf);
    }
    else
#endif
    {
      out_tagon(COLOR_ERROR);
      OutValue(x, OOFW_IMM|OOF_ADDR);
      out_tagoff(COLOR_ERROR);
      QueueMark(Q_noName, cmd.ea);
    }
  }
}

//----------------------------------------------------------------------
const char *get_cond8(char value)
{
  switch ( value )
  {
    case COND8_UNC:  return "unc";
    case COND8_NBIO: return "nbio";
    case COND8_BIO:  return "bio";
    case COND8_NC:   return "nc";
    case COND8_C:    return "c";
    case COND8_NTC:  return "ntc";
    case COND8_TC:   return "tc";
    case COND8_AGEQ: return "ageq";
    case COND8_ALT:  return "alt";
    case COND8_ANEQ: return "aneq";
    case COND8_AEQ:  return "aeq";
    case COND8_AGT:  return "agt";
    case COND8_ALEQ: return "aleq";
    case COND8_ANOV: return "anov";
    case COND8_AOV:  return "aov";
    case COND8_BGEQ: return "bgeq";
    case COND8_BLT:  return "blt";
    case COND8_BNEQ: return "bneq";
    case COND8_BEQ:  return "beq";
    case COND8_BGT:  return "bgt";
    case COND8_BLEQ: return "bleq";
    case COND8_BNOV: return "bnov";
    case COND8_BOV:  return "bov";
    default: return NULL;
  }
}


static void out_cond8(char value)
{
  const char *cond = get_cond8(value);
  QASSERT(256, cond != NULL) ;
  out_line(cond, COLOR_REG);
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  ea_t ea;

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_register(ph.regNames[x.reg]);
      break;

    case o_near:
    case o_far:
      out_address(calc_code_mem(x.addr, x.type == o_near), x, false, false);
      break;

    case o_imm:
      {
        const char *name = NULL;
        if ( idpflags & TMS320C54_IO && x.IOimm )
          name = find_sym(x.value);
        if ( !x.NoCardinal )
          out_symbol('#');
        if ( name != NULL )
        {
          out_line(name, COLOR_IMPNAME);
        }
        else
        {
          if ( !x.Signed )
            OutValue(x, OOFW_IMM);
          else
            OutValue(x, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
        }
        break;
      }

    case o_local:
      OutValue(x, OOFW_IMM|OOF_ADDR);
      break;

    case o_mmr:
    case o_mem:
    case o_farmem:
      if ( x.IndirectAddressingMOD == ABSOLUTE_INDIRECT_ADRESSING )
      {
        out_symbol('*');
        out_symbol('(');
      }
      ea = calc_data_mem(x.addr, x.type == o_mem);
      if ( ea != BADADDR )
        out_address(ea, x, true, x.IndirectAddressingMOD != ABSOLUTE_INDIRECT_ADRESSING); // no '@' if absolute "indirect" adressing
      else
        OutValue(x, OOFW_IMM|OOF_ADDR);
      if ( x.IndirectAddressingMOD == ABSOLUTE_INDIRECT_ADRESSING )
        out_symbol(')');
      break;

    case o_displ: // Indirect addressing mode
      {
        const char *reg = ph.regNames[x.reg];
        char buf[8];
        switch ( x.IndirectAddressingMOD )
        {
          case 0:
            qsnprintf(buf, sizeof(buf), "*%s",reg);
            out_register(buf);
            break;
          case 1:
            qsnprintf(buf, sizeof(buf), "*%s-",reg);
            out_register(buf);
            break;
          case 2:
            qsnprintf(buf, sizeof(buf), "*%s+",reg);
            out_register(buf);
            break;
          case 3:
            qsnprintf(buf, sizeof(buf), "*+%s",reg);
            out_register(buf);
            break;
          case 4:
            qsnprintf(buf, sizeof(buf), "*%s-0B",reg);
            out_register(buf);
            break;
          case 5:
            qsnprintf(buf, sizeof(buf), "*%s-0",reg);
            out_register(buf);
            break;
          case 6:
            qsnprintf(buf, sizeof(buf), "*%s+0",reg);
            out_register(buf);
            break;
          case 7:
            qsnprintf(buf, sizeof(buf), "*%s+0B",reg);
            out_register(buf);
            break;
          case 8:
            qsnprintf(buf, sizeof(buf), "*%s-%%",reg);
            out_register(buf);
            break;
          case 9:
            qsnprintf(buf, sizeof(buf), "*%s-0%%",reg);
            out_register(buf);
            break;
          case 0xA:
            qsnprintf(buf, sizeof(buf), "*%s+%%",reg);
            out_register(buf);
            break;
          case 0xB:
            qsnprintf(buf, sizeof(buf), "*%s+0%%",reg);
            out_register(buf);
            break;
          case 0xC:
            qsnprintf(buf, sizeof(buf), "*%s(",reg);
            out_register(buf);
            OutValue(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
            out_symbol(')');
            break;
          case 0xD:
            qsnprintf(buf, sizeof(buf), "*+%s(",reg);
            out_register(buf);
            OutValue(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
            out_symbol(')');
            break;
          case 0xE:
            qsnprintf(buf, sizeof(buf), "*+%s(",reg);
            out_register(buf);
            OutValue(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
            out_symbol(')');
            out_symbol('%');
            break;
          // this special adressing mode is now defined as o_farmem !
          // case ABSOLUTE_INDIRECT_ADRESSING:
          //   out_symbol('*');
          //   out_symbol('(');
          //   OutValue(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
          //   out_symbol(')');
          //   break;
          default:
            error("interr: out: o_displ");
        }
        break;
      }

    case o_bit:
      {
        if ( !x.NoCardinal )
          out_symbol('#');
        char buf[20];
        qsnprintf(buf, sizeof(buf), "%d", int(x.value));
        out_line(buf,COLOR_REG);
        break;
      }

    case o_cond8:
      out_cond8((uchar)x.value);
      break;

    case o_cond2:
      {
        const char *cond = "";
        switch ( x.value )
        {
          case 0: cond = "eq";  break;
          case 1: cond = "lt";  break;
          case 2: cond = "gt";  break;
          case 3: cond = "neq"; break;
          default: warning("interr: out 2-bit condition");
        }
        out_line(cond, COLOR_REG);
        break;
      }

    default:
      error("interr: out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  OutMnem();
  out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
    if ( cmd.IsParallel )
    { // new line for Parallel instructions
      term_output_buffer();
      MakeLine(buf);
      init_output_buffer(buf, sizeof(buf));
      out_line("|| ", COLOR_INSN);
      const char *insn2 = NULL;
      switch ( cmd.itype )
      {
        case TMS320C54_ld_mac:  insn2 = "mac  "; break;
        case TMS320C54_ld_macr: insn2 = "macr "; break;
        case TMS320C54_ld_mas:  insn2 = "mas  "; break;
        case TMS320C54_ld_masr: insn2 = "masr "; break;
        case TMS320C54_st_add:  insn2 = "add  "; break;
        case TMS320C54_st_sub:  insn2 = "sub  "; break;
        case TMS320C54_st_ld:   insn2 = "ld   "; break;
        case TMS320C54_st_mpy:  insn2 = "mpy  "; break;
        case TMS320C54_st_mac:  insn2 = "mac  "; break;
        case TMS320C54_st_macr: insn2 = "macr "; break;
        case TMS320C54_st_mas:  insn2 = "mas  "; break;
        case TMS320C54_st_masr: insn2 = "masr "; break;
        default: warning("interr: out parallel instruction");
      }
      out_line(insn2, COLOR_INSN);
    }
    if ( cmd.Op3.type != o_void )
    {
      if ( !cmd.IsParallel )
      {
        out_symbol(',');
        OutChar(' ');
      }
      out_one_operand(2);
      if ( cmd.Op4_type != 0 )
      {
        out_symbol(',');
        OutChar(' ');
        switch ( cmd.Op4_type )
        {
          case o_reg:
            out_register(ph.regNames[cmd.Op4_value]);
            break;
          case o_cond8:
            out_cond8(cmd.Op4_value);
            break;
          default:
            break;
        }
      }
    }
  }
  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea, uFlag, 2) ) OutImmChar(cmd.Op3);

  term_output_buffer();
  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
static void print_segment_register(int reg, sel_t value)
{
  if ( reg == ph.regDataSreg ) return;
  if ( value != BADADDR )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), value);
    gen_cmt_line("assume %s = %s", ph.regNames[reg], buf);
  }
  else
  {
    gen_cmt_line("drop %s", ph.regNames[reg]);
  }
}

//--------------------------------------------------------------------------
// function to produce assume directives
void idaapi assumes(ea_t ea)
{
  segreg_t *Darea  = getSRarea(ea);
  segment_t *Sarea = getseg(ea);
  if ( Sarea == NULL || Darea == NULL || !inf.s_assume ) return;

  for ( int i=ph.regFirstSreg; i <= ph.regLastSreg; i++ )
  {
    if ( i == ph.regCodeSreg ) continue;
    sel_t now  = getSR(ea, i);
    bool show = (ea == Sarea->startEA);
    if ( show || Darea->startEA == ea )
    {
      segreg_t *prev = getSRarea(ea-1);
      if ( show || (prev != NULL && getSR(prev->startEA, i) != now) )
        print_segment_register(i, now);
    }
  }
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;

  char sclas[MAXNAMELEN];
  get_segm_class(Sarea, sclas, sizeof(sclas));

  if ( strcmp(sclas,"CODE") == 0 )
    printf_line(inf.indent, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( strcmp(sclas,"DATA") == 0 )
    printf_line(inf.indent, COLSTR(".data", SCOLOR_ASMDIR));

  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t)
{
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_cmt_line("Processor       : %-8.8s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  gen_cmt_line("Byte sex        : %s, %s",
                  inf.mf ? "big-endian" : "little-endian",
                  inf.wide_high_byte_first ? "high_byte_first" : "high_byte_last");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
  MakeNull();
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR),ash.end);
}

//--------------------------------------------------------------------------
void idaapi gen_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v)
{
  char sign = ' ';
  if ( v < 0 )
  {
    sign = '-';
    v = -v;
  }

  char name[MAXNAMELEN];
  name[0] = '\0';
  get_member_name(mptr->id, name, sizeof(name));

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  qsnprintf(buf, bufsize,
            COLSTR("%s",SCOLOR_KEYWORD) " "
            COLSTR("%c%s",SCOLOR_DNUM)
            COLSTR(",",SCOLOR_SYMBOL) " "
            COLSTR("%s",SCOLOR_LOCNAME),
            ash.a_equ,
            sign,
            vstr,
            name);
}


/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#include "avr.hpp"
#include <entry.hpp>

//----------------------------------------------------------------------
static void out_phrase(int phn)
{
  switch ( phn )
  {
    case PH_XPLUS:     // X+
      out_register("X");
      out_symbol('+');
      break;
    case PH_MINUSX:    // -X
      out_symbol('-');
    case PH_X:         // X
      out_register("X");
      break;
    case PH_YPLUS:     // Y+
      out_register("Y");
      out_symbol('+');
      break;
    case PH_MINUSY:    // -Y
      out_symbol('-');
    case PH_Y:         // Y
      out_register("Y");
      break;
    case PH_ZPLUS:     // Z+
      out_register("Z");
      out_symbol('+');
      break;
    case PH_MINUSZ:    // -Z
      out_symbol('-');
    case PH_Z:         // Z
      out_register("Z");
      break;
    default:
      error("%a: bad phrase number", cmd.ea);
  }
}

//----------------------------------------------------------------------
static void out_bad_address(ea_t addr)
{
  out_tagon(COLOR_ERROR);
  OutLong(addr, 16);
  out_tagoff(COLOR_ERROR);
  QueueMark(Q_noName, cmd.ea);
}

//----------------------------------------------------------------------
bool idaapi outop(op_t &x)
{
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_reg:
      if ( ram != BADADDR )
      {
        char buf[MAXSTR];
        const char *name = get_name(cmd.ea, ram+x.reg, buf, sizeof(buf));
        if ( name != NULL )
        {
          out_register(name);
          break;
        }
      }
      out_register(ph.regNames[x.reg]);
      break;

    case o_imm:
      if ( cmd.itype == AVR_cbi
        || cmd.itype == AVR_sbic
        || cmd.itype == AVR_sbi
        || cmd.itype == AVR_sbis )
      {
        const char *bit = find_bit(cmd.Op1.addr, (size_t)x.value);
        if ( bit != NULL )
        {
          out_line(bit, COLOR_REG);
          break;
        }
      }
      if ( x.specflag1 && isOff1(uFlag) && !is_invsign(cmd.ea, uFlag, 1) )
      {
        out_symbol('-');
      }
      OutValue(x, OOFS_IFSIGN|OOF_SIGNED|OOFW_8);
      break;

    case o_near:
      {
        ea_t ea = toEA(cmd.cs, x.addr);
        if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_mem:
      {
        ea_t ea = toEA(dataSeg(), x.addr);
        if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_phrase:
      out_phrase(x.phrase);
      break;

    case o_displ:
      out_phrase(x.phrase);
      OutValue(x,OOF_ADDR|OOFS_NEEDSIGN|OOFW_IMM);
      break;

    case o_port:
      {
        const char *pname = find_port(x.addr);
        if ( pname == NULL )
          out_bad_address(x.addr);
        else
          out_register(pname);
      }
      break;

    default:
      warning("out: %a: bad optype %d", cmd.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  // output .org for enties without any labels
  if ( !has_any_name(uFlag) && helper.altval(cmd.ea) )
  {
    btoa(buf, sizeof(buf), cmd.ip);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }

  init_output_buffer(buf, sizeof(buf));

  OutMnem();

  out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }

  if ( isVoid(cmd.ea, uFlag, 0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea, uFlag, 1) ) OutImmChar(cmd.Op2);

  term_output_buffer();

  gl_comm = 1;
  MakeLine(buf);
}

//--------------------------------------------------------------------------
void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);
  if ( is_spec_segm(Sarea->type) ) return;
  char sname[MAXNAMELEN];
  char sclas[MAXNAMELEN];
  get_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));
  printf_line(0, COLSTR("%s", SCOLOR_ASMDIR)
                 " "
                 COLSTR("%s %s", SCOLOR_AUTOCMT),
                 strcmp(sclas,"CODE") == 0
                    ? ".CSEG"
                    : strcmp(sclas,"DATA") == 0
                         ? ".DSEG"
                         : ".ESEG",
                 ash.cmnt,
                 sname);
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
  gen_cmt_line("Processor       : %-8.8s [%s]", inf.procName, device);
  gen_cmt_line("Target assembler: %s", ash.name);
//  gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  char name[MAXSTR];
  get_name(BADADDR, inf.beginEA, name, sizeof(name));
  printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR)
                " "
                COLSTR("%s %s",SCOLOR_AUTOCMT), ash.end, ash.cmnt, name);
}

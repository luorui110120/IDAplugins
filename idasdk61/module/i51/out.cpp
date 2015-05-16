/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "i51.hpp"
#include <fpro.h>
#include <diskio.hpp>

//----------------------------------------------------------------------
static void vlog(const char *format, va_list va)
{
  static FILE *fp = NULL;
  if ( fp == NULL ) fp = fopenWT("debug_log");
  qvfprintf(fp, format, va);
  qflush(fp);
}
//----------------------------------------------------------------------
inline void log(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vlog(format, va);
  va_end(va);
}

#define AT   COLSTR("@", SCOLOR_SYMBOL)
#define PLUS COLSTR("+", SCOLOR_SYMBOL)

static const char *phrases[] =
{
  AT COLSTR("R0", SCOLOR_REG),
  AT COLSTR("R1", SCOLOR_REG),
  AT COLSTR("DPTR", SCOLOR_REG),
  AT COLSTR("A", SCOLOR_REG) PLUS COLSTR("DPTR", SCOLOR_REG),
  AT COLSTR("A", SCOLOR_REG) PLUS COLSTR("PC", SCOLOR_REG)
};

//----------------------------------------------------------------------
inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
// generate the text representation of an operand

bool idaapi outop(op_t &x)
{
  uval_t v;
  int dir, bit;
  char buf[MAXSTR];
  switch ( x.type )
  {
    case o_reg:
      OutReg(x.reg);
      break;

    case o_phrase:
      if ( x.phrase == fRi )
      {
        out_symbol('@');
        OutReg(x.indreg);
        break;
      }
      out_colored_register_line(phrases[x.phrase]);
      break;

    case o_displ:
      out_symbol('@');
      OutReg(x.reg);
      out_symbol('+');
      OutValue(x, OOF_ADDR | OOFS_IFSIGN | OOFW_16);
      break;

    case o_imm:
      out_symbol('#');
      if ( cmd.auxpref & aux_0ext ) out_symbol('0');
      if ( cmd.auxpref & aux_1ext ) out_symbol('1');
      OutValue(x, OOFS_IFSIGN | OOFW_IMM);
      break;

    case o_mem:
    case o_near:
      v = map_addr(x.addr, x.n, x.type==o_mem);
      if ( get_name_expr(cmd.ea+x.offb, x.n, v, x.addr, buf, sizeof(buf)) <= 0 )
      {
/*        int nbit;
        if ( cmd.itype == I51_ecall || cmd.itype == I51_ejmp )
          nbit = OOFW_32;
        else
          nbit = OOFW_16;*/
        OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
        QueueMark(Q_noName, cmd.ea);
        break;
      }

      // we want to output SFR register names always in COLOR_REG,
      // so remove the color tags and output it manually:

      if ( x.type == o_mem && x.addr >= 0x80 )
      {
        tag_remove(buf, buf, sizeof(buf));
        out_register(buf);
        break;
      }
      OutLine(buf);
      break;

    case o_void:
      return false;

    case o_bit251:
      if ( x.b251_bitneg ) out_symbol('/');
      dir = (int)x.addr;
      bit = x.b251_bit;
      goto OUTBIT;

    case o_bitnot:
      out_symbol('/');
    case o_bit:
      dir = (x.reg & 0xF8);
      bit = x.reg & 7;
      if ( (dir & 0x80) == 0 ) dir = dir/8 + 0x20;
OUTBIT:
      v = map_addr(dir, x.n, true);
      out_addr_tag(v);
      if ( ash.uflag & UAS_PBIT )
      {
        const ioport_bit_t *predef = find_bit( dir, bit);
        if ( predef != NULL )
        {
          out_line(predef->name, COLOR_REG);
          break;
        }
      }
      {
        ssize_t len = get_name_expr(cmd.ea+x.offb, x.n, v, dir, buf, sizeof(buf));
        if ( len > 0 && strchr(buf, '+') == NULL )
        {

      // we want to output the bit names always in COLOR_REG,
      // so remove the color tags and output it manually:

          if ( dir < 0x80 )
          {
            OutLine(buf);
          }
          else
          {
            tag_remove(buf, buf, sizeof(buf));
            out_register(buf);
          }
        }
        else
        {
          out_long(dir, 16);
        }
        out_symbol(ash.uflag & UAS_NOBIT ? '_' : '.');
        out_symbol(char('0'+bit));
      }
      break;

     default:
       warning("out: %a: bad optype %d",cmd.ea,x.type);
       break;
  }
  return true;
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the 'cmd' structure

void idaapi out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf)); // setup the output pointer
  OutMnem();                            // output instruction mnemonics

  out_one_operand(0);                   // output the first operand

  if ( cmd.Op2.type != o_void)
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);                 // output the second operand
  }

  if ( cmd.Op3.type != o_void)
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(2);                 // output the third operand
  }


  // output a character representation of the immediate values
  // embedded in the instruction as comments

  if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea,uFlag,2) ) OutImmChar(cmd.Op3);

  term_output_buffer();                 // terminate the output string
  gl_comm = 1;                          // ask to attach a possible user-
                                        // defined comment to it
  MakeLine(buf);                        // pass the generated line to the
                                        // kernel
}

//--------------------------------------------------------------------------
// generate start of the disassembly

void idaapi header(void)
{
  gen_cmt_line("Processor:        %s [%s]", device[0] ? device : inf.procName, deviceparams);
  gen_cmt_line("Processor:        %s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ ) MakeLine(*ptr,0);
}

//--------------------------------------------------------------------------
// generate start of a segment

void idaapi segstart(ea_t ea)
{
  char buf[MAXSTR];
  segment_t *Sarea = getseg(ea);

  char name[MAXNAMELEN];
  get_segm_name(Sarea, name, sizeof(name));

  if ( ash.uflag & UAS_SECT )
  {
    if ( Sarea->type == SEG_IMEM )
    {
      MakeLine(".RSECT", inf.indent);
    }
    else
    {
      printf_line(0, COLSTR("%s: .section", SCOLOR_ASMDIR), name);
    }
  }
  else
  {
    if ( ash.uflag & UAS_NOSEG )
       printf_line(inf.indent, COLSTR("%s.segment %s", SCOLOR_AUTOCMT), ash.cmnt, name);
    else
       printf_line(inf.indent, COLSTR("segment %s",SCOLOR_ASMDIR), name);
    if ( ash.uflag & UAS_SELSG) MakeLine(name, inf.indent );
    if ( ash.uflag & UAS_CDSEG )
      MakeLine(Sarea->type == SEG_IMEM
                 ? COLSTR("DSEG", SCOLOR_ASMDIR)
                 : COLSTR("CSEG", SCOLOR_ASMDIR),
               inf.indent);
            // XSEG - eXternal memory
  }
  if ( inf.s_org )
  {
    adiff_t org = ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      btoa(buf, sizeof(buf), org);
      gen_cmt_line("%s %s", ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly

void idaapi footer(void)
{
  char buf[MAXSTR];
  if ( ash.end != NULL)
  {
    MakeNull();
    char *const end = buf + sizeof(buf);
    char *ptr = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
    char name[MAXSTR];
    if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL )
    {
      APPCHAR(ptr, end, ' ');
      if( ash.uflag & UAS_NOENS )
        APPEND(ptr, end, ash.cmnt);
      APPEND(ptr, end, name);
    }
    MakeLine(buf, inf.indent);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
// output one "equ" directive

static void do_out_equ(const char *name, const char *equ, uchar off)
{
  char buf[MAXSTR];
  char *ptr = buf;
  char *const end = buf + sizeof(buf);
  gl_name = 0;
  if ( ash.uflag & UAS_PSAM )
  {
    ptr = tag_addstr(ptr, end, COLOR_KEYWORD, equ);
    APPCHAR(ptr, end, ' ');
    APPEND(ptr, end, name);
    ptr = tag_addchr(ptr, end, COLOR_SYMBOL, ',');
  }
  else
  {
    APPEND(ptr, end, name);
    if ( ash.uflag & UAS_EQCLN )
      ptr = tag_addchr(ptr, end, COLOR_SYMBOL, ':');
    APPCHAR(ptr, end, ' ');
    ptr = tag_addstr(ptr, end, COLOR_KEYWORD, equ);
    APPCHAR(ptr, end, ' ');
  }
  ptr = tag_on(ptr, end, COLOR_NUMBER);
  ptr += btoa32(ptr, end-ptr, off);
  tag_off(ptr, end, COLOR_NUMBER);
  MakeLine(buf, 0);
}

//--------------------------------------------------------------------------
// output "equ" directive(s) if necessary

static int out_equ(ea_t ea)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  segment_t *s = getseg(ea);
  if ( s != NULL && s->type == SEG_IMEM && ash.a_equ != NULL)
  {
    char nbuf[MAXSTR];
    char *name = get_name(BADADDR, ea, nbuf, sizeof(nbuf));
    if ( name != NULL
      && ((ash.uflag & UAS_PBYTNODEF) == 0 || !IsPredefined(name)) )
    {
      get_colored_name(BADADDR, ea, buf, sizeof(buf));
      uchar off = uchar(ea - get_segm_base(s));
      do_out_equ(buf, ash.a_equ, off);
      if ( (ash.uflag & UAS_AUBIT) == 0 && (off & 0xF8) == off )
      {
        char *ptr = tag_on(tail(buf), end, COLOR_SYMBOL);
        APPCHAR(ptr, end, ash.uflag & UAS_NOBIT ? '_' : '.');
        APPCHAR(ptr, end, '0');
        tag_off(ptr, end, COLOR_SYMBOL);
        for ( int i=0; i < 8; i++ )
        {
          const ioport_bit_t *b = find_bit(off, i);
          char *p2 = ptr;
          if ( b == NULL || b->name == NULL )
            ptr[-1] = char('0' + i);
          else
            p2 = tag_addstr(ptr-1, end, COLOR_HIDNAME, b->name);
          tag_off(p2, end, COLOR_SYMBOL);
          do_out_equ(buf, ash.a_equ, uchar(off+i));
        }
        MakeNull();
      }
    }
    else
    {
      gl_name = 0;
      MakeLine("");
    }
    return 1;
  }
  if ( ash.uflag & UAS_NODS )
  {
    if ( s != NULL && !isLoaded(ea) && s->type == SEG_CODE )
    {
      adiff_t org = ea - get_segm_base(s) + get_item_size(ea);
      btoa(buf, sizeof(buf), org);
      printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
      return 1;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
// generate a data representation
// usually all the job is handled by the kernel's standard procedure,
// intel_data()
// But 8051 has its own quirks (namely, "equ" directives) and intel_data()
// can't handle them. So we output "equ" ourselves and pass everything
// else to intel_data()
// Again, let's repeat: usually the data items are output by the kernel
// function intel_data(). You have to override it only if the processor
// has special features and the data items should be displayed in a
// special way.

void idaapi i51_data(ea_t ea)
{
  gl_name = 1;

  // the kernel's standard routine which outputs the data knows nothing
  // about "equ" directives. So we do the following:
  //    - try to output an "equ" directive
  //    - if we succeed, then ok
  //    - otherwise let the standard data output routine, intel_data()
  //        do all the job

  if ( !out_equ(ea) )
    intel_data(ea);
}

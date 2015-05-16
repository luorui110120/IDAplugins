/*
        This module has been created by Petr Novak
 */

#include "xa.hpp"
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
  uval_t v = 0;
  int dir, bit;
  char buf[MAXSTR];
  switch ( x.type )
  {
    case o_reg:
      OutReg(x.reg);
      break;

    case o_phrase:
      switch ( x.phrase )
      {
        case fAdptr:
        case fApc:
                out_colored_register_line(phrases[x.phrase]);
                break;
        case fRi:
                out_symbol('[');
                OutReg(x.indreg);
                out_symbol(']');
                break;
        case fRip:
                out_symbol('[');
                OutReg(x.indreg);
                out_symbol('+');
                out_symbol(']');
                break;
        case fRii:
                out_symbol('[');
                out_symbol('[');
                OutReg(x.indreg);
                out_symbol(']');
                out_symbol(']');
                break;
        case fRipi:
                out_symbol('[');
                out_symbol('[');
                OutReg(x.indreg);
                out_symbol('+');
                out_symbol(']');
                out_symbol(']');
                break;
        case fRlistL:
        case fRlistH:
                v = x.indreg;
                dir = (x.dtyp == dt_byte) ? rR0L : rR0;
                if ( x.phrase == fRlistH ) dir += 8;
                for (bit = 0; bit < 8; bit++,dir++,v >>= 1)
                {
                  if ( v&1 )
                  {
                    OutReg(dir);
                    if ( v & 0xfe) out_symbol(',' );
                  }
                }
                break;
      }
      break;

    case o_displ:
      if ( cmd.itype != XA_lea) out_symbol('[' );
      OutReg(x.indreg);
      if ( x.indreg == rR7 || x.phrase != fRi )
        OutValue(x, OOF_ADDR | OOFS_NEEDSIGN | OOF_SIGNED | OOFW_16);
      if ( cmd.itype != XA_lea) out_symbol(']' );
      break;

    case o_imm:
      out_symbol('#');
      OutValue(x, OOFS_IFSIGN | /* OOF_SIGNED | */ OOFW_IMM);
      break;

    case o_mem:
    case o_near:
    case o_far:
      switch ( x.type )
      {
        case o_mem:
          v = map_addr(x.addr);
          break;
        case o_near:
          v = toEA(cmd.cs, x.addr);
          break;
        case o_far:
          v = x.addr + (x.specval<<16);
          break;
      }
      if ( get_name_expr(cmd.ea+x.offb, x.n, v, x.addr & 0xFFFF, buf, sizeof(buf)) <= 0 )
      {
        OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
        QueueMark(Q_noName, cmd.ea);
        break;
      }

      // we want to output SFR register names always in COLOR_REG,
      // so remove the color tags and output it manually:

      if ( x.type == o_mem && x.addr >= 0x400 )
      {
        tag_remove(buf, buf, sizeof(buf));
        out_register(buf);
        break;
      }
      OutLine(buf);
      break;

    case o_void:
      return 0;

    case o_bitnot:
      out_symbol('/');
    case o_bit:
      dir = int(x.addr >> 3);
      bit = x.addr & 7;
      if ( dir & 0x40 ) // SFR
      {
        dir += 0x3c0;
      } else if ( (dir & 0x20) == 0 ) { // Register file
        dir = int(x.addr >> 4);
        bit = x.addr & 15;
        OutReg(rR0+dir);
        out_symbol(ash.uflag & UAS_NOBIT ? '_' : '.');
        if ( bit>9 )
        {
          out_symbol('1');
          bit -= 10;
        }
        out_symbol(char('0'+bit));
        break;
      }
      if ( ash.uflag & UAS_PBIT )
      {
        predefined_t *predef = GetPredefined(ibits, dir, bit);
        if ( predef != NULL )
        {
          out_line(predef->name, COLOR_REG);
          break;
        }
      }
      {
        v = map_addr(dir);
        bool ok = get_name_expr(cmd.ea+x.offb, x.n, v, dir, buf, sizeof(buf));
        if ( ok && strchr(buf, '+') == NULL )
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
       warning("out: %a: bad optype %d", cmd.ea, x.type);
       break;
  }
  return 1;
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the 'cmd' structure

void idaapi out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf)); // setup the output pointer
  if ( cmd.Op1.type != o_void ) {
    switch ( cmd.Op1.dtyp )
    {
      case dt_byte:
        OutMnem(8,".b");
        break;
      case dt_word:
        OutMnem(8,".w");
        break;
      case dt_dword:
        OutMnem(8,".d");
        break;
      default:
        OutMnem();
    }
  } else
    OutMnem();                          // output instruction mnemonics

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
  gen_cmt_line("Processor:        %s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ ) MakeLine(*ptr,0);
}

//--------------------------------------------------------------------------
// generate start of a segment

void idaapi segstart(ea_t ea)
{
  segment_t *Sarea = getseg(ea);

  char sname[MAXNAMELEN];
  get_segm_name(Sarea, sname, sizeof(sname));

  if ( ash.uflag & UAS_SECT )
  {
    if ( Sarea->type == SEG_IMEM )
      MakeLine(".RSECT", inf.indent);
    else
      printf_line(0, COLSTR("%s: .section", SCOLOR_ASMDIR), sname);
  }
  else
  {
    if ( ash.uflag & UAS_NOSEG )
      printf_line(inf.indent, COLSTR("%s.segment %s", SCOLOR_AUTOCMT),
                 ash.cmnt, sname);
    else
      printf_line(inf.indent, COLSTR("segment %s",SCOLOR_ASMDIR), sname);
    if ( ash.uflag & UAS_SELSG) MakeLine(sname, inf.indent );
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
    if( org != 0 )
    {
      char buf[MAX_NUMBUF];
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
  char *const end = buf + sizeof(buf);
  if ( ash.end != NULL)
  {
    MakeNull();
    register char *p = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
    char name[MAXSTR];
    if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL )
    {
      APPCHAR(p, end, ' ');
      if ( ash.uflag & UAS_NOENS )
        APPEND(p, end, ash.cmnt);
      APPEND(p, end, name);
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

static void do_out_equ(char *name,const char *equ,uchar off)
{
  char buf[MAXSTR];
  char *const end = buf + sizeof(buf);
  register char *p = buf;
  gl_name = 0;
  if ( ash.uflag & UAS_PSAM ) {
    p = tag_addstr(p, end, COLOR_KEYWORD, equ);
    APPCHAR(p, end, ' ');
    APPEND(p, end, name);
    p = tag_addchr(p, end, COLOR_SYMBOL, ',');
  } else {
    APPEND(p, end, name);
    if ( ash.uflag & UAS_EQCLN )
      p = tag_addchr(p, end, COLOR_SYMBOL, ':');
    APPCHAR(p, end, ' ');
    p = tag_addstr(p, end, COLOR_KEYWORD, equ);
    APPCHAR(p, end, ' ');
  }
  p = tag_on(p, end, COLOR_NUMBER);
  p += btoa(p, end-p, off);
  tag_off(p, end, COLOR_NUMBER);
  MakeLine(buf, 0);
}

//--------------------------------------------------------------------------
// output "equ" directive(s) if necessary

static int out_equ(ea_t ea)
{
  segment_t *s = getseg(ea);
  if ( s != NULL && s->type == SEG_IMEM && ash.a_equ != NULL)
  {
    char nbuf[MAXSTR];
    char *name = get_name(BADADDR, ea, nbuf, sizeof(nbuf));
    if ( name != NULL
      && ((ash.uflag & UAS_PBYTNODEF) == 0 || !IsPredefined(name)) )
    {
      char buf[MAXSTR];
      char *const end = buf + sizeof(buf);
      char *ptr = get_colored_name(BADADDR, ea, buf, sizeof(buf));
      uchar off = uchar(ea - get_segm_base(s));
      do_out_equ(buf, ash.a_equ, off);
      if ( (ash.uflag & UAS_AUBIT) == 0 && (off & 0xF8) == off )
      {
        ptr = tag_on(ptr, end, COLOR_SYMBOL);
        APPCHAR(ptr, end, ash.uflag & UAS_NOBIT ? '_' : '.');
        APPZERO(ptr, end);
        tag_off(ptr, end, COLOR_SYMBOL);
        for( ; ptr[-1] < '8'; off++, (ptr[-1])++)
          do_out_equ(buf, ash.a_equ, off);
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
    if ( !isLoaded(ea) && s->type == SEG_CODE )
    {
      adiff_t org = ea - get_segm_base(s) + get_item_size(ea);
      char buf[MAX_NUMBUF];
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
// has special features and the data itesm should be displayed in a
// special way.

void idaapi xa_data(ea_t ea)
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

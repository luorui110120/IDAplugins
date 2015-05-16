/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "pic.hpp"
#include <frame.hpp>
#include <srarea.hpp>
#include <struct.hpp>

//----------------------------------------------------------------------
static void out_bad_address(ea_t addr)
{
  out_tagon(COLOR_ERROR);
  OutLong(addr, 16);
  out_tagoff(COLOR_ERROR);
  QueueMark(Q_noName, cmd.ea);
}

//----------------------------------------------------------------------
inline void outreg(int r)
{
  out_register(ph.regNames[r]);
}

//----------------------------------------------------------------------
ea_t calc_code_mem(ea_t ea)
{
  return toEA(cmd.cs, ea);
}

//----------------------------------------------------------------------
ea_t calc_data_mem(ea_t ea)
{
  return dataseg + map_port(ea);
}

//----------------------------------------------------------------------
int calc_outf(op_t &x)
{
  switch ( x.dtyp )
  {
    default:
      INTERR(249);
    case dt_byte: return OOFS_IFSIGN|OOFW_8;
    case dt_word: return OOFS_IFSIGN|OOFW_16;
  }
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
      outreg(x.reg);
      break;

    case o_imm:
      if ( is_bit_insn() )
      {
        const char *name = find_bit(cmd.Op1.addr, (int)x.value);
        if ( name != NULL )
        {
          out_line(name, COLOR_IMPNAME);
          break;
        }
      }
      OutValue(x, calc_outf(x));
      break;

    case o_mem:
      {
        ea = calc_data_mem(x.addr);
        const char *name = find_sym(x.addr);
        if ( name == NULL ) goto OUTNAME;
        out_addr_tag(ea);
        out_line(name, COLOR_IMPNAME);
      }
      break;

    case o_near:
      {
        ea = calc_code_mem(x.addr);
OUTNAME:
        if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    default:
      error("interr: out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
bool conditional_insn(void)
{
  if ( isFlow(uFlag) )
  {
    int code;
    switch ( ptype )
    {
      case PIC12:
        code = get_full_byte(cmd.ea-1);
        if ( (code & 0xFC0) == 0x2C0 ) return true;        // 0010 11df ffff DECFSZ  f, d           Decrement f, Skip if 0
        else if ( (code & 0xFC0) == 0x3C0 ) return true;   // 0011 11df ffff INCFSZ  f, d           Increment f, Skip if 0
        else if ( (code & 0xF00) == 0x600 ) return true;   // 0110 bbbf ffff BTFSC   f, b           Bit Test f, Skip if Clear
        else if ( (code & 0xF00) == 0x700 ) return true;   // 0111 bbbf ffff BTFSS   f, b           Bit Test f, Skip if Set
        break;
      case PIC14:
        code = get_full_byte(cmd.ea-1);
        if ( (code & 0x3F00) == 0x0B00 ) return true;      // 00 1011 dfff ffff DECFSZ  f, d        Decrement f, Skip if 0
        else if ( (code & 0x3F00) == 0x0F00 ) return true; // 00 1111 dfff ffff INCFSZ  f, d        Increment f, Skip if 0
        else if ( (code & 0x3C00) == 0x1800 ) return true; // 01 10bb bfff ffff BTFSC   f, b        Bit Test f, Skip if Clear
        else if ( (code & 0x3C00) == 0x1C00 ) return true; // 01 11bb bfff ffff BTFSS   f, b        Bit Test f, Skip if Set
        break;
      case PIC16:
        code = get_word(cmd.ea-2);
        code >>= 10;
        // 1010 bbba ffff ffff BTFSS  f, b, a    Bit Test f, Skip if Set
        // 1011 bbba ffff ffff BTFSC  f, b, a    Bit Test f, Skip if Clear
        if ( (code & 0x38) == 0x28 )
          return true;
        switch ( code )
        {
          case 0x0B: // 0010 11da ffff ffff DECFSZ f, d, a    Decrement f, Skip if 0
          case 0x0F: // 0011 11da ffff ffff INCFSZ f, d, a    Increment f, Skip if 0
          case 0x12: // 0100 10da ffff ffff INFSNZ f, d, a    Increment f, Skip if not 0
          case 0x13: // 0100 11da ffff ffff DCFSNZ f, d, a    Decrement f, Skip if not 0
          case 0x18: // 0110 000a ffff ffff CPFSLT f, a       Compare f with W, Skip if <
                     // 0110 001a ffff ffff CPFSEQ f, a       Compare f with W, Skip if ==
          case 0x19: // 0110 010a ffff ffff CPFSGT f, a       Compare f with W, Skip if >
                     // 0110 011a ffff ffff TSTFSZ f, a       Test f, Skip if 0
            return true;
        }
        break;
    }
  }
  return false;
}

//----------------------------------------------------------------------
void idaapi out(void)
{
  char buf[MAXSTR];
  init_output_buffer(buf, sizeof(buf));

  if ( conditional_insn() ) OutChar(' ');
  OutMnem();

  out_one_operand(0);
  if ( cmd.Op2.type != o_void )
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
    if ( cmd.Op3.type != o_void )
    {
      out_symbol(',');
      OutChar(' ');
      out_one_operand(2);
    }
  }

  if ( ( cmd.Op1.type == o_mem && cmd.Op1.addr == PIC16_INDF2 )
    || ( cmd.Op2.type == o_mem && cmd.Op2.addr == PIC16_INDF2 ) )
  {
    func_t *pfn  = get_func(cmd.ea);
    struc_t *sptr  = get_frame(pfn);
    if ( pfn != NULL && sptr != NULL )
    {
      member_t *mptr = get_member(sptr, pfn->frregs + pfn->frsize);
      if ( mptr != NULL )
      {
        char name[MAXNAMELEN];
        if ( get_member_name(mptr->id, name, sizeof(name)) > 0 )
        {
          OutChar(' ');
          out_line(ash.cmnt, COLOR_AUTOCMT);
          OutChar(' ');
          out_line(name, COLOR_LOCNAME);
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
  if ( value != BADSEL )
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
void idaapi assumes(ea_t ea)         // function to produce assume directives
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

  char sname[MAXNAMELEN];
  char sclas[MAXNAMELEN];
  get_true_segm_name(Sarea, sname, sizeof(sname));
  get_segm_class(Sarea, sclas, sizeof(sclas));

  printf_line(inf.indent, COLSTR("%s %s (%s)", SCOLOR_AUTOCMT),
                  ash.cmnt,
                 strcmp(sclas,"CODE") == 0
                    ? ".text"
                    : strcmp(sclas,"BSS") == 0
                         ? ".bss"
                         : ".data",
                 sname);
  if ( Sarea->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Sarea->orgbase);
    printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(ea_t) {
#if 0
  segment_t *s = getseg(ea-1);
  if ( is_spec_segm(s->type) ) return;
  printf_line(0,COLSTR(";%-*s ends",SCOLOR_AUTOCMT),inf.indent-2,get_segm_name(s));
#endif
}

//--------------------------------------------------------------------------
void idaapi header(void)
{
  gen_cmt_line("Processor       : %-8.8s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  printf_line(0,COLSTR("include \"P%s.INC\"",SCOLOR_ASMDIR),device);
//  gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ )
      printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
  MakeNull();
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  char name[MAXSTR];
  get_colored_name(BADADDR, inf.beginEA, name, sizeof(name));
  const char *end = ash.end;
  if ( end == NULL )
    printf_line(inf.indent,COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    printf_line(inf.indent,COLSTR("%s",SCOLOR_ASMDIR)
                  " "
                  COLSTR("%s %s",SCOLOR_AUTOCMT), ash.end, ash.cmnt, name);
}

//--------------------------------------------------------------------------
static void out_equ(bool indent, const char *name, uval_t off)
{
  if ( name != NULL )
  {
    gl_name = 0;
    char buf[MAXSTR];
    char *const end = buf + sizeof(buf);
    char *p = buf;
    if ( indent ) APPCHAR(p, end, ' ');
    APPEND(p, end, name);
    p = addblanks(buf, inf.indent-1);
    APPCHAR(p, end, ' ');
    p = tag_addstr(p, end, COLOR_KEYWORD, ash.a_equ);
    APPCHAR(p, end, ' ');
    p = tag_on(p, end, COLOR_NUMBER);
    p += btoa(p, end-p, off);
    tag_off(p, end, COLOR_NUMBER);
    MakeLine(buf, 0);
  }
}

//--------------------------------------------------------------------------
// output "equ" directive(s) if necessary
static int out_equ(ea_t ea)
{
  segment_t *s = getseg(ea);
  if ( s != NULL && s->type == SEG_IMEM && ash.a_equ != NULL )
  {
    char nbuf[MAXSTR];
    char *name = get_name(BADADDR, ea, nbuf, sizeof(nbuf));
    if ( name != NULL )
    {
      uval_t off = ea - get_segm_base(s);
      out_equ(false, name, off);
      const ioport_bit_t *bits = find_bits(off);
      if ( bits != NULL )
      {
        for ( int i=0; i < 8; i++ )
          out_equ(true, bits[i].name, i);
        MakeNull();
      }
    }
    else
    {
      MakeLine("");
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void idaapi data(ea_t ea)
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

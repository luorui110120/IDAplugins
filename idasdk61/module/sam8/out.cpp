
#include "sam8.hpp"
#include <fpro.h>
#include <diskio.hpp>

//----------------------------------------------------------------------
void OutRegString(bool isWorkingReg, bool isPair, int regNum, int regBit = -1) {
  char buf[256];

  // if it is a working register, output it with an R in front
  if ( isWorkingReg ) {
    if ( !isPair ) {
      qsnprintf(buf, sizeof(buf), "R%u", regNum);
    } else {
      qsnprintf(buf, sizeof(buf), "RR%u", regNum);
    }
  } else {
    // output either working or non-working reg
    if ( !isPair ) {
      // N.B. working registers start at 0xC0
      if ( regNum >= 0xC0 ) {
        qsnprintf(buf, sizeof(buf), "R%u", regNum - 0xC0);
      } else {
        qsnprintf(buf, sizeof(buf), "0%XH", regNum);
      }
    } else {
      // N.B. working registers start at 0xC0
      if ( regNum >= 0xC0 ) {
        qsnprintf(buf, sizeof(buf), "RR%u", regNum - 0xC0);
      } else {
        qsnprintf(buf, sizeof(buf), "0%XH", regNum);
      }
    }
  }
  out_register(buf);

  // output regBit if requested
  if ( regBit != -1 ) {
    qsnprintf(buf, sizeof(buf), ".%i", regBit);
    out_line(buf, COLOR_DEFAULT);
  }
}

//----------------------------------------------------------------------
void OutAddr(op_t& x, ea_t ea, ea_t off, bool isSigned = false) {
  // try and find the real name expression
  if ( !out_name_expr(x, ea, off) )
  {
    // work out flags correctly
    uint32 flags = OOF_ADDR | OOFW_16;
    if ( isSigned ) flags |= OOF_SIGNED;
    else flags |= OOFS_NOSIGN;

    // if name wasn't found, just output the value & add to noname queue
    OutValue(x, flags);
    QueueMark(Q_noName, cmd.ea);
  }
}


//----------------------------------------------------------------------
// generate the text representation of an operand

bool idaapi outop(op_t &x) {
  // output operands
  switch ( x.type ) {
  case o_reg:
    OutRegString(x.fl_workingReg, x.fl_regPair, x.reg);
    break;

  case o_reg_bit:
    OutRegString(x.fl_workingReg, x.fl_regPair, x.reg, (int)x.v_bit);
    break;

  case o_imm:
    out_symbol('#');
    OutValue(x, OOFS_IFSIGN | OOFW_IMM);
    break;

  case o_cmem_ind:
    // this needs special treatment... has to have a # in front of it
    out_symbol('#');
    OutAddr(x, x.addr, x.addr);
    break;

  case o_near:
  case o_cmem:
    OutAddr(x, x.addr, x.addr);
    break;

  case o_emem:
    OutAddr(x, SAM8_EDATASEG_START + x.addr, x.addr);
    break;

  case o_phrase:
    switch ( x.phrase ) {
    case fIndReg:
      out_symbol('@');
      OutRegString(x.fl_workingReg, x.fl_regPair, x.v_phrase_reg);
      break;

    case fIdxReg:
      out_symbol('#');
      OutRegString(false, false, x.v_phrase_reg);
      out_symbol('[');
      OutRegString(true, false, x.v_phrase_idxreg);
      out_symbol(']');
      break;
    }
    break;

  case o_displ:
    switch ( x.phrase ) {
  case fIdxCAddr:
      out_symbol('#');
      OutAddr(x, x.addr, x.addr, (x.addr > 0xffff));
      out_symbol('[');
      OutRegString(true, true, x.v_phrase_idxreg);
      out_symbol(']');
      break;

    case fIdxEAddr:
      out_symbol('#');
      OutAddr(x, SAM8_EDATASEG_START + x.addr, x.addr, (x.addr > 0xffff));
      out_symbol('[');
      OutRegString(true, true, x.v_phrase_idxreg);
      out_symbol(']');
      break;
    }
    break;
  }

  // OK
  return 1;
}




//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the 'cmd' structure
void idaapi out(void) {
  char buf[MAXSTR];

  // setup the output pointer
  init_output_buffer(buf, sizeof(buf));

  // output instruction mnemonics
  OutMnem();

  // check for JP/JR instruction with condition code
  // add the condition on as a pseudo operand if present
  if ( (cmd.itype == SAM8_JR ) ||
      ((cmd.itype == SAM8_JP) && (cmd.c_condition != ccNone))) {
    // sanity check
    if ( cmd.c_condition >= cc_last ) {
      warning("%a (%s): Internal error: bad condition code %i",
              cmd.ea, cmd.get_canon_mnem(), cmd.c_condition);
      return;
    }

    // output the condition code normally
    out_keyword(ccNames[cmd.c_condition]);
    out_symbol(',');
    OutChar(' ');
  }

  // output the first operand
  if ( cmd.Op1.type != o_void ) {
    out_one_operand(0);
  }

  // output the second operand
  if ( cmd.Op2.type != o_void ) {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);
  }

  // output the third operand
  if ( cmd.Op3.type != o_void ) {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(2);
  }

  // terminate the output string
  term_output_buffer();

  // ask to attach a possible user-defined comment to it
  gl_comm = 1;

  // pass the generated line to the kernel
  MakeLine(buf);
}


//--------------------------------------------------------------------------
// generate start of the disassembly
void idaapi header(void) {
  // generate standard header
  gen_cmt_line("Processor:        %s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);

  // output assembler-specific header
  if ( ash.header != NULL ) {
    for (const char **ptr=ash.header; *ptr != NULL; ptr++) {
      MakeLine(*ptr, 0);
    }
  }
}


// --------------------------------------------------------------------------
// generate start of segment
void idaapi segstart(ea_t ea) {
  // generate ORG directive if necessary
  if ( inf.s_org )
  {
    // get segment data
    segment_t *Sarea = getseg(ea);
    size_t org = size_t(ea - get_segm_base(Sarea));

    // generate line
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}


// --------------------------------------------------------------------------
// generate end of the disassembly
void idaapi footer(void) {
  char buf[MAXSTR];

  // if assembler supplies end statement, output it
  if ( ash.end != NULL ) {
    MakeNull();
    tag_addstr(buf, buf+sizeof(buf), COLOR_ASMDIR, ash.end);
    MakeLine(buf, inf.indent);
  }
}


// --------------------------------------------------------------------------
// customised address output
void idaapi out_data(ea_t ea) {
  // if addres is valid, use normal output function
  if ( isLoaded(ea) ) {
    intel_data(ea);
  } else {
    MakeLine(COLSTR("; db ?", SCOLOR_SYMBOL));
  }
}


#include "m32r.hpp"
#include <srarea.hpp>
#include <diskio.hpp>

// print register name
inline static void outreg(const int n) {
    out_register(ph.regNames[n]);
}

inline static const char *ptype_str(void) {
    switch ( ptype ) {
        case prc_m32r:        return "m32r";
        case prc_m32rx:       return "m32rx";
    }
    return NULL;
}

// generate header
void idaapi header(void) {
    gen_cmt_line("Processor:        %s [%s]", inf.procName, device);
    gen_cmt_line("Target assembler: %s", ash.name);

    if ( ash.header != NULL ) {
        for (const char **ptr=ash.header; *ptr != NULL; ptr++) {
            MakeLine(*ptr,0);
        }
    }

    char buf[MAXSTR];
    const char *n = ptype_str();

    // print the processor directive .m32r, or .m32rx
    if ( n ) {
        qsnprintf(buf, sizeof(buf), COLSTR(".%s", SCOLOR_ASMDIR), n);
        MakeLine(buf,0);
    }
}

// generate footer
void idaapi footer(void) {
    gen_cmt_line("end of file");
}

// output an operand
bool idaapi outop(op_t &op) {
    switch ( op.type ) {
        // register
        case o_reg:
            outreg(op.reg);
            break;

        // immediate
        case o_imm:
            {
                const ioport_t * port = find_sym(op.value);

                // this immediate is represented in the .cfg file
                if ( port != NULL ) {
                    // output the port name instead of the numeric value
                    out_line(port->name, COLOR_IMPNAME);
                }
                // otherwise, simply print the value
                else {
                    out_symbol('#');
                    OutValue(op, OOFW_IMM|OOF_SIGNED);
                }
            }
            break;

        // displ @(imm, reg)
        case o_displ:
            out_symbol('@');
            out_symbol('(');
            OutValue(op, OOF_SIGNED | OOF_ADDR | OOFW_32);
            out_symbol(',');
            OutChar(' ');
            outreg(op.reg);
            out_symbol(')');
            break;

        // address
        case o_near:
            {
                if ( !out_name_expr(op, toEA(cmd.cs, op.addr), op.addr) )
                    OutValue(op, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
            }
            break;

        // phrase
        case o_phrase:
            switch ( op.specflag1 ) {
                // @R
                case fRI:
                    out_symbol('@');
                    if ( isDefArg(uFlag, op.n) ) {
                        out_symbol('(');
                        OutValue(op, 0);   // will print 0
                        out_symbol(',');
                        OutChar(' ');
                        outreg(op.reg);
                        out_symbol(')');
                    }
                    else {
                        outreg(op.reg);
                    }
                    break;

                // @R+
                case fRIBA:
                    out_symbol('@');
                    outreg(op.reg);
                    out_symbol('+');
                    break;

                // @+R
                case fRIAA:
                    out_symbol('@');
                    out_symbol('+');
                    outreg(op.reg);
                    break;

                // @-R
                case fRIAS:
                    out_symbol('@');
                    out_symbol('-');
                    outreg(op.reg);
                    break;
            }
            break;
    }
    return 1;
}

// output an instruction and its operands
void idaapi out(void) {
    char buf[MAXSTR];

    init_output_buffer(buf, sizeof(buf));     // setup the output pointer

    // if this DSP instruction in executed in parallel with a NOP instruction
    // (example: nop || machi r1, r2), first print the NOP.
    if ( cmd.segpref & NEXT_INSN_PARALLEL_DSP ) {
       out_line("nop", COLOR_INSN);
       OutChar(' ');
       out_symbol('|');
       out_symbol('|');
       OutChar(' ');
    }

    char postfix[3];                        // postfix to eventually insert after the insn name
    postfix[0] = '\0';                      // postfix is null by default

    // use synthetic option is selected
    if ( use_synthetic_insn() ) {

         if ( cmd.segpref & SYNTHETIC_SHORT )
           qstrncpy(postfix, (cmd.itype == m32r_ldi ? "8" : ".s"), sizeof(postfix));
         if ( cmd.segpref & SYNTHETIC_LONG )
           qstrncpy(postfix, (cmd.itype == m32r_ldi ? "16" : ".l"), sizeof(postfix));
    }

    OutMnem(8, postfix);

    out_one_operand(0);                   // output the first operand

    if ( cmd.Op2.type != o_void ) {
        out_symbol(',');
        OutChar(' ');
        out_one_operand(1);               // output the second operand
    }

    if ( cmd.Op3.type != o_void ) {
        out_symbol(',');
        OutChar(' ');
        out_one_operand(2);               // output the third operand
    }

    // output a character representation of the immediate values
    // embedded in the instruction as comments
    if ( isVoid(cmd.ea,uFlag,0)) OutImmChar(cmd.Op1 );
    if ( isVoid(cmd.ea,uFlag,1)) OutImmChar(cmd.Op2 );
    if ( isVoid(cmd.ea,uFlag,2)) OutImmChar(cmd.Op3 );

    // print a parallel NOP instruction unless the current instruction
    // is either push or pop (in this special case, nop cannot be executed in //)
    if ( (cmd.itype != m32r_push && cmd.itype != m32r_pop) && cmd.segpref & NEXT_INSN_PARALLEL_NOP ) {
        // don't print NOP if the instruction was ld/st reg, fp, and has been converted to ld/st reg, @(arg, fp)
        // (in other words, in the second operand is a stack variable).
        // because the o_displ form of ld/st insn is 32 bits, and cannot handle a parallel nop.
        if ( (cmd.itype != m32r_ld && cmd.itype != m32r_st) || !isStkvar1(uFlag) ) {
            if ( cmd.Op1.type != o_void) OutChar(' ' );
            out_symbol('|');
            out_symbol('|');
            OutChar(' ');
            out_line("nop", COLOR_INSN);
        }
    }

    if ( cmd.segpref & NEXT_INSN_PARALLEL_OTHER ) {
        if ( cmd.Op1.type != o_void) OutChar(' ' );
        out_symbol('|');
        out_symbol('|');
        out_symbol('\\');
    }

    term_output_buffer();                 // terminate the output string
    gl_comm = 1;                          // ask to attach a possible user-
                                          // defined comment to it
    MakeLine(buf);                        // pass the generated line to the
                                          // kernel
}

// generate segment header
void idaapi gen_segm_header(ea_t ea)
{
    segment_t *Sarea = getseg(ea);

    char sname[MAXNAMELEN];
    get_segm_name(Sarea, sname, sizeof(sname));
    char *segname = sname;

    if ( *segname == '_' )
        *segname = '.';

    printf_line(0, COLSTR(".section %s", SCOLOR_ASMDIR), segname);
}

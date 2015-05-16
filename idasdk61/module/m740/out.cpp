
#include "m740.hpp"

// output register name
inline static void outreg(const int n) { out_register(ph.regNames[n]); }

// output an address
static void outaddr(op_t &op, const bool replace_with_label = true) {
    bool ind = is_addr_ind(op);      // is operand indirect ?
    bool sp = is_addr_sp(op);        // is operand special page ?

    int size = 16;  // operand is 16 bits long

    if ( ind)    out_symbol('(' );
    if ( sp)     { out_symbol('\\' ); size = 8; /* just display the first 8 bits */ }

    if ( !out_name_expr(op, toEA(cmd.cs, op.addr), op.addr) || !replace_with_label)
    {
        if ( replace_with_label) out_tagon(COLOR_ERROR );
        OutValue(op, OOF_ADDR | OOFS_NOSIGN | (size < 16 ? OOFW_8 : OOFW_16) );
        if ( replace_with_label) out_tagoff(COLOR_ERROR );
    }

    if ( ind)    out_symbol(')' );
}

// output a displacement
static void outdispl(void) {
    if ( is_displ_indx() ) {
        out_symbol('(');
        outaddr(cmd.Op1, false);
        out_symbol(',');
        if ( !(ash.uflag & UAS_INDX_NOSPACE)) OutChar(' ' );
        outreg(cmd.Op1.reg);
        out_symbol(')');
        return;
    }
    if ( is_displ_indy() ) {
        out_symbol('(');
        outaddr(cmd.Op1, false);
        out_symbol(')');
        out_symbol(',');
        OutChar(' ');
        outreg(cmd.Op1.reg);
        return;
    }
    if ( is_displ_zpx() || is_displ_zpy() || is_displ_absx() || is_displ_absy() ) {
        outaddr(cmd.Op1, false);
        out_symbol(',');
        OutChar(' ');
        outreg(cmd.Op1.reg);
        return;
    }
    INTERR(10023);
}

// generate header
void idaapi header(void) {
    gen_cmt_line("Processor:            %s [%s]", inf.procName, device);
    gen_cmt_line("Target assembler:     %s", ash.name);

    if ( ash.header != NULL ) {
        for (const char **ptr = ash.header; *ptr != NULL; ptr++) {
            MakeLine(*ptr,0);
        }
    }
}

// generate footer
void idaapi footer(void) {
    char buf[MAXSTR];
    char *const end = buf + sizeof(buf);
    if ( ash.end != NULL ) {
        MakeNull();
        register char *p = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
        char name[MAXSTR];
        if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL ) {
            APPCHAR(p, end, ' ');
            APPEND(p, end, name);
        }
        MakeLine(buf, inf.indent);
    }
    else {
        gen_cmt_line("end of file");
    }
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
            if ( (op.specflag1 & OP_IMM_BIT) == 0 )
              out_symbol('#');
            OutValue(op, OOFW_IMM);
            break;

        // data / code memory address
        case o_near:
        case o_mem:
            outaddr(op);
            break;

        // displ
        case o_displ:
            outdispl();
            break;

        // ignore void operands
        case o_void:
            break;

        default:
            INTERR(10024);
    }
    return 1;
}

// outputs an instruction
void idaapi out(void) {
    char buf[MAXSTR];

    init_output_buffer(buf, sizeof(buf));

    OutMnem();
    out_one_operand(0);        // output the first operand

    if ( cmd.Op2.type != o_void ) {
        out_symbol(',');
        OutChar(' ');
        out_one_operand(1);
    }

    if ( cmd.Op3.type != o_void ) {
        out_symbol(',');
        OutChar(' ');
        out_one_operand(2);
    }

    // output a character representation of the immediate values
    // embedded in the instruction as comments
    if ( isVoid(cmd.ea,uFlag,0)) OutImmChar(cmd.Op1 );
    if ( isVoid(cmd.ea,uFlag,1)) OutImmChar(cmd.Op2 );
    if ( isVoid(cmd.ea,uFlag,2)) OutImmChar(cmd.Op3 );

    term_output_buffer();                   // terminate the output string
    gl_comm = 1;                            // ask to attach a possible user-
                                            // defined comment to it
    MakeLine(buf);                          // pass the generated line to the
                                            // kernel
}

// generate segment header
void idaapi gen_segm_header(ea_t ea) {
    segment_t *Sarea = getseg(ea);

    char sname[MAXNAMELEN];
    get_segm_name(Sarea, sname, sizeof(sname));
    char *segname = sname;

    if ( ash.uflag & UAS_SEGM )
        printf_line(inf.indent, COLSTR("SEGMENT %s", SCOLOR_ASMDIR), segname);
    else if ( ash.uflag & UAS_RSEG )
        printf_line(inf.indent, COLSTR("RSEG %s", SCOLOR_ASMDIR), segname);

    ea_t orgbase = ea - get_segm_para(Sarea);
    if ( orgbase != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), orgbase);
      printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
}

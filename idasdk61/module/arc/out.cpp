/*
 *                      Interactive disassembler (IDA).
 *                      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                      ALL RIGHTS RESERVED.
 *                                                                                                                      E-mail: ig@estar.msk.su, ig@datarescue.com
 *                                                                                                                      FIDO:    2:5020/209
 *
 */

#include "arc.hpp"
#include <fpro.h>
#include <diskio.hpp>

        /* condition codes */
static const char ccode[][4] =
{
  "", "z", "nz", "p",
  "n", "c", "nc", "v",
  "vc", "gt", "ge", "lt",
  "le", "hi", "ls", "pnz",
  "?", "?", "?", "?",
  "?", "?", "?", "?",
  "?", "?", "?", "?",
  "?", "?", "?", "?"
};

        /* jump delay slot codes */
static const char ncode[][4]={"", ".d", ".jd", "??"};

        /* outputs an operand 'x' */
bool idaapi outop(op_t &x)
{
// const char *ptr;
  ea_t v;
        switch ( x.type )
        {
        case o_reg:
                out_register(ph.regNames[x.reg]);
                break;
        case o_imm:
                OutValue(x, OOFS_IFSIGN | OOFW_IMM);
                break;
        case o_mem:
        case o_near:
                v=toEA(cmd.cs, x.addr);
                if ( !out_name_expr(x, v, x.addr) )
                {
                        OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
                        QueueMark(Q_noName, cmd.ea);
                        break;
                }
                break;
        default:
                out_symbol('?');
                break;
        }
        return 1;
}

void idaapi out(void)
{
        char buf[MAXSTR];
        char postfix[MAXSTR]="";

        init_output_buffer(buf, sizeof(buf));
                /* if we have a load or store instruction, flags are used a bit different */
        if ( cmd.itype<=ARC_store_instructions )
        {
                switch ( (cmd.auxpref&6)>>1 )
                {
                case 0:
                        qstrncat(postfix, "", sizeof(postfix)); break;
                case 1:
                        qstrncat(postfix, "b", sizeof(postfix)); break;
                case 2:
                        qstrncat(postfix, "w", sizeof(postfix)); break;
                default:
                        qstrncat(postfix, "?", sizeof(postfix)); break;
                }
                if ( cmd.auxpref&1 )
                        qstrncat(postfix, ".x", sizeof(postfix));
                if ( cmd.auxpref&8 )
                        qstrncat(postfix, ".a", sizeof(postfix));
                if ( cmd.auxpref&32 )
                        qstrncat(postfix, ".di", sizeof(postfix));
        } else if ( cmd.auxpref&31 )
        {
                if ( (cmd.itype != ARC_b) && (cmd.itype != ARC_lp) && (cmd.itype != ARC_bl) && (cmd.itype != ARC_j) && (cmd.itype != ARC_jl) )
                        qstrncat(postfix, ".", sizeof(postfix));
                qstrncat(postfix, ccode[cmd.auxpref&31], sizeof(postfix));
        }
        if ( (cmd.itype == ARC_b) || (cmd.itype == ARC_lp) || (cmd.itype == ARC_bl) || (cmd.itype == ARC_j) || (cmd.itype == ARC_jl) )  // branch instruction
                qstrncat(postfix, ncode[(cmd.auxpref>>5)&3], sizeof(postfix));
        else
                if ( cmd.auxpref&(1<<8) && (cmd.itype!=ARC_flag) )              // flag implicitly sets this bit
                        qstrncat(postfix, ".f", sizeof(postfix));

        OutMnem(8, postfix);                                                                                                            // output instruction mnemonics

        if ( cmd.itype<=ARC_store_instructions )
        {
                        /* load/store operations have another syntax with braces */
                out_one_operand(0);                                                                      // output the first operand
                out_symbol(',');
                OutChar(' ');
                out_symbol('[');

                if ( cmd.Op2.type != o_void)
                {
                        out_one_operand(1);                                                              // output the second operand
                }

                if ( cmd.Op3.type != o_void)
                {
                        out_symbol(',');
                        OutChar(' ');
                        out_one_operand(2);                                                              // output the third operand
                }
                out_symbol(']');
        } else
        {
                if ( cmd.Op1.type != o_void)
                        out_one_operand(0);                                                                      // output the first operand

                if ( cmd.Op2.type != o_void)
                {
                        out_symbol(',');
                        OutChar(' ');
                        out_one_operand(1);                                                              // output the second operand
                }

                if ( cmd.Op3.type != o_void)
                {
                        out_symbol(',');
                        OutChar(' ');
                        out_one_operand(2);                                                              // output the third operand
                }
        }


        // output a character representation of the immediate values
        // embedded in the instruction as comments

        if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
        if ( isVoid(cmd.ea,uFlag,1) ) OutImmChar(cmd.Op2);
        if ( isVoid(cmd.ea,uFlag,2) ) OutImmChar(cmd.Op3);

        term_output_buffer();
        gl_comm = 1;                                                                                                    // ask to attach a possible user-
                                                                                                                                                                // defined comment to it
        MakeLine(buf);                                                                                          // pass the generated line to the
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
        char name[MAXNAMELEN];
        segment_t *Sarea = getseg(ea);
        get_segm_name(Sarea, name, sizeof(name));
        printf_line(0, COLSTR(".section %s", SCOLOR_ASMDIR), name);
        if ( inf.s_org )
        {
                adiff_t org = ea - get_segm_base(Sarea);
                if ( org!=0 )
                {
                  char buf[MAX_NUMBUF];
                  btoa(buf, sizeof(buf), org);
                  printf_line(0, COLSTR("%s %s",SCOLOR_ASMDIR), ash.origin, buf);
                }
        }
}

//--------------------------------------------------------------------------
// generate end of the disassembly

void idaapi footer(void)
{
        char buf[MAXSTR];
        char *const end = buf + sizeof(buf);
        MakeNull();
        register char *p = tag_addstr(buf, end, COLOR_ASMDIR, ".end");
        char name[MAXSTR];
        if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL )
        {
                APPCHAR(p, end, ' ');
                APPCHAR(p, end, '#');
                APPEND(p, end, name);
        }
        MakeLine(buf, inf.indent);
}

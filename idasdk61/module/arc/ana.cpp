/*
 *                      Interactive disassembler (IDA).
 *                      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                      ALL RIGHTS RESERVED.
 *                                                                                                                      E-mail: ig@estar.msk.su, ig@datarescue.com
 *                                                                                                                      FIDO:    2:5020/209
 *
 */

        /* ARC code, based on IDA SDK, written by Felix Domke <tmbinc@gmx.net> */

#include "arc.hpp"
#include <frame.hpp>

/*
                this code might be seen as a bit messy, but i like it anyway.

                What i'm doing here is trying to fit the instruction in a generic
                struct, insn_t. The actual decoding of some Flags and specalities
                is done in the output-routine.

                This is mainly because i just had 16 bits at auxpref (and another,
                unused, 8 bits at segpref) available for the internal representation
                of the instruction.

                Another method would be to define bitfields in auxpref for the condition-
                codes and the other flags, maybe along with instructions about braces (in
                the ld, st,..-instructions). At the moment this is deduced from the
                instruction type itself (itype) in the output.

                I think this solution here is a nice compromise.
                Auxpref ALWAYS contains the bitfield of the flags, even if an instruction
                uses immediate arguments. in this case, auxpref is "reconstructed", so
                that the output doesn't have to care about this.

                Comments don't make code better, so i'll stop here.
*/


/*
        doRegisterOperand converts the 6 bit field 'code' to an IDA-"op_t"-operand.

        'd' is the maybe-used (signed) immediate in the lowest 9 bits, li is the
        long-immediate which is loaded in the instruction decoding, since it's
        loaded only once, even if an instructions uses multiple times a long immediate

        when it's all about a branch (isbranch is true), we have to multiply the absolute
        address by 4, since it's granularity are words then (and not bytes)

        FYI:
                register code 61 means "short immediate with .f-flag set", 63 "short immediate
                without .f-flag" and 62 means "long immediate (4 bytes following the instruction,
                making the instruction 8 bytes long (cmd.size)).
*/

void doRegisterOperand(int code, op_t &op, int d, int li, int isbranch)
{
                /* we always deal with double words, exceptions are load/stores
                   with 8 or 16 bits. these are covered by the instruction decoding */

        op.dtyp=dt_dword;
        if ( (code==61) || (code==63) ) // short immediate with/wo flags
        {
                if ( isbranch )
                {
                        op.type=o_near;
                        op.addr=d*4;
                } else
                {
                        op.type=o_imm;
                        op.value=d;
                }
        } else if ( code==62 )  // long immediate
        {
                if ( isbranch )
                {
                        op.type=o_near;
                                /* the upper 7 bits containing processor flags to set  */
                                /* they are handled in the instruction decoding, since */
                                /* they produce a second (ida-)operand */
                        op.addr=(li&0x1FFFFFF)*4;
                } else
                {
                        op.type=o_imm;
                        op.value=li;
                }
                op.offb=4;
        } else  /* just a register */
        {
                op.type=o_reg;
    op.reg=uint16(code);
        }
}

/*
        doBranchOperand handles pc-relativ word offsets.
        nothing special here.
*/
void doBranchOperand(op_t &op, int l)
{
        op.dtyp=dt_dword;
        op.type=o_near;
        op.addr=cmd.ip+l*4+4;
        op.offb=0;
}

void doRegisterInstruction()
{
        uint32 code = get_long(cmd.ea);

        int i = (code>>27)&31;
        int a = (code>>21)&63;
        int b = (code>>15)&63;
        int c = (code>>9)&63;

                /* the (maybe used?) short immediate value */
        int d = code&0x1FF;
        if ( d>=0x100 )
                d-=0x200;

        cmd.size=4;

                /* store the flags. if there are actually no flags at that place , they */
                /* will be reconstructed later */
        cmd.auxpref=code&0x1FF;

        switch ( i )
        {
        case 0: // LD register+register
                cmd.itype=ARC_ld0;
                break;
        case 1: // LD register+offset, LR
                if ( code & (1<<13) )
                        cmd.itype=ARC_lr;
                else
                        cmd.itype=ARC_ld1;
                break;
        case 2: // ST, SR
                if ( code & (1<<25) )
                        cmd.itype=ARC_sr;
                else
                        cmd.itype=ARC_st;
                break;
        case 3: // single operand instructions
                switch ( c )
                {
                case 0:
                        cmd.itype=ARC_flag;
                        a=b;    // flag has no 'a' operand, so we're moving the b-operand to a.
                        break;
                case 1:
                        cmd.itype=ARC_asr; break;
                case 2:
                        cmd.itype=ARC_lsr; break;
                case 3:
                        cmd.itype=ARC_ror; break;
                case 4:
                        cmd.itype=ARC_rrc; break;
                case 5:
                        cmd.itype=ARC_sexb; break;
                case 6:
                        cmd.itype=ARC_sexw; break;
                case 7:
                        cmd.itype=ARC_extb; break;
                case 8:
                        cmd.itype=ARC_extw; break;
                }
                c=-1;   // c operand is no real operand, so don't try to convert it.
                break;
        case 7: // Jcc, JLcc
                cmd.itype=ARC_j; break;
        case 8: // ADD
                cmd.itype=ARC_add; break;
        case 9: // ADC
                cmd.itype=ARC_adc; break;
        case 10: // SUB
                cmd.itype=ARC_sub; break;
        case 11: // ADC
                cmd.itype=ARC_adc; break;
        case 12: // AND
                cmd.itype=ARC_and; break;
        case 13: // OR
                cmd.itype=ARC_or; break;
        case 14: // BIC
                cmd.itype=ARC_bic; break;
        case 15: // XOR
                cmd.itype=ARC_xor; break;
        }

        int immediate=0, noop3=0, isnop=0;

        if ( (a==61) || (b==61) || (c==61) )
                cmd.auxpref=1<<8;       // .f

        if ( (b == 63) || (c == 63) )
                cmd.auxpref=0;

        if ( (b == 62) || (c == 62) )
        {
                immediate=get_long(cmd.ea+4);
                cmd.size+=4;
        }

        if ( cmd.itype==ARC_flag )      // special handling for flag, since it's a-operand is a source here
                b=-1;

                /* pseudo instruction heuristic:

                        we have some types of pseudo-instructions:

                                (rS might be an immediate)
                        insn                    will be coded as
                        move rD, rS             and rD, rS, rS
                        asl rD, rS              add rD, rS, rS
                        lsl rD, rS              add rD, rS, rS (the same as asl, of course...)
                        rlc rD, rS              adc.f rD, rS, rS
                        rol rD, rS              add.f rD, rS, rS; adc rD, rD, 0
                        nop                     xxx 0, 0, 0
                */

                /* mov */
        if ( (b==c) && ((cmd.itype==ARC_and) || (cmd.itype==ARC_or)) )
        {
                noop3=1;
                cmd.itype=ARC_move;
        }
                /* asl, lsl */
        if ( (b==c) && (cmd.itype==ARC_add) )
        {
                noop3=1;
                cmd.itype=ARC_lsl;
        }
                /* rlc */
        if ( (b==c) && (cmd.itype==ARC_adc) )
        {
                noop3=1;
                cmd.itype=ARC_rlc;
        }
                /* rol - we somehow have to check the insn byte too
        if ( (b==c) && (cmd.itype==ARC_add) && (cmd.auxpref&(1<<8) && ...  )
        {
                noop3=1;
                cmd.itype=ARC_rlc;
        }
                */

        if ( (i>=8) && (a>62) && !(cmd.auxpref&(1<<8)) )        // 3 operands, but target is immediate and no flags to set
                isnop=1;

        if ( !isnop )
        {
                if ( cmd.itype==ARC_ld0 )
                {
                        doRegisterOperand(a, cmd.Op1, d, immediate, 0);
                        doRegisterOperand(b, cmd.Op2, d, immediate, 0);
                        doRegisterOperand(c, cmd.Op3, d, immediate, 0);
                        /*
                                in a load-insn the second operand is often an memory reference
                        */
                        if ( cmd.Op2.type==o_imm )
                        {
                                cmd.Op2.type=o_mem;
                                cmd.Op2.addr=cmd.Op2.value;
                        }
                        /*
                                the third operand, mostly an offset into a struct or just 0
                        */
                        if ( cmd.Op3.type==o_imm )
                        {
                                if ( !cmd.Op3.value )
                                        cmd.Op3.type=o_void;
                        }
                } else if ( (cmd.itype==ARC_ld1) || (cmd.itype==ARC_lr) || (cmd.itype==ARC_st) || (cmd.itype==ARC_sr) )
                {
                                /* fetch the flag-bits from the right location */
                        if ( cmd.itype==ARC_ld1 )
                                cmd.auxpref=(code>>9)&0x3F;
                        else if ( cmd.itype==ARC_st )
                                cmd.auxpref=(code>>21)&0x3F;
                        else
                                cmd.auxpref=0;
                        if ( (cmd.itype==ARC_st) || (cmd.itype==ARC_sr) )
                        {
                                        /* in a move to special register or load from special register,
                                           we have the target operand somewhere else */
                                a=c;
                        /*      c=-1; not used anyway */
                        }
                        doRegisterOperand(a, cmd.Op1, d, immediate, 0);
                        doRegisterOperand(b, cmd.Op2, d, immediate, 0);
                        if ( (code&0x1FF) && (cmd.itype!=ARC_lr) && (cmd.itype!=ARC_sr) )
                        {
                                cmd.Op3.dtyp=dt_dword;
                                cmd.Op3.type=o_imm;
                                cmd.Op3.value=d;
                        } else
                                cmd.Op3.type=o_void;
                } else if ( i==7 )
                {
                                /* the jump (absolute) instruction, with a special imm-encoding */
                        doRegisterOperand(b, cmd.Op1, d, immediate, 1);
                } else
                {
                        if ( a != -1 )
                                doRegisterOperand(a, cmd.Op1, 0, immediate, 0);
                                        /* this is a bugfix for the gnu-as: long immediate must be equal, while short */
                                        /* immediates don't have to. */
                        if ( b != -1 )
                                doRegisterOperand(b, cmd.Op2, d, immediate, 0);
                        if ( (c != -1 ) && (!noop3) )
                                doRegisterOperand(c, cmd.Op3, d, immediate, 0);
                }
        } else
        {
                cmd.itype=ARC_nop;
                cmd.auxpref=0;
        }
}

void doBranchInstruction()
{
        uint32 code = get_long(cmd.ea);
        cmd.size=4;
        int i = (code>>27)&31;

        int l = (code>>7)&0xFFFFF;      // note: bits 21..2, so it's in WORDS

        if ( l>=0x80000 )               // convert to signed
                l=l-0x100000;

        doBranchOperand(cmd.Op1, l);

        switch ( i )
        {
        case 4: // Bcc
                cmd.itype=ARC_b; break;
        case 5: // BLcc
                cmd.itype=ARC_bl; break;
        case 6: // LPcc
                cmd.itype=ARC_lp; break;
        }
        cmd.auxpref=code&0x1FF;
}

//----------------------------------------------------------------------
// analyze an instruction
int idaapi ana(void)
{
        if ( cmd.ea&3 )
                return 0;
        cmd.Op1.dtyp = dt_dword;
        cmd.Op2.dtyp = dt_dword;
        cmd.Op3.dtyp = dt_dword;

        uint32 code = get_long(cmd.ea);

        int i = (code>>27)&31;

        cmd.itype=0;
        cmd.size=4;

        switch ( i )
        {
        case 0: // LD register+register
        case 1: // LD register+offset, LR
        case 2: // ST, SR
        case 3: // single operand instructions
                doRegisterInstruction();
                break;
        case 4: // Bcc
        case 5: // BLcc
        case 6: // LPcc
                doBranchInstruction();
                break;
        case 7: // Jcc, JLcc
        case 8: // ADD
        case 9: // ADC
        case 10: // SUB
        case 11: // ADC
        case 12: // AND
        case 13: // OR
        case 14: // BIC
        case 15: // XOR
                doRegisterInstruction();
                break;
        }

        return cmd.size;
}

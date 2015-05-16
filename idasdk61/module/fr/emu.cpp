
#include "fr.hpp"

// Analyze an instruction
static ea_t next_insn(ea_t ea) {
    if ( decode_insn(ea) == 0 )
        return 0;
    ea += cmd.size;
    return ea;
}

// Emulate an operand.
static void handle_operand(op_t &op) {
    bool offset = false;
    switch ( op.type ) {
        case o_near:
            ua_add_cref(op.offb, toEA(cmd.cs, op.addr), (cmd.itype == fr_call) ? fl_CN : fl_JN);
            break;

        case o_mem:
            {
                enum dref_t mode = dr_U;

                if ( op.specflag1 & OP_ADDR_R )           mode = dr_R;
                else if ( op.specflag1 & OP_ADDR_W )      mode = dr_W;

                ea_t ea = toEA(cmd.cs, op.addr);
                ua_add_dref(op.offb, ea, mode);
                ua_dodata2(op.offb, ea, op.dtyp);
            }
            break;

        case o_imm:
            // if current insn is ldi:32 #imm, r1
            // and next insn is call @r1,
            // replace the immediate value with an offset.
            if (cmd.itype == fr_ldi_32 &&
                cmd.Op1.type == o_imm &&
                cmd.Op2.type == o_reg)
            {
                const int callreg = cmd.Op2.reg;
                insn_t cmd_backup = cmd;
                if ( next_insn(cmd.ea + cmd.size ) > 0 &&
                    cmd.itype == fr_call &&
                    cmd.Op1.type == o_phrase &&
                    cmd.Op1.specflag2 == fIGR &&
                    cmd.Op1.reg == callreg)
                {
                    offset = true;
                }
                const ea_t from = cmd.ea;
                cmd = cmd_backup;
                if ( !isDefArg(uFlag, 0) && offset && set_offset(cmd.ea, 0, 0) )
                    add_cref(from, toEA(cmd.cs, cmd.Op1.value), fl_CN);
            }
            doImmd(cmd.ea);
            if ( !offset )
                // if the value was converted to an offset, then create a data xref:
                if ( isOff(uFlag, op.n) )
                  ua_add_off_drefs2(op, dr_O, 0);

            // create stack variables if necessary
            {
                bool ok = false;
                // ldi8 #our_value, R1
                // extsb R1
                // addn R14, R1
                if (cmd.itype == fr_ldi_8 &&
                    cmd.Op2.type == o_reg &&
                    cmd.Op2.reg == rR1)
                {
                    insn_t current_insn = cmd;
                    next_insn(cmd.ea + cmd.size);
                    if (cmd.itype == fr_extsb &&
                        cmd.Op1.type == o_reg &&
                        cmd.Op1.reg == rR1)
                    {
                        ok = true;
                    }
                    if ( ok ) {
                        ok = false;
                        next_insn(cmd.ea + cmd.size);
                        if (cmd.itype == fr_addn &&
                            cmd.Op1.type == o_reg &&
                            cmd.Op1.reg == rR14 &&
                            cmd.Op2.type == o_reg &&
                            cmd.Op2.reg == rR1)
                        {
                            ok = true;
                        }
                    }
                    cmd = current_insn;
                }
                // ldi32 #our_value, Ri
                // addn R14, Ri
                //
                // (where Ri is either R1 or R2)
                else if (cmd.itype == fr_ldi_32 &&
                    cmd.Op2.type == o_reg &&
                    (cmd.Op2.reg == rR1 || cmd.Op2.reg == rR2))
                {
                    ushort the_reg = cmd.Op2.reg;
                    insn_t current_insn = cmd;
                    next_insn(cmd.ea + cmd.size);
                    if (cmd.itype == fr_addn &&
                        cmd.Op1.type == o_reg &&
                        cmd.Op1.reg == rR14 &&
                        cmd.Op2.type == o_reg &&
                        cmd.Op2.reg == the_reg)
                    {
                        ok = true;
                    }
                    cmd = current_insn;
                }

                if ( ok && may_create_stkvars() && !isDefArg(uFlag, op.n) ) {
                    func_t *pfn = get_func(cmd.ea);
                    if ( pfn != NULL && pfn->flags & FUNC_FRAME ) {
                        if ( ua_stkvar2(op, op.value, 0) ) {
                            op_stkvar(cmd.ea, op.n);
                        }
                    }
                }
            }
            break;

        case o_displ:
        case o_phrase:  // XXX
        case o_reglist:
        case o_void:
        case o_reg:
            break;

        default:
            INTERR(10017);
    }
}

inline bool is_stop (void) {
    uint32 feature = cmd.get_canon_feature();
    return (feature & CF_STOP) != 0;
}

// Emulate an instruction.
int idaapi emu(void) {
    bool flow = !is_stop() || (cmd.auxpref & INSN_DELAY_SHOT);
    if ( flow )
    {
      insn_t cmd_backup = cmd;
      if ( decode_prev_insn(cmd.ea) != BADADDR ) {
          flow = !(is_stop() && (cmd.auxpref & INSN_DELAY_SHOT));
      }
      cmd = cmd_backup;
    }

    if ( cmd.Op1.type != o_void)            handle_operand(cmd.Op1 );
    if ( cmd.Op2.type != o_void)            handle_operand(cmd.Op2 );
    if ( cmd.Op3.type != o_void)            handle_operand(cmd.Op3 );
    if ( cmd.Op4.type != o_void)            handle_operand(cmd.Op4 );

    if ( flow )
        ua_add_cref(0, cmd.ea + cmd.size, fl_F);

    return 1;
}

// Create a function frame
bool idaapi create_func_frame(func_t *pfn) {
    ushort savedreg_size = 0;
    uint32 args_size = 0;
    uint32 localvar_size;

    ea_t ea = pfn->startEA;

    // detect multiple ``st Ri, @-R15'' instructions.
    while ( (ea = next_insn(ea) ) != 0 &&
       cmd.itype == fr_st &&
       cmd.Op1.type == o_reg &&
       cmd.Op2.type == o_phrase &&
       cmd.Op2.reg == rR15 &&
       cmd.Op2.specflag2 == fIGRM)
    {
        savedreg_size += 4;
#if defined(__DEBUG__)
        msg("0x%a: detected st Rx, @-R15\n", ea);
#endif /* __DEBUG__ */
    }

    // detect enter #nn
    if ( cmd.itype == fr_enter ) {
        // R14 is automatically pushed by fr_enter
        savedreg_size += 4;
        localvar_size = uint32(cmd.Op1.value - 4);
#if defined(__DEBUG__)
        msg("0x%a: detected enter #0x%a\n", ea, cmd.Op1.value);
#endif /* __DEBUG__ */
    }
    // detect mov R15, R14 + ldi #imm, R0 instructions
    else {
        if (cmd.itype != fr_mov ||
            cmd.Op1.type != o_reg ||
            cmd.Op1.reg != rR15 ||
            cmd.Op2.type != o_reg ||
            cmd.Op2.reg != rR14)
        {
            goto bad_func;
        }
        /*ea = */next_insn(ea);
        if ( (cmd.itype == fr_ldi_20 || cmd.itype == fr_ldi_32 ) &&
            cmd.Op1.type == o_imm &&
            cmd.Op2.type == o_reg &&
            cmd.Op2.reg == rR0)
        {
            localvar_size = uint32(cmd.Op1.value);
        }
        else
            goto bad_func;
#if defined(__DEBUG__)
        msg("0x%a: detected ldi #0x%a, R0\n", ea, cmd.Op1.value);
#endif /* __DEBUG__ */
    }

    // XXX we don't care about near/far functions, because currently
    // we don't know how to detect them ;-)

    pfn->flags |= FUNC_FRAME;
    return add_frame(pfn, localvar_size, savedreg_size, args_size);

bad_func:
    return 0;
}

int idaapi is_sp_based(const op_t &) {
    return OP_SP_ADD | OP_FP_BASED;
}

int idaapi is_align_insn(ea_t ea) {
    return get_byte(ea) == 0;
}

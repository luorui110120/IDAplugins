
#include "st9.hpp"

static bool flow;

// Emulate an operand.
static void handle_operand(op_t &op, bool write) {
    switch ( op.type ) {
        // Code address
        case o_near:
            {
                cref_t mode;
                ea_t ea = toEA(cmd.cs, op.addr);

                // call or jump ?
                if ( cmd.itype == st9_call || cmd.itype == st9_calls )
                {
                  if ( !func_does_return(ea) )
                    flow = false;
                  mode = fl_CN;
                }
                else
                {
                  mode = fl_JN;
                }
                ua_add_cref(op.offb, ea, mode);
            }
            break;

        // Memory address
        case o_mem:
            {
                enum dref_t mode;

                mode = write ? dr_W: dr_R;

                ua_add_dref(op.offb, toEA(cmd.cs, op.addr), mode);
                ua_dodata2(op.offb, op.addr, op.dtyp);
            }
            break;

        // Immediate value
        case o_imm:
            doImmd(cmd.ea);
            // create a comment if this immediate is represented in the .cfg file
            {
                const ioport_t * port = find_sym(op.value);

                if ( port != NULL && !has_cmt(uFlag) ) {
                    set_cmt(cmd.ea, port->cmt, false);
                }
            }
            // if the value was converted to an offset, then create a data xref:
            if ( isOff(uFlag, op.n) )
              ua_add_off_drefs2(op, dr_O, 0);
            break;

        // Displacement
        case o_displ:
            doImmd(cmd.ea);
            if ( isOff(uFlag, op.n) ) {
                ua_add_off_drefs2(op, dr_O, OOF_ADDR);
                ua_dodata2(op.offb, op.addr, op.dtyp);
            }

            // create stack variables if required
            if ( may_create_stkvars() && !isDefArg(uFlag, op.n) ) {
                func_t *pfn = get_func(cmd.ea);
                if ( pfn != NULL && pfn->flags & FUNC_FRAME ) {
                    if ( ua_stkvar2(op, op.addr, STKVAR_VALID_SIZE) ) {
                        op_stkvar(cmd.ea, op.n);
                        if ( cmd.Op2.type == o_reg ) {
                            regvar_t *r = find_regvar(pfn, cmd.ea, ph.regNames[cmd.Op2.reg]);
                            if ( r != NULL ) {
                                struc_t *s = get_frame(pfn);
                                member_t *m = get_stkvar(op, op.addr, NULL);
                                char b[20];
                                qsnprintf(b, sizeof b, "%scopy", r->user);
                                set_member_name(s, m->soff, b);
                            }
                        }
                    }
                }
            }
            break;

        // Register - Phrase - Void: do nothing
        case o_reg:
        case o_phrase:
        case o_void:
            break;

        default:
            INTERR(10076);
    }
}

// Emulate an instruction.
int idaapi emu(void) {
    uint32 feature = cmd.get_canon_feature();
    flow = ((feature & CF_STOP) == 0);

    if ( cmd.Op1.type != o_void) handle_operand(cmd.Op1, (feature & CF_CHG1) != 0 );
    if ( cmd.Op2.type != o_void) handle_operand(cmd.Op2, (feature & CF_CHG2) != 0 );
    if ( cmd.Op3.type != o_void) handle_operand(cmd.Op3, (feature & CF_CHG3) != 0 );

    if ( flow )
        ua_add_cref(0, cmd.ea + cmd.size, fl_F);

    //  Following code will update the current value of the two virtual
    //  segment registers: RW (register window) and RP (register page).

    bool rw_has_changed = false;
    bool rp_has_changed = false;

    switch ( cmd.itype ) {
        case st9_srp:
            {
                sel_t val = cmd.Op1.value;
                if ( val % 2 ) val--;     // even reduced
                splitSRarea1(cmd.ea, rRW, val | (val << 8), SR_auto);
            }
            rw_has_changed = true;
            break;

        case st9_srp0:
            {
                sel_t RW = getSR(cmd.ea, rRW);
                splitSRarea1(cmd.ea, rRW, cmd.Op1.value | (RW & 0xFF00), SR_auto);
            }
            rw_has_changed = true;
            break;

        case st9_srp1:
            {
                sel_t RW = getSR(cmd.ea, rRW);
                splitSRarea1(cmd.ea, rRW, (cmd.Op1.value << 8) | (RW & 0x00FF), SR_auto);
            }
            rw_has_changed = true;
            break;

        case st9_spp:
            splitSRarea1(cmd.ea, rRP, cmd.Op1.value, SR_auto);
            rp_has_changed = true;
            break;
    }

    // If RW / RP registers have changed, print a comment which explains the new mapping of
    // the general registers.

    if ( rw_has_changed && !has_cmt(uFlag) ) {
        char buf[MAXSTR];
        sel_t RW = getSR(cmd.ea, rRW);
        int low = RW & 0x00FF;
        int high = (RW & 0xFF00) >> 8;

        low *= 8;
        high *= 8;

        const char *fmt =
            "r0 -> R%d, r1 -> R%d, r2 -> R%d, r3 -> R%d, r4 -> R%d, r5 -> R%d, r6 -> R%d, r7 -> R%d,\n"
            "r8 -> R%d, r9 -> R%d, r10 -> R%d, r11 -> R%d, r12 -> R%d, r13 -> R%d, r14 -> R%d, r15 -> R%d";

        qsnprintf(buf, sizeof buf, fmt,
            0 + low,
            1 + low,
            2 + low,
            3 + low,
            4 + low,
            5 + low,
            6 + low,
            7 + low,
            8 + high,
            9 + high,
            10 + high,
            11 + high,
            12 + high,
            13 + high,
            14 + high,
            15 + high
        );

        set_cmt(cmd.ea, buf, false);
    }

    if ( rp_has_changed && !has_cmt(uFlag) ) {
        char buf[MAXSTR];
        qsnprintf(buf, sizeof buf, "Registers R240-R255 will now be referred to the page %d of paged registers",
            int(getSR(cmd.ea, rRP)));
        set_cmt(cmd.ea, buf, false);
    }

    return 1;
}

// Analyze an instruction
static ea_t next_insn(ea_t ea) {
    if ( decode_insn(ea) == 0 )
        return 0;
    ea += cmd.size;
    return ea;
}

// Create a function frame
bool idaapi create_func_frame(func_t *pfn) {
    ea_t ea = pfn->startEA;

    ea = next_insn(ea);
    if ( !ea )
        return 0;

    /*
     * Get the total frame size
     *
     * LINK rr14, #size
     */

    if ( cmd.itype != st9_link )
        return 0;

    int link_register = cmd.Op1.reg;
    size_t total_size = (size_t)cmd.Op2.value;

    /*
     * Get arguments size
     *
     * LDW 0x??(rr14), RR???        a word
     * LD  ''                       a byte
     */

    int args_size = 0;

    for(int i = 0; true; i++) {
        ea = next_insn(ea);
        if ( !ea )
            return 0;

        if ( cmd.Op1.type != o_displ || cmd.Op2.type != o_reg )
            break;

        if ( cmd.Op1.reg != link_register )
            break;

        if ( cmd.itype == st9_ld ) // byte
            args_size++;
        else if ( cmd.itype == st9_ldw ) // word
            args_size += 2;
        else
            break;

        char regvar[10];
        qsnprintf(regvar, sizeof regvar, "arg_%d", i);
        int error = add_regvar(pfn, cmd.ea, cmd.ea + cmd.size,
            ph.regNames[cmd.Op2.reg], regvar, NULL);
        if ( error )
            msg("add_regvar() failed : error %d\n", error);
    }

    /*
     * Detect FAR functions.
     */

    bool is_func_far = false;

    while ( true ) {
        ea = next_insn(ea);
        if ( !ea )
            return 0;

        bool should_break = false;

        switch ( cmd.itype ) {
            case st9_ret:
            case st9_iret:
            case st9_eret:
                should_break = true;
                break;

            case st9_rets:
                is_func_far = should_break = true;
                break;
        }

        if ( should_break )
            break;
    }

    // mark the function as FAR
    if ( is_func_far )
        pfn->flags |= FUNC_FAR;

    //msg("LOCAL: %d\nARGS: %d\n", total_size - args_size, args_size);

    pfn->flags |= FUNC_FRAME;
    return add_frame(pfn, total_size - args_size, 0, args_size);
}

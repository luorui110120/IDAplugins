
#include "m32r.hpp"

static bool flow;

// handle immediate values
static void handle_imm(void) {

    doImmd(cmd.ea);
}

// emulate operand
static void handle_operand(op_t &op, bool loading) {
    switch ( op.type ) {

        // Address
        case o_near:
            // branch label - create code reference (call or jump
            // according to the instruction)
            {
              ea_t ea = toEA(cmd.cs, op.addr);
              cref_t ftype = fl_JN;
              if ( cmd.itype == m32r_bl )
              {
                if ( !func_does_return(ea) )
                  flow = false;
                ftype = fl_CN;
              }
              ua_add_cref(op.offb, ea, ftype);
            }
            break;

        // Immediate
        case o_imm:
            if ( !loading ) {
                   interr("handle_operand(): o_imm with CF_CHG");
            }
            handle_imm();
            // if the value was converted to an offset, then create a data xref:
            if ( isOff(uFlag, op.n) )
              ua_add_off_drefs2(op, dr_O, OOFW_IMM|OOF_SIGNED);

            // create a comment if this immediate is represented in the .cfg file
            {
                const ioport_t * port = find_sym(op.value);

                if ( port != NULL && !has_cmt(uFlag) ) {
                    set_cmt(cmd.ea, port->cmt, false);
                }
            }
            break;

        // Displ
        case o_displ:
            handle_imm();
            // if the value was converted to an offset, then create a data xref:
            if ( isOff(uFlag, op.n) )
              ua_add_off_drefs2(op, loading ? dr_R : dr_W, OOF_SIGNED|OOF_ADDR|OOFW_32);

            // create stack variables if required
            if ( may_create_stkvars() && !isDefArg(uFlag, op.n) ) {
                func_t *pfn = get_func(cmd.ea);
                if ( pfn != NULL && (op.reg == rFP || op.reg == rSP) && pfn->flags & FUNC_FRAME ) {
                      if ( ua_stkvar2(op, op.addr, STKVAR_VALID_SIZE) ) {
                        op_stkvar(cmd.ea, op.n);
                    }
                }
              }
            break;

        case o_phrase:
            /* create stack variables if required */
            if ( op.specflag1 == fRI && may_create_stkvars() && !isDefArg(uFlag, op.n) ) {
                func_t *pfn = get_func(cmd.ea);
                if ( pfn != NULL && (op.reg == rFP || op.reg == rSP) && pfn->flags & FUNC_FRAME ) {
                    if ( ua_stkvar2(op, 0, STKVAR_VALID_SIZE) ) {
                        op_stkvar(cmd.ea, op.n);
                    }
                }
            }
            break;

        // Phrase - register - void : do nothing
        case o_reg:
        case o_void:
            break;

        // Others types should never be called
        default:
            interr2("handle_operand(): unknown type %d", op.type);
            break;
    }
}

// emulate an instruction
int idaapi emu(void) {
    uint32 feature = cmd.get_canon_feature();
    flow = ((feature & CF_STOP) == 0);

    if ( feature & CF_USE1)    handle_operand(cmd.Op1, 1 );
    if ( feature & CF_USE2)    handle_operand(cmd.Op2, 1 );
    if ( feature & CF_USE3)    handle_operand(cmd.Op3, 1 );

    if ( feature & CF_JUMP)    QueueMark(Q_jumps, cmd.ea );

    if ( feature & CF_CHG1)    handle_operand(cmd.Op1, 0 );
    if ( feature & CF_CHG2)    handle_operand(cmd.Op2, 0 );
    if ( feature & CF_CHG3)    handle_operand(cmd.Op3, 0 );

    if ( flow)    ua_add_cref(0, cmd.ea + cmd.size, fl_F );

    return 1;
}

bool idaapi create_func_frame(func_t *pfn) {
    if ( pfn == NULL )
        return 0;

    ea_t ea = pfn->startEA;
    insn_t insn[4];
    int i;

    for (i = 0; i < 4; i++) {
        decode_insn(ea);
        insn[i] = cmd;
        ea += cmd.size;
    }

    i = 0;
    ushort regsize = 0;            // number of saved registers

    // first insn is not either push fp OR st fp, @-sp
    if ( (insn[i].itype != m32r_push || insn[i].Op1.reg != rFP ) &&
        (insn[i].itype != m32r_st || insn[i].Op1.reg != rFP || insn[i].Op2.reg != rSP || insn[i].Op2.specflag1 != fRIAS))
    {
        return 0;
    }

    regsize += 4;
    i++;

    // next insn is push lr OR st lr, @-sp
    if ( (insn[i].itype == m32r_push && insn[i].Op1.reg == rLR ) ||
        (insn[i].itype == m32r_st && insn[i].Op1.reg == rFP && insn[i].Op2.reg == rLR && insn[i].Op2.specflag1 != fRIAS))
    {
        regsize += 4;
        i++;
    }

    // next insn is not addi sp, #imm
    if ( insn[i].itype != m32r_addi || insn[i].Op1.reg != rSP )
        return 0;

    sval_t offset = - (sval_t) insn[i].Op2.value;

    // toggle to the negative sign of the immediate operand of the addi insn
    if ( !is_invsign(insn[i].ea, get_flags_novalue(insn[i].ea), 2) )
      toggle_sign(insn[i].ea, 2);

    i++;

    // next insn is not mv fp, sp
    if ( insn[i].itype != m32r_mv || insn[i].Op1.reg != rFP || insn[i].Op2.reg != rSP )
        return 0;

#if DEBUG
    msg("=> %d bytes\n", - (signed) insn[1].Op2.value);
#endif

    pfn->flags |= (FUNC_FRAME | FUNC_BOTTOMBP);
    //setflag((uint32 &) pfn->flags, FUNC_FRAME | FUNC_BOTTOMBP, 1);
    return add_frame(pfn, offset, regsize, 0);
}

// should always returns 0
int idaapi m32r_get_frame_retsize(func_t *)
{
    return 0;
}

// check is the specified operand is relative to the SP register
int idaapi is_sp_based(const op_t &op) {
    return OP_SP_ADD | (op.reg == rSP ? OP_SP_BASED : OP_FP_BASED);
}

bool idaapi can_have_type(op_t &op) {
    switch ( op.type ) {
        case o_imm:
        case o_displ:
            return 1;

        case o_phrase:
            if ( op.specflag1 == fRI )   return 1;
    }
    return 0;
}

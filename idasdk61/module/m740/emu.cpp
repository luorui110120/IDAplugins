
#include "m740.hpp"

static bool flow;

static void handle_imm(op_t &op) {
    doImmd(cmd.ea);
    bool in_hex = false;
    switch ( cmd.itype ) {
        case m740_and:
        case m740_ora:
            in_hex = true;
            break;
    }
    if ( in_hex) op_hex(cmd.ea, op.n );
}

static void handle_operand(op_t &op) {
    switch ( op.type ) {

        // code address
        case o_near:
            {
                ea_t ea = toEA(cmd.cs, op.addr);
                cref_t mode = fl_JN;
                if ( cmd.itype == m740_jsr )
                {
                  if ( !func_does_return(ea) )
                    flow = false;
                  mode = fl_CN;
                }
                ua_add_cref(op.offb, ea, mode);
            }
            break;

        // data address
        case o_mem:
            {
                enum dref_t mode = dr_U;

                if ( is_addr_ind(op) )            mode = dr_R;    /* NOT dr_O */
                else if ( is_addr_read(op) )      mode = dr_R;
                else if ( is_addr_write(op) )     mode = dr_W;

                ua_add_dref(op.offb, toEA(cmd.cs, op.addr), mode);
                ua_dodata2(op.offb, op.addr, op.dtyp);
            }
            break;

        // immediate
        case o_imm:
            handle_imm(op);
            // if the value was converted to an offset, then create a data xref:
            if ( isOff(uFlag, op.n) )
              ua_add_off_drefs2(op, dr_O, 0);
            break;

        // displ
        case o_displ:
            if ( isOff(uFlag, op.n) ) {
                ua_add_off_drefs2(op, dr_O, OOF_ADDR);
                ua_dodata2(op.offb, op.addr, op.dtyp);
            }
            break;

        // reg - do nothing
        case o_reg:
        case o_void:
            break;

        default:
            INTERR(10022);
    }
}

// emulate an instruction
int idaapi emu(void) {
    uint32 feature = cmd.get_canon_feature();
    flow = ((feature & CF_STOP) == 0);

    if ( cmd.Op1.type != o_void)            handle_operand(cmd.Op1 );
    if ( cmd.Op2.type != o_void)            handle_operand(cmd.Op2 );
    if ( cmd.Op3.type != o_void)            handle_operand(cmd.Op3 );

/*
     we can't use this code

    if ( feature & CF_USE1)    handle_operand(cmd.Op1, 1 );
    if ( feature & CF_USE2)    handle_operand(cmd.Op2, 1 );
    if ( feature & CF_USE3)    handle_operand(cmd.Op3, 1 );
*/

    // we don't use CF_JUMP
    //if ( feature & CF_JUMP )
    switch ( cmd.itype ) {
        case m740_jmp:
        case m740_jsr:
            if ( cmd.Op1.type != o_void && is_addr_ind(cmd.Op1) )
                QueueMark(Q_jumps, cmd.ea);
            break;
    }

/*
    if ( feature & CF_CHG1)    handle_operand(cmd.Op1, 0 );
    if ( feature & CF_CHG2)    handle_operand(cmd.Op2, 0 );
    if ( feature & CF_CHG3)    handle_operand(cmd.Op3, 0 );
*/

    if ( flow ) {
        // skip the next byte if the current insn is brk
        if ( cmd.itype == m740_brk ) {
            ua_add_cref(0, cmd.ea + cmd.size + 1, fl_JN);
            doByte(cmd.ea + cmd.size, 1);
        }
        else {
            ua_add_cref(0, cmd.ea + cmd.size, fl_F);
        }
    }

    return 1;
}

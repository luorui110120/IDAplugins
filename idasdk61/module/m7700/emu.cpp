
#include "m7700.hpp"

static bool flow;

static void handle_imm(op_t &op) {
    doImmd(cmd.ea);
    bool in_hex = false;
    switch ( cmd.itype ) {
        case m7700_and:
        case m7700_ora:
            in_hex = true;
            break;
    }
    if ( in_hex) op_hex(cmd.ea, op.n );
}

// propagate m and x to the jump target
static void propagate_bits_to(ea_t ea)
{
  if ( !isLoaded(ea) )
    return;
  splitSRarea1(ea, rfM, getSR(cmd.ea, rfM), SR_auto);
  splitSRarea1(ea, rfX, getSR(cmd.ea, rfX), SR_auto);
}

static void handle_operand(op_t &op) {
    switch ( op.type ) {

        // code address
        case o_near:
            {
                ea_t ea = toEA(cmd.cs, op.addr);
                cref_t mode;
                if ( cmd.itype == m7700_jsr )
                {
                  mode = is_insn_long_format() ? fl_CF : fl_CN;
                  if ( !func_does_return(ea) )
                    flow = false;
                }
                else
                {
                  mode = is_insn_long_format() ? fl_JF : fl_JN;
                }
                ua_add_cref(op.offb, ea, mode);
                propagate_bits_to(ea);
            }
            break;

        // data address
        case o_mem:
            // create xref for instructions with :
            //      - direct addressing mode if the value of DR is known
            //        (and therefore, computed by the analyzer)
            //      - other addressing modes
            if ( !is_addr_dr_rel(op) || getSR(cmd.ea, rDR) != BADSEL ) {
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

        // bit
        case o_bit:
            handle_imm(op);
            // create a comment if this immediate is represented in the .cfg file
            if ( op.n == 0 && (cmd.Op2.type == o_near || cmd.Op2.type == o_mem) )
            {
                const ioport_bit_t * port = find_bit(cmd.Op2.addr, (size_t)op.value);

                if ( port != NULL && port->name != NULL && !has_cmt(uFlag) ) {
                    set_cmt(cmd.ea, port->cmt, false);
                }
            }
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
            INTERR(10028);
    }
}

// emulate an instruction
int idaapi emu(void) {
    uint32 feature = cmd.get_canon_feature();
    flow = ((feature & CF_STOP) == 0);

    if ( cmd.Op1.type != o_void)            handle_operand(cmd.Op1 );
    if ( cmd.Op2.type != o_void)            handle_operand(cmd.Op2 );
    if ( cmd.Op3.type != o_void)            handle_operand(cmd.Op3 );

    // we don't use CF_JUMP
    //if ( feature & CF_JUMP )
    switch ( cmd.itype ) {
        case m7700_jmp:
        case m7700_jsr:
            if ( cmd.Op1.type != o_void && is_addr_ind(cmd.Op1) )
                QueueMark(Q_jumps, cmd.ea);
            break;
    }

    if ( flow ) {
        // skip the next byte if the current insn is brk
        if ( cmd.itype == m7700_brk ) {
            ua_add_cref(0, cmd.ea + cmd.size + 1, fl_JN);
            doByte(cmd.ea + cmd.size, 1);
        }
        else {
            ua_add_cref(0, cmd.ea + cmd.size, fl_F);
        }
    }

    switch ( cmd.itype ) {
        // clear m flag
        case m7700_clm:
            splitSRarea1(cmd.ea + cmd.size, rfM, 0, SR_auto);
            break;
        // set m flag
        case m7700_sem:
            splitSRarea1(cmd.ea + cmd.size, rfM, 1, SR_auto);
            break;

        // clear processor status
        case m7700_clp:
            // clear m flag
            if ( ((cmd.Op1.value & 0x20) >> 5) == 1 )
                splitSRarea1(cmd.ea + cmd.size, rfM, 0, SR_auto);
            // clear x flag
            if ( ((cmd.Op1.value & 0x10) >> 4) == 1 )
                splitSRarea1(cmd.ea + cmd.size, rfX, 0, SR_auto);
            break;

        // set processor status
        case m7700_sep:
            // set m flag
            if ( ((cmd.Op1.value & 0x20) >> 5) == 1 )
                splitSRarea1(cmd.ea + cmd.size, rfM, 1, SR_auto);
            // set x flag
            if ( ((cmd.Op1.value & 0x10) >> 4) == 1 )
                splitSRarea1(cmd.ea + cmd.size, rfX, 1, SR_auto);
            break;

        // pull processor status from stack
        case m7700_plp:
            splitSRarea1(cmd.ea + cmd.size, rfM, BADSEL, SR_auto);
            splitSRarea1(cmd.ea + cmd.size, rfX, BADSEL, SR_auto);
            break;
    }
    return 1;
}

static bool is_func_far(ea_t ea) {
    bool func_far = false;
    while ( true ) {
        if ( decode_insn(ea) == 0 )
            break;
        ea += cmd.size;

        // rts = jsr
        if ( cmd.itype == m7700_rts )
            break;

        // rtl = jsrl
        if ( cmd.itype == m7700_rtl ) {
            func_far = true;
            break;
        }
    }
    return func_far;
}

bool idaapi create_func_frame(func_t *pfn) {

    // PC (2 bytes long) is always pushed
    int context_size = 2;

    // detect phd
    ea_t ea = pfn->startEA;

    // if far, 1 byte more on the stack (PG register)
    if ( is_func_far(ea) ) {
        pfn->flags |= FUNC_FAR;
        context_size++;
    }

    decode_insn(ea);
    ea += cmd.size;
    if ( cmd.itype != m7700_phd )
        return 0;

    // DR (2 bytes long) is pushed
    context_size += 2;

    int auto_size = 0;

    while ( true ) {
        decode_insn(ea);
        ea += cmd.size;

        // A (2 bytes long) is pushed
        if ( cmd.itype != m7700_pha )
            break;

        auto_size += 2;
    }

    // gen comment
    char b[MAXSTR];
    qsnprintf(b, sizeof b, "Auto Size (%d) - Context Size (%d)", auto_size, context_size);
    set_func_cmt(pfn, b, false);

    return add_frame(pfn, auto_size, 0, 0);;
}

int idaapi idp_get_frame_retsize(func_t *pfn)
{
    return is_func_far(pfn->startEA) ? 2 : 3;
}

/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INS_HPP
#define __INS_HPP

extern instruc_t Instructions[];

enum nameNum {

ARC_null = 0,   // Unknown Operation

ARC_ld0,
ARC_ld1,
ARC_lr,
ARC_st,
ARC_sr,
ARC_store_instructions=ARC_sr,
ARC_flag,
ARC_asr,
ARC_lsr,
ARC_sexb,
ARC_sexw,
ARC_extb,
ARC_extw,
ARC_ror,
ARC_rrc,
ARC_b,
ARC_bl,
ARC_lp,
ARC_j,
ARC_jl,
ARC_add,
ARC_adc,
ARC_sub,
ARC_sbc,
ARC_and,
ARC_or,
ARC_bic,
ARC_xor,

        // pseudo instructions
ARC_move,
ARC_nop,
ARC_lsl,
ARC_rlc,

ARC_last,

    };

#endif

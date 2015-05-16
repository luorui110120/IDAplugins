/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "arc.hpp"

instruc_t Instructions[] = {

{ "",           0                               },      // Unknown Operation
{ "ld",         CF_CHG1|CF_USE2|CF_USE3         },      // load
{ "ld",         CF_CHG1|CF_USE2|CF_USE3         },      // load
{ "lr",         CF_CHG1|CF_USE2|CF_USE3         },      // load special
{ "st",         CF_USE1|CF_USE2|CF_USE3         },      // store
{ "sr",         CF_USE1|CF_USE2|CF_USE3         },      // store special
{ "flag",       CF_USE1                         },      // flag
{ "asr",        CF_USE1|CF_CHG1                 },      // arithmetic shift right
{ "lsr",        CF_USE1|CF_CHG1                 },      // logical shift right
{ "sexb",       CF_USE1|CF_CHG1                 },      // sign extend
{ "sexw",       CF_USE1|CF_CHG1                 },      // sign extend
{ "extb",       CF_USE1|CF_CHG1                 },      // zero extend
{ "extw",       CF_USE1|CF_CHG1                 },      // zero extend
{ "ror",        CF_USE1|CF_CHG1                 },      // rotate right
{ "rrc",        CF_USE1|CF_CHG1                 },      // rotate right through carry
{ "b",          CF_USE1|CF_JUMP                 },      // branch
{ "bl",         CF_USE1|CF_CALL                 },      // branch and link
{ "lp",         CF_USE1                         },      // loop setup
{ "j",          CF_USE1|CF_JUMP                 },      // jump
{ "jl",         CF_USE1|CF_CALL                 },      // jump and link
{ "add",        CF_CHG1|CF_USE2|CF_USE3         },      // add
{ "adc",        CF_CHG1|CF_USE2|CF_USE3         },      // add with carry
{ "sub",        CF_CHG1|CF_USE2|CF_USE3         },      // sub
{ "sbc",        CF_CHG1|CF_USE2|CF_USE3         },      // sub with carry
{ "and",        CF_CHG1|CF_USE2|CF_USE3         },      // and
{ "or",         CF_CHG1|CF_USE2|CF_USE3         },      // or
{ "bic",        CF_CHG1|CF_USE2|CF_USE3         },      // and with invert
{ "xor",        CF_CHG1|CF_USE2|CF_USE3         },      // xor
{ "mov",        CF_CHG1|CF_USE2                 },      // pseudo instruction: move
{ "nop",        0                               },      // pseudo instruction: nop
{ "lsl",        CF_CHG1|CF_USE2                 },      // pseudo instruction: lsl
{ "rlc",        CF_CHG1|CF_USE2                 },      // pseudo instruction: rlc
  };

CASSERT(qnumber(Instructions) == ARC_last);

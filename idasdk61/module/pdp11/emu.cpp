/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "pdp.hpp"
#include <ints.hpp>

static int flow;
static int32 emuFlg;
static ushort emuR0 = 0xFFFF;
static union {
    ushort w;
    uchar b[2];
 }emuR0data = {0xFFFF};
//------------------------------------------------------------------------
void loadR0data(op_t *x, int sme)
{
  if ( cmd.Op2.type == o_void ) {
    if ( cmd.itype != pdp_clr ) goto undefdat;
    if ( sme ) {
      if ( !cmd.bytecmd ) goto undefdat;
      emuR0data.b[1] = 0;
      return;
    }
    if ( cmd.bytecmd ) emuR0data.b[0] = 0;
    else            emuR0data.w = 0;
    return;
  }
  if ( x != &cmd.Op2 ) return;
  if ( cmd.Op1.type == o_imm ) {
    if ( cmd.itype == pdp_mov ) {
      if ( !cmd.bytecmd ) {
        if ( sme ) goto undefdat;
        emuR0data.w = (ushort)cmd.Op1.value;
        return;
      }
      if ( !sme) emuR0data.b[0] = (uchar )cmd.Op1.value;
      else     emuR0data.b[1] = (uchar)cmd.Op1.value;
      return;
    }
    if ( !cmd.bytecmd ) goto undefdat;
undefbyt:
   if ( !sme ) emuR0data.b[0] = 0xFF;
   else     emuR0data.b[1] = 0xFF;
   return;
  }
  if ( cmd.bytecmd ) goto undefbyt;
undefdat:
  emuR0data.w = 0xFFFF;
}

//------------------------------------------------------------------------
inline void doImmdValue(void) {
    doImmd(cmd.ea);
}

//------------------------------------------------------------------------
static void TouchArg(op_t &x,int isAlt,int isload) {
  ea_t jmpa;
  switch ( x.type ) {
  case o_near:       // Jcc/ [jmp/call 37/67]
  case o_mem:        // 37/67/77
  case o_far:
      jmpa = toEA(x.type == o_far ? x.segval : codeSeg(x.addr16,x.n), x.addr16);
      if ( x.phrase == 0) { ua_add_cref(x.offb,jmpa,fl_JN ); break; } //Jcc
extxref:
      if ( (x.phrase & 070) == 070 ) goto xrefset;
      if ( cmd.itype == pdp_jmp) ua_add_cref(x.offb,jmpa,fl_JF );
      else if ( cmd.itype == pdp_jsr || cmd.itype == pdp_call ) {
             ua_add_cref(x.offb,jmpa,fl_CF);
             if ( !func_does_return(jmpa) )
               flow = false;
           } else {
xrefset:
             ua_dodata2(x.offb, jmpa, x.dtyp);
             ua_add_dref(x.offb, jmpa, isload ? dr_R : dr_W);
           }
      break;
  case o_displ:     // 6x/7x (!67/!77)
      doImmdValue();
      if ( !isload && x.phrase == (060 + rR0) && x.addr16 <= 1 )
                                                  loadR0data(&x, x.addr16);
      if ( !isAlt && isOff(emuFlg,x.n ) &&
         (jmpa = get_offbase(cmd.ea, x.n)) != BADADDR) {
        jmpa += x.addr16;
        goto extxref;
      }
      break;
  case o_imm:        // 27
      if ( !x.ill_imm ) {
         doImmdValue();
         if ( isOff(uFlag, x.n) )
           ua_add_off_drefs2(x, dr_O, OOF_SIGNED);
      }
      break;
  case o_number:      // EMT/TRAP/MARK/SPL
      if ( cmd.itype == pdp_emt && get_cmt(cmd.ea, false, NULL, 0) <= 0 ) {
         if ( x.value >= 0374 && x.value <= 0375 ) {
           cmd.Op2.value = (x.value == 0375) ? emuR0data.b[1] : (emuR0 >> 8);
           cmd.Op2.type = o_imm;
         }
         char buf[MAXSTR];
         if ( get_predef_insn_cmt(cmd, buf, sizeof(buf)) > 0 )
           set_cmt(cmd.ea, buf, false);
        cmd.Op2.type = o_void;
      }
      break;
  case o_reg:        // 0
      if ( x.reg == rR0 ) {
        if ( cmd.Op2.type == o_void ) { // one operand cmd
          if ( cmd.itype != pdp_clr ) {
            goto undefall;
          } else {
            if ( cmd.bytecmd ) emuR0 &= 0xFF00;
            else            emuR0 = 0;
            goto undefdata;
          }
        }
        if ( &x == &cmd.Op2 ) {
          if ( cmd.itype != pdp_mov ) {
            if ( cmd.bytecmd ) { emuR0 |= 0xFF; goto undefdata; }
            else            goto undefall;
          }
          if ( cmd.bytecmd ) goto undefall;
          if ( cmd.Op1.type == o_imm ) {
            if ( (emuR0 = (ushort)cmd.Op1.value) & 1 ) goto undefdata;
            emuR0data.w = get_word(toEA(cmd.cs, emuR0));
          } else {
undefall:
            emuR0 = 0xFFFF;
undefdata:
            emuR0data.w = 0xFFFF;
          }
        }
      }
      break;
  case o_phrase:     // 1x/2x/3x/4x/5x (!27/!37)
      if ( (x.phrase & 7) == rR0 )
      {
        if ( !isload && x.phrase == (010 + rR0)) loadR0data(&x, 0 );
        else if ( cmd.Op2.type == o_void || &x == &cmd.Op2 ) goto undefall;
      }
  case o_fpreg:      // FPP
    break;
  default:
    warning("%" FMT_EA "o (%s): bad optype %d", cmd.ip, cmd.get_canon_mnem(), x.type);
    break;
  }
}

//----------------------------------------------------------------------
int idaapi emu(void) {
  int flag1 = is_forced_operand(cmd.ea, 0);
  int flag2 = is_forced_operand(cmd.ea, 1);

  uint32 Feature = cmd.get_canon_feature();
  flow = !(Feature & CF_STOP);

  if ( Feature & CF_USE1) TouchArg(cmd.Op1, flag1, 1 );
  if ( Feature & CF_USE2) TouchArg(cmd.Op2, flag2, 1 );
  if ( Feature & CF_JUMP) QueueMark(Q_jumps, cmd.ea );

  if ( Feature & CF_CHG1) TouchArg(cmd.Op1, flag1, 0 );
  if ( Feature & CF_CHG2) TouchArg(cmd.Op2, flag2, 0 );

  ea_t newEA = cmd.ea + cmd.size;
  if ( cmd.itype == pdp_emt && cmd.Op1.value == 0376 ) {
    doByte(newEA, 2);
    goto prompt2;
  }
  else if(flow &&
          !(cmd.itype == pdp_emt && cmd.Op1.value == 0350)) {

    if ( cmd.Op1.type == o_imm && cmd.Op1.ill_imm ) newEA += 2;
    if ( cmd.Op2.type == o_imm && cmd.Op2.ill_imm ) {
prompt2:
      newEA += 2;
    }
    ua_add_cref(0, newEA, fl_F);
  }

  return(1);
}

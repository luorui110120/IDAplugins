/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      JVM module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "java.hpp"

static uint32 Feature;

static const char badlocvar[] = "Invalid local variable number";

//----------------------------------------------------------------------
static uval_t SearchFM(ushort name, ushort dscr, char *naprN)
{
  char    buf[(qmax(sizeof(FieldInfo), sizeof(SegInfo))+1+3)&~3];
  sval_t  pos = curClass.FieldCnt;
  uint32  csz = sizeof(FieldInfo);
  sval_t  napr = *naprN;

  if ( napr != 1 ) {
    if ( napr != -1) INTERNAL("SearchFM" );
    pos = -(uval_t)curClass.MethodCnt;
    csz = sizeof(SegInfo);
  }
  for(register void *p = buf; pos; pos -= napr) {
    if ( ClassNode.supval(pos, p, sizeof(buf)) != csz) DESTROYED("SearchFM" );
    if(   ((_FMid_ *)p)->extflg & EFL_NAMETYPE
       || CmpString(name, ((_FMid_ *)p)->name)
       || CmpString(dscr, ((_FMid_ *)p)->dscr)) continue;

    if ( napr >= 0) return(curClass.startEA + ((FieldInfo *)p)->id.Number );
    if ( ((SegInfo *)p)->CodeSize ) *naprN = 0;
    return(((SegInfo *)p)->startEA);
  }
  return(BADADDR);
}

//------------------------------------------------------------------------
void mark_and_comment(ea_t ea, const char *cmt)
{
  if ( loadpass >= 0 ) {
    QueueMark(Q_att, ea);
    if ( *cmt && (!has_cmt(get_flags_novalue(ea)) || ea == curClass.startEA) )
      append_cmt(ea, cmt, false);
  }
}

//------------------------------------------------------------------------
static void TouchArg(op_t &x, int isload)
{
  register const char *p;

  switch ( x.type ) {
    case o_void:       // not operand
      break;

    case o_cpool:      // ConstantPool reference (index)
      if ( x.ref ) {
        p = x.ref == 1 ? "Invalid string in constant pool" :
                         "Invalid index in constant pool";
        goto mark;
      }
      if ( x.cp_ind ) {
         ea_t ea;
         char npr = -1;

         switch ( (uchar)x.cp_type ) {
           case CONSTANT_Fieldref:
            npr = 1;
           case CONSTANT_InterfaceMethodref:
           case CONSTANT_Methodref:
             if ( !(x._subnam | x._name | x._class) ) break;
             if ( x._class == curClass.This.Dscr ) {
               if ( (ea = SearchFM(x._subnam, x._dscr, &npr)) == BADADDR ) break;
             } else {
               if ( !cmd.xtrn_ip ) break;
               ea = (cmd.xtrn_ip == 0xFFFF) ? curClass.startEA :
                                              curClass.xtrnEA + cmd.xtrn_ip;
               if ( npr < 0 ) npr = 0;
             }
             if ( npr <= 0 ) {
               ua_add_cref(x.offb, ea, fl_CF);
               if ( !npr) autoCancel(ea, ea+1 );
             } else ua_add_dref(x.offb, ea,
                                (   cmd.itype == j_putstatic
                                 || cmd.itype == j_putfield) ? dr_W : dr_R);
            break;

           case CONSTANT_Class:
            if ( cmd.xtrn_ip )
              ua_add_dref(x.offb, cmd.xtrn_ip == 0xFFFF ?
                                      curClass.startEA :
                                      curClass.xtrnEA + cmd.xtrn_ip, dr_I);
             break;

           case CONSTANT_Float:
             npr &= 1;
           case CONSTANT_Double:
             check_float_const(cmd.ea, &x.value, npr &= 3);
           default:
             break;
         }
      }
      break;

    case o_array:      // type!
      if ( x.ref ) {
        p = "Invalid array type";
        goto mark;
      }
      break;

    case o_imm:        //const (& #data)
      if ( x.ref < 2) doImmd(cmd.ea );
      break;

    case o_mem:        // local data pool
      if ( x.ref ) {
        p = badlocvar;
mark:
        mark_and_comment(cmd.ea, p);
      } else {
        dref_t  ref = isload ? dr_R : dr_W;
        ea_t    adr = curSeg.DataBase + x.addr;
        ua_add_dref(x.offb, adr, ref);
        if(   (x.dtyp == dt_qword || x.dtyp == dt_double)
           && get_item_size(adr) <= 1) ua_add_dref(x.offb, adr + 1, ref);
      }
      break;

    case o_near:
      if ( x.ref ) {
        p = "Invalid jump address";
        goto mark;
      }
      ua_add_cref(x.offb,curSeg.startEA + x.addr,(Feature & CF_CALL) ? fl_CN :
                                                                       fl_JN);
      break;

    default:
      warning("%a: %s,%d: bad optype %d", cmd.ea, cmd.get_canon_mnem(), x.n,
              x.type);
      break;
  }
}

//----------------------------------------------------------------------
int idaapi emu(void)
{
  Feature = cmd.get_canon_feature();

  if ( cmd.wid > 1 )
      mark_and_comment(cmd.ea, "Limited usage instruction");

  if ( cmd.itype >= j_a_software )
      mark_and_comment(cmd.ea, "Undocumented instruction");

  if ( cmd.Op1.type == o_void && cmd.Op1.ref ) {
    if ( (char)cmd.Op1.ref < 0) mark_and_comment(cmd.ea, badlocvar );
    else {
      dref_t ref = (cmd.itype >= j_istore_0) ? dr_W : dr_R;
      ua_add_dref(0, cmd.Op1.addr, ref);
      if ( (cmd.Op1.ref & 2) && get_item_size(cmd.Op1.addr) <= 1 )
                                      ua_add_dref(0, cmd.Op1.addr + 1, ref);
    }
  }

  if ( Feature & CF_USE1) TouchArg(cmd.Op1, 1 );
  if ( Feature & CF_USE2) TouchArg(cmd.Op2, 1 );
  if ( Feature & CF_USE3) TouchArg(cmd.Op3, 1 );

//  if ( Feature & CF_JUMP) QueueMark(Q_jumps, cmd.ea );

  if ( Feature & CF_CHG1) TouchArg(cmd.Op1, 0 );

  if ( cmd.swit ) {         // tableswitch OR lookupswitch
    uval_t count, addr, rnum;

    if ( cmd.swit & 0200 )
        mark_and_comment(cmd.ea, badlocvar);
    if ( cmd.swit & 0100 )
        mark_and_comment(cmd.ea, "Nonzero filler (warning)");

    rnum = cmd.Op2.value - 1;   // for lookupswtitch
    for(addr= cmd.Op2.addr, count= cmd.Op3.value; count; addr +=4, count--) {

      uval_t refa;

      if ( cmd.itype != j_lookupswitch ) ++rnum;
      else {
        rnum = get_long(curSeg.startEA + addr); // skip pairs
        addr += 4;
      }
      refa = cmd.ip + get_long(curSeg.startEA + addr);

      if ( refa < curSeg.CodeSize ) {
        ua_add_cref(0, (refa += curSeg.startEA), fl_JN);
        if ( !has_cmt(get_flags_novalue(refa)) ) {
          char  str[32];
          qsnprintf(str, sizeof(str), "case %" FMT_EA "d", rnum);
          set_cmt(refa, str, false);
        }
      }
    }
  }

  if ( !(Feature&CF_STOP) && (!(Feature&CF_CALL) || func_does_return(cmd.ea)) )
    ua_add_cref(0, cmd.ea + cmd.size, fl_F);

  return(1);
}

//----------------------------------------------------------------------
size_t make_locvar_cmt(char *buf, size_t bufsize)
{
  LocVar  lv;

  if ( curSeg.varNode ) {
    const char  *p = NULL;
    uval_t      idx = cmd.Op1.addr;

    if ( cmd.Op1.type == o_mem ) {
      if ( !cmd.Op1.ref) switch(cmd.itype ) {
        case j_ret:
          p = "Return";
          break;
        case j_iinc:
          p = "Add 8-bit signed const to";
          break;
        default:
          p = "Push";
          if ( cmd.get_canon_feature() & CF_CHG1 ) p = "Pop";
          break;
      }
    } else if(   cmd.Op1.type == o_void
              && (char)cmd.Op1.ref >= 0
              && (int32)(idx -= curSeg.DataBase) >= 0) {
      p = "Push";
      if ( cmd.itype >= j_istore_0 ) p = "Pop";
    }

    if ( p && netnode(curSeg.varNode).supval(idx,&lv,sizeof(lv))==sizeof(lv) ) {
      char  name[MAXSTR];
      if ( fmtName(lv.var.Name, name, sizeof(name), fmt_name) )
        return(qsnprintf(buf, bufsize, "%s %s", p, name));
    }
  }
  return(0);
}

//----------------------------------------------------------------------

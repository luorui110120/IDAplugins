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

//----------------------------------------------------------------------
static int LoadIndex(void)
{
  register ushort top;

  cmd.Op1.type = o_mem;
//  cmd.Op1.ref = 0;
  cmd.Op1.offb = char(cmd.size);
  cmd.Op1.addr = top = cmd.wid ? ua_next_word() : ua_next_byte();
  if(   ((cmd.Op1.dtyp == dt_qword || cmd.Op1.dtyp == dt_double) && !++top)
     || top >= curSeg.DataSize) {

    if ( !debugmode) return(0 );
    ++cmd.Op1.ref;
  }
  return(1);
}

//----------------------------------------------------------------------
enum CIC_param {
                 C_4byte = 0,
                 C_8byte,
                 C_Field,
                 C_Method,
                 C_Interface,
                 C_Class,
                 C_Type,
                 C_TypeName,
               };

static int ConstLoad(CIC_param ctype)
{
  ConstOpis cntopis;
  uchar     i;

  cmd.Op1.type = o_cpool;
//  cmd.Op1.ref = 0;

  if ( !cmd.Op1.cp_ind ) goto dmpchk;  //NULL Ptr

  if ( !LoadOpis(cmd.Op1.cp_ind, 0, &cntopis) ) goto dmpchk;

#ifdef __BORLANDC__
#if ( offsetof(ConstOpis,flag) != (offsetof(ConstOpis,type) + sizeof(uchar) ) \
     || (sizeof(cntopis.type) != sizeof(uchar))      \
     || (sizeof(cntopis.flag) != sizeof(uchar))      \
     || (sizeof(cmd.Op1.cp_type) < (2*sizeof(uchar))) \
     || (sizeof(ushort) != sizeof(cmd.Op1.cp_type)))
#error
#endif
#endif
  cmd.Op1.cp_type = *((ushort *)&cntopis.type);
  i = cntopis.type;

  switch ( ctype ) {
    case C_Class:
      if ( i != CONSTANT_Class ) break;
      //PASS THRU
    case C_4byte: // ldc/ldcw
      switch ( i ) {
        case CONSTANT_Class:
          if ( !(cntopis.flag & HAS_CLSNAME) ) goto wrnret;
          cmd.Op1.addr  = 0x10001ul * (ushort)fmt_fullname;
loadref1:
          cmd.xtrn_ip   = cntopis.ref_ip;
          //PASS THRU
        case CONSTANT_Integer:
        case CONSTANT_Float:
        case CONSTANT_String:
          cmd.Op1.value = cntopis.value;  // for string index to Utf8
          return(1);                      // or TWO index for other
        default:
          break;
      }
      break;

    case C_8byte:
      if ( i == CONSTANT_Long || i == CONSTANT_Double ) goto load2;
      break;

    case C_Field:
      if ( i != CONSTANT_Fieldref ) break;
      if ( (cntopis.flag & NORM_FIELD) != NORM_FIELD ) goto wrnret;
loadref2:
      cmd.xtrn_ip   = cntopis.ref_ip;
load2:
      cmd.Op1.addr  = cntopis.value2;
      cmd.Op1.value = cntopis.value;     // for string index to Utf8
#ifdef __EA64__
      cmd.Op1.value = make_ulonglong(int32(cmd.Op1.value), uint32(cmd.Op1.addr));
#endif
      return 1;

    case C_Interface:
      if ( i == CONSTANT_InterfaceMethodref ) goto methodchk;
      break;
    case C_Method:
      if ( i != CONSTANT_Methodref ) break;
methodchk:
      if ( (cntopis.flag & NORM_METOD) == NORM_METOD ) goto loadref2; //load 3 ind. & xtrn_ref
      goto wrnret;

    case C_Type:
      if ( i != CONSTANT_Class ) break;
      if ( !(cntopis.flag & HAS_TYPEDSCR) ) goto wrnret;
      cmd.Op1.addr = ((uint32)fmt_dscr << 16) | (ushort)fmt_classname;
      goto loadref1; //load 1 ind.

    case C_TypeName:
      if ( i != CONSTANT_Class ) break;
      if ( !(cntopis.flag & (HAS_TYPEDSCR | HAS_CLSNAME)) ) goto wrnret;
      cmd.Op1.addr = ((uint32)fmt_cast << 16) | (ushort)
                                            ((cntopis.flag & HAS_CLSNAME) ?
                                               fmt_fullname : fmt_classname);
      goto loadref1; //load 1 ind.

    default:
      warning("Illegal CIC call (%x)\n", ctype);
      return(0);
  }
dmpchk:
  if ( !debugmode) return(0 );
  ++cmd.Op1.ref;
wrnret:
  ++cmd.Op1.ref;
  cmd.Op1.addr_shorts.low = cmd.Op1.cp_ind;    // for dmp out
  return(1);
}

//----------------------------------------------------------------------
int idaapi ana(void)
{
  CIC_param ctype;
  register segment_t *s = getMySeg(cmd.ea); // also set curSeg

  if ( s->type != SEG_CODE || cmd.ip >= curSeg.CodeSize ) {
    warning("Can't decode non-code fragment!");
    return(0);
  }

  cmd.Op1.dtyp = dt_void;
  cmd.wid = cmd.swit = 0;
  cmd.Op1.ref = 0;

  if ( (cmd.itype = ua_next_byte()) == j_wide ) {
    if(   (cmd.itype = ua_next_byte()) == j_iinc
       || (cmd.itype >= j_iload && cmd.itype <= j_aload)
       || (cmd.itype >= j_istore && cmd.itype <= j_astore)
       || cmd.itype == j_ret) cmd.wid = 1; //_w
    else {
      if ( !debugmode) return(0 );
      cmd.size = 1;
      cmd.itype = j_wide;
    }
  }

  if ( cmd.itype >= j_lastnorm ) {
    if ( !debugmode) return(0 );
    if ( cmd.itype < j_quick_last ) {
      static const uchar redefcmd[j_quick_last - j_lastnorm] = {
            j_ldc,                    //j_ldc_quick
            j_ldcw,                   //j_ldcw_quick
            j_ldc2w,                  //j_ldc2w_quick
            j_getfield,               //j_getfield_quick
            j_putfield,               //j_putfield_quick
            j_getfield,               //j_getfield2_quick
            j_putfield,               //j_putfield2_quick
            j_getstatic,              //j_getstatic_quick
            j_putstatic,              //j_putstatic_quick
            j_getstatic,              //j_getstatic2_quick
            j_putstatic,              //j_putstatic2_quick
            j_invokevirtual,          //j_invokevirtual_quick
            j_invokespecial,          //j_invokenonvirtual_quick
            j_a_invokesuper,          //j_invokesuper_quick
            j_invokestatic,           //j_invokestatic_quick
            j_invokeinterface,        //j_invokeinterface_quick
            j_a_invokevirtualobject,  //j_invokevirtualobject_quick
            j_a_invokeignored,        //j_invokeignored_quick
            j_new,                    //j_new_quick
            j_anewarray,              //j_anewarray_quick
            j_multianewarray,         //j_multianewarray_quick
            j_checkcast,              //j_checkcast_quick
            j_instanceof,             //j_instanceof_quick
            j_invokevirtual,          //j_invokevirtual_quick_w
            j_getfield,               //j_getfield_quick_w
            j_putfield                //j_putfield_quick_w
        };

      cmd.wid = 2; //_quick;
      switch ( cmd.itype ) {
        case j_getstatic2_quick:
        case j_putstatic2_quick:
        case j_getfield2_quick:
        case j_putfield2_quick:
          cmd.wid = 3;  //2_quick
          break;
        case j_invokevirtual_quick_w:
        case j_getfield_quick_w:
        case j_putfield_quick_w:
          cmd.wid = 4;  //_quick_w
          break;
        default:
          break;
      }
      cmd.itype = redefcmd[cmd.itype - j_lastnorm];
    } else if ( cmd.itype < j_software) return(0 );
           else cmd.itype -= (j_software - j_a_software);
  }
//---
  switch ( cmd.itype ) {
    default:
      {
        register unsigned refs, ref2f;

        if ( cmd.itype >= j_iload_0 && cmd.itype <= j_aload_3 ) {
          refs = (cmd.itype - j_iload_0) % 4;
          ref2f = (cmd.itype - j_iload_0) / 4;
          ref2f =   ref2f == ((j_lload_0 - j_iload_0) / 4)
                 || ref2f == ((j_dload_0 - j_iload_0) / 4);
          goto refer;
        }
        if ( cmd.itype >= j_istore_0 && cmd.itype <= j_astore_3 ) {
          refs = (cmd.itype - j_istore_0) % 4;
          ref2f = (cmd.itype - j_istore_0) / 4;
          ref2f =    ref2f == ((j_lstore_0 - j_istore_0) / 4)
                  || ref2f == ((j_dstore_0 - j_istore_0) / 4);
refer:
          cmd.Op1.addr = curSeg.DataBase + (ushort)refs;
          cmd.Op1.ref = (uchar)(ref2f + 1);
          if ( (ushort)(refs + ref2f) >= curSeg.DataSize ) cmd.Op1.ref |= 0x80;
          break;
        }
      } // end refs/refx
      if ( cmd.itype < j_ifeq || cmd.itype > j_jsr ) break;
    case j_ifnull:
    case j_ifnonnull:
      cmd.Op1.addr = (short)ua_next_word();
b_near:
      cmd.Op1.type = o_near;
      cmd.Op1.offb = 1;
      cmd.Op1.addr += cmd.ip;
      if ( cmd.Op1.addr >= curSeg.CodeSize ) goto set_bad_ref;
      break;

    case j_goto_w:
    case j_jsr_w:
      cmd.Op1.addr = ua_next_long();
      goto b_near;

    case j_bipush:
      cmd.Op1.dtyp = dt_byte;
      cmd.Op1.value = (char)ua_next_byte();
      goto setdat;
    case j_sipush:
      cmd.Op1.dtyp = dt_word;
      cmd.Op1.value = (short)ua_next_word();
setdat:
      cmd.Op1.type = o_imm;
      cmd.Op1.offb = 1;
      break;

    case j_ldc:
      cmd.Op1.cp_ind = ua_next_byte();
      ctype = C_4byte;
      goto constchk;
    case j_ldcw:
      ctype = C_4byte;
      goto const2w;
    case j_ldc2w:
      ctype = C_8byte;
const2w:
      cmd.Op1.cp_ind = ua_next_word();
constchk:
      if ( !ConstLoad(ctype)) return(0 );
      break;

    case j_getstatic:
    case j_putstatic:
    case j_getfield:
    case j_putfield:
      if ( cmd.wid > 1 ) {     //_quick form
        cmd.Op1.type = o_imm;
        cmd.Op1.ref = 2;        //#data
        cmd.Op1.offb = 1;
        if ( cmd.wid == 4 ) { //???
          cmd.Op1.dtyp = dt_word;
          cmd.Op1.value = ua_next_word();
        } else {
          cmd.Op1.dtyp = dt_byte;
          cmd.Op1.value = ua_next_byte();
          ++cmd.size;           // SKIP
        }
        break;
      }
      ctype = C_Field;
      goto const2w;

    case j_new:
      ctype = C_Class;
      goto const2w;

    case j_anewarray:
//\\ ?/
    case j_checkcast:
    case j_instanceof:
      ctype = C_TypeName;
      goto const2w;

    case j_a_invokesuper:
    case j_a_invokeignored:
      goto fictarg;
    case j_invokevirtual:
    case j_a_invokevirtualobject:
      cmd.Op2.dtyp = dt_void;
      if ( cmd.wid > 1 ) {
        if ( cmd.wid == 4 ) {
fictarg:
          cmd.Op1.value = ua_next_word(); //???
          cmd.Op1.dtyp = dt_word;
        } else {
          cmd.Op2.type = o_imm;
          cmd.Op1.ref = 2;        //#data
          cmd.Op1.dtyp = cmd.Op2.dtyp = dt_byte;
          cmd.Op1.value = ua_next_byte();
          cmd.Op2.offb = 2;
          cmd.Op2.value = ua_next_byte();
        }
        cmd.Op1.offb = 1;
        cmd.Op1.type = o_imm;
        cmd.Op1.ref = 2;        //#data
        break;
      }
    case j_invokespecial:
    case j_invokestatic:
    case j_invokedynamic:
      ctype = C_Method;
      goto const2w;
    case j_invokeinterface:
      ctype = C_Interface;
      cmd.Op1.cp_ind = ua_next_word();
      cmd.Op2.type = o_imm;
      cmd.Op2.ref = 1;          //not descriptor
      cmd.Op2.dtyp = dt_byte;
      cmd.Op2.value = ua_next_byte();
      if ( cmd.wid > 1 ) {
        cmd.Op3.type = o_imm;
        cmd.Op3.ref = 2;        //#data
        cmd.Op3.value = ua_next_byte();
        cmd.Op3.offb = 4;
        cmd.Op3.dtyp = dt_byte;
      } else {
        ++cmd.size;  //reserved
        cmd.Op3.dtyp = dt_void;
      }
      goto constchk;

    case j_multianewarray:
      cmd.Op1.cp_ind = ua_next_word();
      cmd.Op2.type = o_imm;
      cmd.Op2.ref = 1;         // not descriptor
      cmd.Op2.dtyp = dt_byte;
      if ( (cmd.Op2.value = ua_next_byte()) == 0 && !debugmode) return(0 );
      ctype = C_Type;
      goto constchk;

    case j_iinc:
    case j_iload:
    case j_istore:
      cmd.Op1.dtyp = dt_dword;
      goto memref;
    case j_lload:
    case j_lstore:
      cmd.Op1.dtyp = dt_qword;
      goto memref;
    case j_fload:
    case j_fstore:
      cmd.Op1.dtyp = dt_float;
      goto memref;
    case j_dload:
    case j_dstore:
      cmd.Op1.dtyp = dt_double;
      goto memref;
    case j_aload:
    case j_astore:
      cmd.Op1.dtyp = dt_string;
      goto memref;
    case j_ret:
      cmd.Op1.dtyp = dt_code;
memref:
      if ( !LoadIndex()) return(0 );
      if ( cmd.itype == j_iinc ) {
        cmd.Op2.type = o_imm;
        cmd.Op2.ref = 0;
        cmd.Op2.offb = (uchar)cmd.size;
//\\??? Это надо???
        if ( cmd.wid ) {
          cmd.Op2.dtyp = dt_word;
          cmd.Op2.value = (short)ua_next_word();
        } else {
          cmd.Op2.dtyp = dt_byte;
          cmd.Op2.value = (char)ua_next_byte();
        }
      }
      break;

    case j_tableswitch:
    case j_lookupswitch:
      {
        int32 count;
        register uint32 top;

        cmd.swit = 1;
        for(top = (4  - uint32((cmd.ip + cmd.size) % 4)) & 3; top; top--)
          if ( ua_next_byte() ) {
            if ( !debugmode) return(0 );
            cmd.swit |= 0100;
          }
        cmd.Op3.type = o_near;
        cmd.Op3.offb = (uchar)cmd.size;
        cmd.Op3.addr = ua_next_long();
        cmd.Op3.addr += cmd.ip;
        cmd.Op3.ref = 0;

        if ( cmd.Op3.addr >= curSeg.CodeSize ) {
          if ( !debugmode) return(0 );
          ++cmd.Op3.ref;
        }

        cmd.swit |= 2;  // start out arguments

        count = ua_next_long();
        if ( cmd.itype == j_tableswitch ) {
          cmd.Op1.type  = o_imm;
          cmd.Op1.dtyp  = dt_dword;
          cmd.Op1.value = count;  // minimal value
          cmd.Op2.ref   = 0;
          cmd.Op2.type  = o_imm;
          cmd.Op2.dtyp  = dt_dword;
          count = (uint32(cmd.Op2.value = ua_next_long()) - count + 1);
        }
        cmd.Op3.value = count;
        cmd.Op2.addr = cmd.ip + cmd.size;
        top = uint32(curSeg.CodeSize - cmd.ip);
        while ( count-- ) {
          if ( cmd.itype == j_lookupswitch) ua_next_long( ); // skip pairs;
          if ( (cmd.ip + ua_next_long()) >= curSeg.CodeSize ) {
            if ( !debugmode) return(0 );
            cmd.swit |= 0200;
          }
          if ( (uint32)cmd.size >= top) return(0 );
        }
      }
      break;

    case j_newarray:
      cmd.Op1.type = o_array;       // type!
      cmd.Op1.offb = 1;
      if(   (cmd.Op1.cp_type = ua_next_byte()) < T_BOOLEAN
         || (uchar)cmd.Op1.cp_type > T_LONG) {
set_bad_ref:
        if ( !debugmode) return(0 );
        ++cmd.Op1.ref;
      }
      break;
  } // switch ( cmd.itype )

  return(cmd.size);
}

//----------------------------------------------------------------------
bool idaapi can_have_type(op_t &x)
{
  if ( x.type == o_cpool) return(   (uchar )x.cp_type == CONSTANT_Integer
                               || (uchar)x.cp_type == CONSTANT_Long);
  return(x.type == o_imm);
}

//----------------------------------------------------------------------

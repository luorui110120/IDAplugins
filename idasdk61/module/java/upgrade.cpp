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
#include "upgrade.hpp"

//----------------------------------------------------------------------
#define _TO_VERSION IDP_JDK16

//----------------------------------------------------------------------
static void make_new_name(ushort name, ushort subnam, uchar mode, unsigned ip)
{
  char  str[MAXNAMELEN];
  init_output_buffer(str, sizeof(str));
  if ( fmtString(name, sizeof(str)-2, fmt_fullname) ) {
trunc:
    trunc_name(ip, mode & 4);
  } else if ( (char)mode > 0 ) {
    register char *p = get_output_ptr();
    if ( p >= &str[sizeof(str)-3] ) goto trunc;
    *p++ = '.';
    set_output_ptr(p);
    if ( fmtString(subnam, &str[sizeof(str)-2] - p, fmt_name) ) goto trunc;
  }
  term_output_buffer();
  do_name_anyway(ip, convert_clsname(str));
  hide_name(ip);
}

//----------------------------------------------------------------------
int upgrade_db_format(int ver, netnode constnode)
{
  if(askyn_c(1, "AUTOHIDE REGISTRY\nHIDECANCEL\n"
                "The database has an old java data format.\n"
                "Do you want to upgrade it?") <= 0) qexit(1);

  switch ( ver ) {
    default:
      INTERNAL("upgrade::ver");
    case IDP_JDK12:
      break;
  }

  // change format: jdk-version
  if ( curClass.MinVers > 0x8000u ) {
badbase:
    return(0);
  }

  curClass.MajVers = JDK_MIN_MAJOR;
  if ( curClass.MinVers >= 0x8000 ) {
    curClass.MinVers &= ~0;
    ++curClass.MajVers;
    curClass.JDKsubver = 2;
  } else if ( curClass.MinVers >= JDK_1_1_MINOR ) ++curClass.JDKsubver;

// change format: This
#ifdef __BORLANDC__
#if offsetof(ClassInfo, This.Ref)  != offsetof(ClassInfo, This.Name) || \
    offsetof(ClassInfo, This.Dscr) != offsetof(ClassInfo, This.Name) + 2
#error
#endif
#endif
   curClass.This.Ref = (curClass.This.Ref << 16) | curClass.This.Dscr;
   if ( !curClass.This.Name ) goto badbase;

// change format: Super
#ifdef __BORLANDC__
#if offsetof(ClassInfo, super.Ref)  != offsetof(ClassInfo, super.Name) || \
    offsetof(ClassInfo, super.Dscr) != offsetof(ClassInfo, super.Name) + 2
#error
#endif
#endif
  switch ( curClass.super.Name ) {
    case 0:       // absent
      curClass.super.Ref &= 0;
      break;
    case 0xFFFF:  // bad index
      ++curClass.super.Name;
      break;
    default:      // reverse order
      curClass.super.Ref = (curClass.super.Ref << 16) | curClass.super.Dscr;
      break;
  }

// validate: impNode
  if ( curClass.impNode && !netnode(curClass.impNode).altval(0) ) goto badbase;

// change variable 'errload' in previous version
  if ( curClass.maxSMsize ) {
    curClass.extflg |= XFL_C_ERRLOAD;
    curClass.maxSMsize &= 0;
  }

// set segments type type for special segments
  segment_t *S;
  if ( (S = getseg(curClass.startEA)) == NULL ) goto badbase;
  S->set_hidden_segtype(true);
  S->update();
  if ( curClass.xtrnCnt ) {
    if ( (S = getseg(curClass.xtrnEA)) == NULL ) goto badbase;
    S->set_hidden_segtype(true);
    S->update();
  }

  curClass.extflg |= XFL_C_DONE;  // do not repeat datalabel destroyer :)
// change: method/fields format
#define SGEXPSZ (sizeof(SegInfo) - offsetof(SegInfo, varNode))
#define FMEXPSZ (sizeof(_FMid_) - offsetof(_FMid_, _UNUSED_ALING))
#define FLEXPSZ (sizeof(FieldInfo) - offsetof(FieldInfo, annNodes))
  uval_t  oldsize = sizeof(SegInfo) - FMEXPSZ - SGEXPSZ;

  for(int pos=-(int)curClass.MethodCnt; pos<=(int)curClass.FieldCnt; pos++) {
    union {
      SegInfo   s;
      FieldInfo f;
      _FMid_    id;
      uchar     _space[qmax(sizeof(SegInfo), sizeof(FieldInfo)) + 1];
    }u;

    if ( !pos ) {  // class node
      oldsize += (sizeof(FieldInfo) - FLEXPSZ) - (sizeof(SegInfo) - SGEXPSZ);
      continue;
    }

    if ( ClassNode.supval(pos, &u, sizeof(u)) != oldsize ) goto badbase;

    memmove((uchar *)&u.id + sizeof(u.id), &u.id._UNUSED_ALING,
            (size_t)oldsize - offsetof(_FMid_, _UNUSED_ALING));
    u.id._UNUSED_ALING = 0;
    u.id.utsign        = 0;

    if ( u.id.extflg & ~EFL__MASK ) goto badbase;
    u.id.extflg &= (EFL_NAMETYPE);

    if ( pos > 0 ) { // fields
      memset(&u.f.annNodes, 0, sizeof(u.f)-offsetof(FieldInfo, annNodes));
      ClassNode.supset(pos, &u.f, sizeof(u.f));
      continue;
    }

    // segments
    memset(&u.s.varNode, 0, sizeof(u.s) - offsetof(SegInfo, varNode));
    if ( u.s.thrNode && !netnode(u.s.thrNode).altval(0) ) {
      netnode(u.s.thrNode).kill();  // empty node (old format)
      u.s.thrNode = 0;
    }

    // have locvars?
    if ( u.s.DataSize ) {
      if ( (S = getseg(u.s.DataBase)) == NULL ) goto badbase;
      S->type = SEG_BSS;
      S->set_hidden_segtype(true);
      S->update();
    }

    // change: Exception format
    if ( u.s.excNode ) {
      register ushort i, j;
      netnode         enode(u.s.excNode);

      if ( (j = (ushort)enode.altval(0)) == 0 ) goto badbase;
      ea_t ea = u.s.startEA + u.s.CodeSize;
      i = 1;
      do {
        Exception exc;

        if ( enode.supval(i, &exc, sizeof(exc)) != sizeof(exc) ) goto badbase;

#ifdef __BORLANDC__
#if offsetof(Exception, filter.Ref)  != offsetof(Exception, filter.Name) || \
    offsetof(Exception, filter.Dscr) != offsetof(Exception, filter.Name) + 2
#error
#endif
#endif
        if ( !exc.filter.Name != !exc.filter.Dscr ) goto badbase;
        exc.filter.Ref = (exc.filter.Ref << 16) | exc.filter.Dscr; // was reverse order
        if ( exc.filter.Name == 0xFFFF ) ++exc.filter.Name;
        enode.supset(i, &exc, sizeof(exc));
        set_exception_xref(&u.s, exc, ea);
      }while ( ++i <= j );
    }
    ClassNode.supset(pos, &u.s, sizeof(u.s));
    //rename local variables (for references)
    if ( u.s.DataSize ) {
      int   i = u.s.DataSize;
      ea_t  ea = u.s.DataBase + i;
      do {
        char  str[MAXNAMELEN];
        qsnprintf(str, sizeof(str), "met%03u_slot%03u", u.s.id.Number, --i);
        --ea;
        if ( do_name_anyway(ea, str)) make_name_auto(ea );
        else hide_name(ea);
      }while ( i );
      coagulate_unused_data(&u.s);
    }
  } // for

//change format of string presentation in constant pool
  for(int pos = 0; (ushort)pos <= curClass.maxCPindex; pos++) {
    ConstOpis co;

    if ( constnode.supval(pos, &co, sizeof(co)) != sizeof(co) ) goto badbase;
    switch ( co.type ) {
      default:
        continue;

      case CONSTANT_Unicode:
        error("Base contain CONSTANT_Unicode, but it is removed from "
              "the standard in 1996 year and never normal loaded in IDA");

      case CONSTANT_Utf8:
        break;
    }
    uint32 v, n, i = pos << 16;
    if(   ((n = (uint32)constnode.altval(i)) & UPG12_BADMASK)
       || (v = n & ~UPG12_CLRMASK) == 0) goto badbase;
    if ( n & UPG12_EXTMASK ) v |= UPG12_EXTSET;
    if ( (n = (ushort)v) != 0 ) {
      register uchar *po = (uchar*)append_tmp_buffer(v);
      n *= sizeof(ushort);
      uint32 pos = 0;
      do {
        uint32 sz = n - pos;
        if ( sz > MAXSPECSIZE ) sz = MAXSPECSIZE;
        if ( constnode.supval(++i, &po[pos], sz) != sz ) goto badbase;
        constnode.supdel(i);
        pos += sz;
      }while ( pos < n );
      constnode.setblob(po, n, i & ~0xFFFF, BLOB_TAG);
      if ( !(v & UPG12_EXTSET) ) do {
#ifdef __BORLANDC__
#if ( sizeof(ushort) % 2) || (MAXSPECSIZE % 2 )
#error
#endif
#endif
        ushort cw = *(ushort *)&po[pos];
        if ( cw >= CHP_MAX ) {
          if ( !javaIdent(cw) ) goto extchar;
        } else if ( (uchar)cw <= CHP_MIN ) {
extchar:
          v |= UPG12_EXTSET;
          break;
        }
      }while ( (pos -= sizeof(ushort)) != 0 );
      v = upgrade_ResW(v);
    }
    constnode.altset(i, v);
    co._Sopstr = v; // my be not needed? (next also)
    constnode.supset(pos, &co, sizeof(co));
  }

// rename 'import' variables for refernces
  for(unsigned ip = 1; (ushort)ip <= curClass.xtrnCnt; ip++) {
    ConstOpis co;
    {
      register unsigned j;
      if(   (j = (unsigned)XtrnNode.altval(ip)) == 0
         || !LoadOpis((ushort)j, 0, &co)) goto badbase;
    }
    switch ( co.type ) {
      default:
        goto badbase;

      case CONSTANT_Class:
        if ( !(co.flag & HAS_CLSNAME) ) continue;
        break;
      case CONSTANT_InterfaceMethodref:
      case CONSTANT_Methodref:
        if ( (co.flag & NORM_METOD) != NORM_METOD ) continue;
        break;
      case CONSTANT_Fieldref:
        if ( (co.flag & NORM_FIELD) != NORM_FIELD ) continue;
        break;
    }
    make_new_name(co._name, co._subnam, co.type != CONSTANT_Class, ip);
  }

  if ( curClass.This.Dscr )
    make_new_name(curClass.This.Name, 0, (uchar)-1, (unsigned)curClass.startEA);

  return(_TO_VERSION);
}

//-----------------------------------------------------------------------
//----------------------------------------------------------------------
// some utilities (size of npool)
//----------------------------------------------------------------------
// visible for converter only
char *convert_clsname(char *buf)
{
  if ( jasmin() )
    for(register char *p = buf; (p = strchr(p, j_clspath_dlm)) != NULL; p++)
      *p = j_field_dlm;

  return(buf);
}

//-----------------------------------------------------------------------
// visible for converter only
uchar set_exception_xref(SegInfo *ps, Exception const & exc, ea_t ea)
{
  uchar ans = 0;

  if ( exc.start_pc >= ps->CodeSize ) ans = 1;
  else {
    if ( !exc.start_pc )
      ps->id.extflg |= XFL_M_LABSTART;  // special label at entry
    add_dref(ea, ps->startEA + exc.start_pc, dr_I);
  }
  if ( exc.end_pc > ps->CodeSize ) ans = 1;
  else {
    if ( exc.end_pc == ps->CodeSize )
      ps->id.extflg |= XFL_M_LABEND;  // special label at end
    add_dref(ea, ps->startEA + exc.end_pc, dr_I);
  }
  if ( exc.handler_pc >= ps->CodeSize) return(1 );
  add_dref(ea, ps->startEA + exc.handler_pc, dr_I);
  return(ans);
}

//----------------------------------------------------------------------

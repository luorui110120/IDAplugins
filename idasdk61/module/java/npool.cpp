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
#include <loader.hpp>
#include <diskio.hpp>
#include <srarea.hpp>
#include "npooluti.hpp"

#define _CUR_IDP_VER  IDP_JDK16

static const char constant_pool[] = "$ Constant Pool ~";

//-----------------------------------------------------------------------
void myBase(const char *arg)
{
  register int  i;

  if ( !arg ) {  // load old file
    if ( ConstantNode.create(constant_pool) ) goto badbase;

    register int v;
    i = sizeof(curClass);
    switch ( v = (int)ConstantNode.altval(CNA_VERSION) ) {
      default:
        error("Very old database format. Cannot convert it");

      case IDP_JDK15:
        error("Intermediate (developer) database fomat. Cannot convert it.");

      case IDP_JDK12:
        i -= sizeof(curClass) - offsetof(ClassInfo, MajVers);
        //PASS THRU
      case _CUR_IDP_VER:  // IDP_JDK16
        break;
    }

    if(   i != (int)ConstantNode.supval(CNS_CLASS, NULL, (size_t)-1)
       || ConstantNode.supval(CNS_CLASS, &curClass, sizeof(curClass)) <
                                          (int32)offsetof(ClassInfo, MajVers)
       || !curClass.ClassNode) goto badbase;

    if ( curClass.xtrnNode ) {
      if ( !curClass.xtrnCnt ) goto badbase;
      XtrnNode = curClass.xtrnNode;
    } else if ( curClass.xtrnCnt ) goto badbase;
    ClassNode = curClass.ClassNode;

    if ( v != IDP_JDK12 ) { // current JDK format
      if(   curClass.MajVers < JDK_MIN_MAJOR
         || curClass.MajVers > JDK_MAX_MAJOR)                   goto badbase;
      if ( curClass.MajVers == JDK_MIN_MAJOR ) {  // JDK1.0/1.1
        if ( curClass.JDKsubver != (curClass.MinVers >= JDK_1_1_MINOR) )
                                                                goto badbase;
      } else {
        if(   curClass.MinVers
           || curClass.MajVers - (JDK_MIN_MAJOR-1) != curClass.JDKsubver)
                                                                goto badbase;
      }
    }

    make_NameChars(0);  // initialize and set enableExr_NameChar for upgrade
    if ( v != _CUR_IDP_VER ) {
      ResW_init();  // prepare RW-find
      if ( (v = upgrade_db_format(v, ConstantNode)) == 0 ) {
badbase:
        DESTROYED("myBase");
      }
      if ( v != _CUR_IDP_VER) INTERNAL("myBase/upgrade" );
      ConstantNode.supset(CNS_CLASS, &curClass, sizeof(curClass));
      ConstantNode.altset(CNA_VERSION, _CUR_IDP_VER);
      ConstantNode.supset(CNS_UNIMAP, &unimap, sizeof(unimap));
    } else {
      if ( (v = curClass.maxStrSz) != 0 )
        tsPtr = (ushort*)myAlloc(sizeof(ushort)*(v+1));
      if ( (v = curClass.maxSMsize) != 0 )
        smBuf = (uchar*)myAlloc(v+1);
      if ( (v = curClass.maxAnnSz) != 0 )
        annBuf = (uchar*)myAlloc(v+1);
      idpflags = (ushort)ConstantNode.altval(CNA_IDPFLAGS);

      if ( !ResW_oldbase() ) goto badbase;
      {
        UNIMAP  old;
        if(   ConstantNode.supval(CNS_UNIMAP, &old, sizeof(old)) != sizeof(old)
           || old.count > 0x80) goto badbase;
        if ( memcmp(&old, &unimap, sizeof(old)) ) {
          ConstantNode.supset(CNS_UNIMAP, &unimap, sizeof(unimap));
          rename_uninames(idpflags & IDF_ENCODING);
        }
      }
    }
    disableExt_NameChar();  // set standart extension
    loadpass = -1;  // no call QueueMark (and error type in fmtString)
    if ( curClass.extflg & XFL_C_DONE ) sm_node = 0;
    if ( curClass.MajVers >= JDK_SMF_MAJOR_MIN ) SMF_mode = 1;
  } else {  // new base
    if ( !ConstantNode) INTERNAL("ConstantNode" );

    char          str[MAXSPECSIZE];
    register char *ps = str;
    if ( (i = (int)strlen((char *)arg)) >= (sizeof(str)) ) {
      ps = (char *)arg + i - (sizeof(str) - 3);
      for(i = sizeof(str) - 1 - 3; i; i--) if ( *--ps == '/' ) break;
      if ( !i) error("notify: illegal file name parameter" );
      arg = ps;
      memcpy(str, "...", 3);
      ps = &str[3];
    }
    memcpy(ps, arg, i);
    if ( ps != str ) i += 3;
    ConstantNode.supset(CNS_SOURCE, str, i);
  }

  user_limiter = inf.s_limiter;
  inf.s_limiter = 0;
}

//-----------------------------------------------------------------------
bool LoadOpis(ushort index, uchar type, ConstOpis *p)
{
#define LoadAnyString(index)  LoadOpis(index, CONSTANT_Utf8, NULL)
  ConstOpis tmp;
  if ( !p ) p = &tmp;

  if(   !index
     || index > curClass.maxCPindex
     || ConstantNode.supval(index, p, sizeof(*p)) != sizeof(*p)) {
bad:
    return(false);
  }

  if ( loadpass <= 0 ) {
good:
    return(true);
  }

  if ( !(p->flag & _REF) ) {
    p->flag |= _REF;
    StoreOpis(index, p);
  }
#if MAX_CONSTANT_TYPE >= 0x20
#error
#endif
  if ( type < 0x20) return(type == 0 || type == p->type );

#define LoadNamedClass(index, p) LoadOpis(index, (uchar)-1, p)
  if ( type == (uchar)-1 )
    return(p->type == CONSTANT_Class && (p->flag & HAS_CLSNAME));

  if ( p->type != CONSTANT_Utf8 ) goto bad;

  switch ( type & 0x1F ) {
    default:
      INTERNAL("LoadOpis");
    case 0:
    case CONSTANT_Utf8:
      break;
  }
  {
    static const uchar chk[8] = {
      0x00,    // align
#define CheckAnyDscr(index, p)    LoadOpis(index, 0x20, p)
      (HAS_TYPEDSCR | HAS_CALLDSCR),
#define CheckFieldDscr(index, p)  LoadOpis(index, 0x40, p)
#define LoadFieldDscr(index, p)   LoadOpis(index, 0x40 | CONSTANT_Utf8, p)
      HAS_TYPEDSCR,
#define CheckFieldName(index, p)  LoadOpis(index, 0x60, p)
#define LoadFieldName(index)      LoadOpis(index, 0x60 | CONSTANT_Utf8, NULL)
      HAS_FLDNAME,
//#define Check...(index, p)      LoadOpis(index, 0x80, p)
      0x00,
#define CheckClass(index, p)      LoadOpis(index, 0xA0, p)
      (HAS_TYPEDSCR | HAS_CLSNAME),
#define CheckCallDscr(index, p)   LoadOpis(index, 0xC0, p)
#define LoadCallDscr(index)       LoadOpis(index, 0xC0 | CONSTANT_Utf8, NULL)
      HAS_CALLDSCR,
#define CheckClassName(index, p)  LoadOpis(index, 0xE0, p)
      HAS_CLSNAME
    };

    if ( p->flag & chk[type>>5] ) goto good;
  }

  if ( type & 0x1F ) goto bad;  // Load...

  if ( loadpass == 2 ) { // needed CR
    ++loadpass;
    msg("\n");
  }
  load_msg("Illegal reference type to Utf8#%u\n", index);
  return(loadpass >= 2);  // true when LoadPool, false after
}

//-----------------------------------------------------------------------
// for annotation
static bool isSingleClass(ushort val)
{
  ConstOpis co;

  return(   LoadFieldDscr(val, &co)
         && (co._Sflags & (_OP_VALPOS | _OP_ONECLS)) == _OP_ONECLS);
}

//-----------------------------------------------------------------------
#define MAX_ATTR_NMSZ  128
static uchar attrStr(ushort index, uchar mode, char str[MAX_ATTR_NMSZ])
{
  static const char *const name[] = {
#define a_LineNumberTable                       0 // 0x00001: code
        "LineNumberTable",
#define a_LocalVariableTable                    1 // 0x00002: code
        "LocalVariableTable",
#define a_LocalVariableTypeTable                2 // 0x00004: code
        "LocalVariableTypeTable",
#define a_StackMap                              3 // 0x00008: code (J2ME CLDC)
        "StackMap",
#define a_StackMapTable                         4 // 0x00010: code (>=JDK1.6)
        "StackMapTable",
#define a_CODE_TOP  5
#define a_ConstantValue                         5 // 0x00020: fld
        "ConstantValue",
#define a_FLD_TOP   6
#define a_Code                                  6 // 0x00040: met
        "Code",
#define a_Exceptions                            7 // 0x00080: met
        "Exceptions",
#define a_RuntimeVisibleParameterAnnotations    8 // 0x00100: met
        "RuntimeVisibleParameterAnnotations",
#define a_RuntimeInvisibleParameterAnnotations  9 // 0x00200: met
        "RuntimeInvisibleParameterAnnotations",
#define a_AnnotationDefault                    10 // 0x00400: met
        "AnnotationDefault",
#define a_MET_TOP   11
#define a_SourceFile                           11 // 0x00800: file
        "SourceFile",
#define a_InnerClasses                         12 // 0x01000: file
        "InnerClasses",
#define a_EnclosingMethod                      13 // 0x02000: file
        "EnclosingMethod",
#define a_SourceDebugExtension                 14 // 0x04000: file
        "SourceDebugExtension",
#define a_FILE_TOP  15
#define a_Signature                            15 // 0x08000: all !code
        "Signature",
#define a_Synthetic                            16 // 0x10000: all !code
        "Synthetic",
#define a_Deprecated                           17 // 0x20000: all !code
        "Deprecated",
#define a_RuntimeVisibleAnnotations            18 // 0x40000: all !code
        "RuntimeVisibleAnnotations",
#define a_RuntimeInvisibleAnnotations          19 // 0x80000: all !code
        "RuntimeInvisibleAnnotations",
// next field for check pool ONLY (must be in last position)
#define a_LocalVariables                       20 //0x100000: obsolete
        "LocalVariables"
#define a_CHECK_MASK   0x1FFFFF
      };
#define a_UNKNOWN     32
#define a_TRUNCATED   33
#define a_NONAME      34
//#if sizeof("RuntimeInvisibleParameterAnnotations") > MAX_ATTR_NMSZ
//#error
//#endif

  str[0] = '\0';
  if ( !LoadFieldName(index)) return(a_NONAME );
  if ( !fmtName(index, str, MAX_ATTR_NMSZ, fmt_name)) return(a_TRUNCATED );

  uchar i = 0, top = (uchar)(qnumber(name) - 1);
  switch ( mode ) {
    case ARQ_CODE:
      top = a_CODE_TOP;
      break;
    case ARQ_FIELD:
      i   = a_CODE_TOP;
      top = a_FLD_TOP;
      break;
    case ARQ_METHOD:
      i   = a_FLD_TOP;
      top = a_MET_TOP;
      break;
    case ARQ_FILE:
      i   = a_MET_TOP;
      top = a_FILE_TOP;
      break;
    default:
//    case ARQ_CHECK:
      ++top;
      break;
  }

repeat:
  do if ( !strcmp(name[i], str)) return(i); while(++i < top );
  if ( mode != ARQ_CODE && i < (uchar)(qnumber(name)-1) ) {
    i = a_FILE_TOP;
    top = (uchar)(qnumber(name) - 1);
    goto repeat;
  }
  return(a_UNKNOWN);
}

//-----------------------------------------------------------------------
static unsigned LoadPool(void)
{
  ConstOpis tcc;
  ushort    k;
  unsigned  ui;
  register  unsigned  i;
  register ConstOpis  *co = &tcc;

  // prepare jasmin reserved word checking
  ResW_init();

  msg("\nLoading constant pool...");
  loadpass = 2; // needed CR
  for(i = 1; (ushort)i <= curClass.maxCPindex; i++) {
    memset(co, 0, sizeof(*co));
    switch ( co->type = read1() ) {
      case CONSTANT_Long:
      case CONSTANT_Double:
        co->value2 = read4();
      case CONSTANT_Integer:
      case CONSTANT_Float:
        co->value = read4();
        break;

      case CONSTANT_NameAndType:
      case CONSTANT_Fieldref:
      case CONSTANT_Methodref:
      case CONSTANT_InterfaceMethodref:
        if ( (k = read2()) == 0 || k > curClass.maxCPindex ) {
badindex:
          error("Bad record in constant pool.\n"
                "Record %u have reference to %u\n"
                "(maxnum %u, file offset after the read is 0x%X)",
                i, k, curClass.maxCPindex, qftell(myFile));
        }
        co->_class = k;     // _subnam for name & type
      case CONSTANT_Class:
        co->ref_ip = 0;
      case CONSTANT_String:
        if ( (k = read2()) == 0 || k > curClass.maxCPindex ) goto badindex;
        co->_name = k;      // _dscr for name & type
        break;

      case CONSTANT_Unicode:
        error("File contain CONSTANT_Unicode, but it is removed from "
              "the standard in 1996 year and not supported by IDA");
        break;

      case CONSTANT_Utf8:
        co->_name = (ushort)i;  // for xtrnRef_dscr
        if ( LoadUtf8((ushort)i, co)) Parser((ushort)i, co );
        break;

      default:
        error("Bad constant type 0x%x (%u)", co->type, i);
    }  // end switch
    StoreOpis(i, co);
    if ( co->type == CONSTANT_Long || co->type == CONSTANT_Double ) {
      if ( curClass.maxCPindex == (ushort)i )
          error("Premature end of constant pool");
      ++i;
    }
  } // end for
  ResW_free();  // free mem - this set not needed later

  msg("checking...");
  loadpass = 2; // needed CR
  for(i = 1; (ushort)i <= curClass.maxCPindex; i++) {
    ConstOpis cr;
    ConstantNode.supval(i, co, sizeof(*co));
    switch ( co->type ) {
      case CONSTANT_String:
        if ( !LoadAnyString(co->_name) ) {
badname:
          k = co->_name;
          goto badref;
        }
        continue;

      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        continue;

      case CONSTANT_NameAndType:
        if ( !CheckFieldName(co->_class, &cr) )                goto badclass;
        co->flag |= ((cr.flag & HAS_FLDNAME) << SUB_SHIFT);
        if ( !CheckAnyDscr(co->_name, &cr) )                   goto badname;
        co->flag |= ((cr.flag<<SUB_SHIFT) & (SUB_TYPEDSCR | SUB_CALLDSCR));
        break;

      case CONSTANT_Class:
        if ( !CheckClass(co->_name, &cr) )                     goto badname;
        co->flag |= (cr.flag & (HAS_FLDNAME | HAS_TYPEDSCR | HAS_CLSNAME));
        co->_dscr = co->_subnam = 0;
        break;
    } // end switch
    StoreOpis(i, co);
    if(   (loadMode & MLD_EXTREF)
       && co->type == CONSTANT_Class
       && (co->flag & HAS_CLSNAME)) {

      uint32          rfc;
      register ushort j;

      for(j = 1; j <= curClass.xtrnCnt; j++)
        if ( !CmpString(co->_name, (ushort)(rfc = (uint32)XtrnNode.altval(j))) ) {
          co->_subnam = (ushort)(rfc >> 16);
          goto fnd;
        }
      XtrnNode.altset(j, (i << 16) | co->_name);
      ++curClass.xtrnCnt;
      co->_subnam = (ushort)i;
fnd:
      StoreOpis(i, co);
    }
  }  // end for
  if ( loadMode & MLD_EXTREF) XtrnNode.altdel( );  // delete all

  msg("referencing...");
  loadpass = 2; // needed CR
  for(ui = 0, i = 1; (ushort)i <= curClass.maxCPindex; i++) {
    ConstOpis cr;
    uint32    sav;

    ConstantNode.supval(i, co, sizeof(*co));
    switch ( co->type ) {
      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        continue;

      case CONSTANT_Class:
        continue;

      case CONSTANT_InterfaceMethodref:
      case CONSTANT_Fieldref:
      case CONSTANT_Methodref:
        if ( !LoadOpis(co->_class, CONSTANT_Class, &cr) ) {
badclass:
          k = co->_class;
          goto badref;
        }
//\\VALID NULL ??? go twos if any... (reorder cur ind to null)
        co->flag |= (cr.flag & HAS_CLSNAME);
        k = co->_name;
        sav = errload;
        co->ref_ip = cr._subnam;
        CheckClassName(co->_name = cr._name, NULL);
        if ( !LoadOpis(k, CONSTANT_NameAndType, &cr) ) {
badref:
          error("Bad reference (from %u to %u) in constant pool", i, k);
        }
        co->_dscr   = cr._name;
        co->_subnam = cr._class;
        co->flag |=(cr.flag & (SUB_FLDNAME | SUB_TYPEDSCR | SUB_CALLDSCR));
        if ( co->type != CONSTANT_Fieldref ) {
          CheckCallDscr(co->_dscr, NULL);
        } else CheckFieldDscr(co->_dscr, NULL);
        if ( !LoadFieldName(co->_subnam) ) --sav;
        if ( (loadMode & MLD_EXTREF) && errload == sav ) {
          XtrnNode.altset(++ui, i, '0');
          ++curClass.xtrnCnt;
        } else co->ref_ip = 0;
        break;
    } // end switch
    StoreOpis(i, co);
  }  // end for

  msg("complete\n");
  loadpass = 1; // normal error checking mode
  return(ui);
}

//-----------------------------------------------------------------------
static void setPoolReference(void)
{
  char      str[MAXNAMELEN];
  ConstOpis co;
  unsigned  i, ic, j, ii, ui;

  msg("Sorting external references...");
  for(ui = 0, i = 1; (ushort)i <= curClass.xtrnCnt; i++) {
    if ( (j = (unsigned)XtrnNode.altval(i, '0')) == 0 ) continue;
    showAddr(curClass.xtrnCnt - (ushort)i);
    ConstantNode.supval(j, &co, sizeof(co));
    if ( co._class == curClass.This.Dscr ) {
      co.ref_ip = 0;
      StoreOpis(j, &co);
      continue;
    }
    ConstOpis cr;
    ConstantNode.supval(ic = co.ref_ip, &cr, sizeof(cr));
    xtrnSet(ic, &cr, ++ui, str, sizeof(str), true);
    xtrnSet(j, &co, ++ui, str, sizeof(str), false);
    deltry(ii = i + 1, ic, ui, &co);
    for( ; (ushort)ii <= curClass.xtrnCnt; ii++) {
      if ( (j = (unsigned)XtrnNode.altval(ii, '0')) == 0 ) continue;
      ConstantNode.supval(j, &cr, sizeof(cr));
      if ( cr.ref_ip != (ushort)ic ) continue;
      xtrnSet(j, &cr, ++ui, str, sizeof(str), false);
      XtrnNode.altdel(ii, '0');
      deltry(ii + 1, ic, ui, &co);
    }
  }
  XtrnNode.altdel_all('0');

  for(i = 1; (ushort)i <= curClass.maxCPindex; i++) {
    ConstantNode.supval(i, &co, sizeof(co));
    switch ( co.type ) {
      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        break;
      case CONSTANT_Class:
        if(   co._subnam == (ushort)i
           && (ushort)i != curClass.This.Dscr
           && !co.ref_ip) xtrnSet(i, &co, ++ui, str, sizeof(str), true);
        break;
    }
  }

  for(i = 1; (ushort)i <= curClass.maxCPindex; i++) {
    ConstantNode.supval(i, &co, sizeof(co));
    switch ( co.type ) {
      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        continue;
      case CONSTANT_Class:
        break;
    }
    if ( co._subnam && co._subnam != (ushort)i ) {
      ConstOpis tmp;
      ConstantNode.supval(co._subnam, &tmp, sizeof(tmp));
      co.ref_ip = tmp.ref_ip;
      StoreOpis(i, &co);
    }
  }

  if ( (curClass.xtrnCnt = (ushort)ui) != 0 ) {
    set_segm_end(curClass.xtrnEA, curClass.xtrnEA + curClass.xtrnCnt + 1, SEGMOD_KILL);
    doByte(curClass.xtrnEA, 1);
  } else {
    XtrnNode.kill();
    curClass.xtrnNode = 0;
    del_segm(curClass.xtrnEA, SEGMOD_KILL);
    curClass.xtrnEA = 0;
  }
  msg("OK\n");
}

//-----------------------------------------------------------------------
static void CheckPoolReference(int pass)
{
  static const char emc[] = "Number of %s CONSTANT_%s: %lu\n";

  char      str[MAX_ATTR_NMSZ];
  ConstOpis co;
  unsigned  k1, k2, k3, i;
  unsigned  mask = a_CHECK_MASK;

  loadpass = 0;  // no set reference
  msg("Checking references, pass %d...\n", pass + 1);
  for(k1 = k2 = k3 = 0, i = 1; (ushort)i <= curClass.maxCPindex; i++) {
    ConstantNode.supval(i, &co, sizeof(co));
    if ( co.type == CONSTANT_Long || co.type == CONSTANT_Double ) ++i;
    if ( co.flag & _REF ) continue;
    switch ( co.type ) {
      case CONSTANT_Utf8:
        if ( !pass ) {
          register uchar j;

          ++k2;
#if ( (1 << (a_LocalVariables+1)) - 1 ) != a_CHECK_MASK
#error
#endif
          if(   (co.flag & HAS_FLDNAME)
             && mask
             && (j = attrStr((ushort)i, ARQ_CHECK, str)) <= a_LocalVariables
             && (mask & (1 << j))) mask ^= (1 << j);
          else if ( co._Ssize ) ++k3; // unnotify empty
        }
        break;

      case CONSTANT_NameAndType:
        if ( !pass ) ++k1;
        break;

      case CONSTANT_Class:
        if ( pass ){
          ++k2;
          if ( !(co.flag & HAS_CLSNAME) ) ++k3;
        }
        break;

      default:
        if ( pass ) ++k1;
        break;
    } // switch
  } // for
  if ( k1 )
    load_msg(emc, "unused", pass ? "(except Class/Type/String)" :
                                        "NameAndType", k1);
  if ( k2 ) {
    if ( k3 ) {
      load_msg(emc, pass ? "unnamed" : "unreferenced",
                    pass ? "Class" : "Utf8", k3);
      k2 -= k3;
    }
    if ( (int)k2 > 0) msg(emc, "unused", pass ? "Class" : "Utf8", k2 );
  }

  loadpass = 1;  // Normal mode
}

//-----------------------------------------------------------------------
static uchar CheckSignature(ushort index, uchar mode);
static void ValidateStoreLocVar(ushort slot, LocVar & lv)
{
  netnode     temp;
  uint32      cnt, id;
  bool        dble;
  LocVar      vals[(qmin(MAXSTR, MAXSPECSIZE)/sizeof(LocVar))];
  const char  *txt = "Invalid declaration";

  lv.ScopeTop = (ushort)(id = (uint32)lv.ScopeBeg + lv.ScopeTop);

  if ( slot >= curSeg.DataSize || id > curSeg.CodeSize ) goto baddecl;

  dble = false;
  if ( curSeg.varNode ) {
    temp = curSeg.varNode;
    if ( (cnt = (uint32)temp.altval(slot)) != 0 ) {
      if ( (int32)cnt < 0 ) {
        cnt = -(int32)cnt;
        dble = true;
      }
      if(   (cnt % sizeof(LocVar))
         || cnt >= sizeof(vals)
         || temp.supval(slot, vals, cnt+1) != cnt) goto interr;
      cnt /= sizeof(LocVar);
    }
  } else {
    temp.create();
    curSeg.varNode = temp;
    cnt = 0;
  }

  if ( !lv.utsign ) { // base declaration
    ConstOpis opis;

#ifdef __BORLANDC__
#if offsetof(LocVar, utsign)+sizeof(lv.utsign) != sizeof(LocVar)
#error
#endif
#endif
    for(id = 0; id < cnt; id++) // skip full duplication
      if ( !memcmp(&lv, &vals[id], offsetof(LocVar, utsign)) ) return;

    if(   !LoadFieldName(lv.var.Name)
       || !LoadFieldDscr(lv.var.Dscr, &opis)) goto baddecl;

#ifdef __BORLANDC__
#if offsetof(ConstOpis, _Sflags) - offsetof(ConstOpis, _Ssize) != 2
#error
#endif
#endif
    if ( !dble && opis._Sopstr == (1 | (_OP_UTF8_ << 16)) ) {
      uchar tmp[sizeof(ushort)+1];
      if ( ConstantNode.supval((uint32)lv.var.Dscr << 16, tmp, sizeof(tmp ),
                             BLOB_TAG) != sizeof(ushort)) goto interr;
      switch ( tmp[0] ) {
        case j_double:
        case j_long:
          dble = true;
          if ( slot+1 == curSeg.DataSize ) goto baddecl;
        default:
          break;
      }
    }

    txt = "Too many variants";
    if ( cnt == qnumber(vals)-1 ) goto baddecl;

    if ( !lv.ScopeBeg )
      curSeg.id.extflg |= XFL_M_LABSTART; // special label at entry
    if ( lv.ScopeTop == curSeg.CodeSize )
      curSeg.id.extflg |= XFL_M_LABEND;   // special label at end
    {
      ea_t dea = curSeg.DataBase + slot;
      add_dref(dea, curSeg.startEA + lv.ScopeBeg, dr_I);
      add_dref(dea, curSeg.startEA + lv.ScopeTop, dr_I);
    }
    xtrnRef_dscr(curSeg.startEA + lv.ScopeBeg, &opis);
    if ( !cnt )
      set_lv_name(lv.var.Name, curSeg.DataBase + slot,
                  (loadMode & MLD_LOCVAR) ? 3 : 0);  // if not rename_on_load ONLY mark
    vals[cnt++] = lv;
  } else {  // signature declaration
#ifdef __BORLANDC__
#if offsetof(LocVar, var.Dscr)+sizeof(lv.var.Dscr)+sizeof(lv.utsign) != \
                                                              sizeof(LocVar)
#error
#endif
#endif
    for(id = 0; id < cnt; id++)
      if ( !memcmp(&lv, &vals[id], offsetof(LocVar, var.Dscr)) ) {
        if ( !vals[id].utsign ) {
          if ( !CheckSignature(lv.utsign, ARQ_CODE) ) goto baddecl;
          vals[id].utsign = lv.utsign;
          goto store;
        }
        if ( vals[id].utsign == lv.utsign ) return;
        txt = "Different signature";
        goto baddecl;
      }
    txt = "Signature without type";
    goto baddecl;
  }
store:
  cnt *= sizeof(LocVar);
  temp.supset(slot, vals, cnt);
  if ( !lv.utsign ) {
    if ( dble) cnt = -(int32 )cnt;
    temp.altset(slot, cnt);
  }
  return;

baddecl:
  load_msg("%s LocVar#%u Method#%u (name#%u dsc#%u sgn#%u scope:%u-%u)\n",
           txt, slot, curSeg.id.Number,
           lv.var.Name, lv.var.Dscr, lv.utsign, lv.ScopeBeg, lv.ScopeTop);
  return;

interr:
  INTERNAL("StoreLocVar");
}

//-----------------------------------------------------------------------
static inline void BadRefFile(const char *to, ushort id)
{
  BadRef(BADADDR, to, id, ARQ_FILE);
}

//-----------------------------------------------------------------------
static uchar *annot_elm(uchar *ptr, uint32 *psize, uchar is_array=0);
static uchar *annotation(uchar *p, uint32 *psize)
{
  if ( *psize < 2 ) {
bad:
    return(NULL);
  }
  *psize -= 2;
  unsigned pairs= read2();
  *(ushort *)p = (ushort)pairs;
  p += sizeof(ushort);
  if ( pairs ) do {
    if ( *psize < 2 ) goto bad;
    *psize -= 2;
    ushort id = read2();
    if ( !LoadFieldName(id) ) goto bad;
    *(ushort *)p = id;
    if ( (p = annot_elm(p+sizeof(ushort), psize)) == NULL ) goto bad;
  }while ( --pairs );
  return(p);
}

//---------------------------------------------------------------------------
static uchar *annot_elm(uchar *ptr, uint32 *psize, uchar is_array)
{
  if ( *psize < 1+2 ) {
bad:
    return(NULL);
  }
  *psize -= 1+2;
  register union {
    uchar   *p1;
    ushort  *p2;
  };
  p1 = ptr;
  uchar   tag = read1();
  ushort  val = read2();
  *p1++ = tag;
  *p2++ = val;
  switch ( tag ) {
    case j_annotation:
      if(   isSingleClass(val)
         && (p1 = annotation(p1, psize)) != NULL) goto done;
    default:
      goto bad;

    case j_array:
      if ( val && !is_array) {  // multidimensional array is not valid (javac )
        uchar *ps = p1;
        uchar tag = 0;
        do {
          if ( (p1 = annot_elm(p1, psize, 1)) == NULL ) goto bad;
          if ( !tag ) {
            if ( val == 1 ) break;
            tag = *ps;
            ps = p1;
          } else if ( tag != (uchar)-1 ) {
            if ( tag != *ps ) goto bad;
            tag = (uchar)-1;
          }
        }while ( --val );
        goto done;
      }
      goto bad;

    case j_enumconst:
      if ( LoadFieldDscr(val, NULL) ) {
        if ( *psize < 2 ) goto bad;
        *psize -= 2;
        *p2++ = val = read2();
        if ( LoadFieldName(val) ) goto done;
      }
      goto bad;

    case j_class_ret:
      if ( isSingleClass(val) ) goto done;
      goto bad; //### in 'classfile.pdf' j_void_ret also remebemered?

    case j_string:
      tag = CONSTANT_Utf8;
      break;
    case j_float:
      tag = CONSTANT_Float;
      break;
    case j_long:
      tag = CONSTANT_Long;
      break;
    case j_double:
      tag = CONSTANT_Double;
      break;
    case j_int:
    case j_byte:
    case j_char:
    case j_short:
    case j_bool:
      tag = CONSTANT_Integer;
      break;
  }
  if ( !LoadOpis(val, tag, NULL) ) goto bad;
done:
  return(p1);
}

//-----------------------------------------------------------------------
static bool sm_chkargs(uchar **pptr, uint32 *pDopSize, ushort cnt)
{
  register union {
    uchar   *p1;
    ushort  *p2;
  };
  p1 = *pptr;
  uint32 dopsize = *pDopSize;
  bool  result = false;

  do {
    if ( !dopsize ) goto declerr_w;
    --dopsize;
    uchar tag = read1();
    if ( tag > ITEM_Uninitialized ) goto declerr_w;
    *p1++ = tag;
#ifdef __BORLANDC__
#if ( ITEM_Object+1 ) != ITEM_Uninitialized
#error
#endif
#endif
    if ( tag >= ITEM_Object ) {
      if ( dopsize < 2 ) goto declerr_w;
      dopsize -= 2;
      ushort var = read2();
      if ( tag == ITEM_Object ) {
        ConstOpis opis;
        if ( var == curClass.This.Dscr ) {
          var = curClass.This.Name;
          p1[-1] = ITEM_CURCLASS;
        } else if ( LoadNamedClass(var, &opis) ) {
          var = opis._name;
        } else {
          p1[-1] = ITEM_BADOBJECT;
        }
      } else { // Uninitialized (offset to new instruction)
        if ( !var ) curSeg.id.extflg |= XFL_M_LABSTART; // PARANOYA
        else if ( var >= curSeg.CodeSize ) goto declerr_w;
      }
      *p2++ = var;
    }
  }while ( --cnt );
  result = true;
  *pptr = p1;
declerr_w:
  *pDopSize = dopsize;
  return(result);
}

//-----------------------------------------------------------------------
static int sm_load(ushort declcnt, uint32 *pDopSize)
{
  union {
    uchar   *p1;
    ushort  *p2;
  };
  sm_info_t smr;
  uint32    dopsize = *pDopSize;
  netnode   temp(curSeg.smNode);
  int       result = 0;
  unsigned  prevoff = (unsigned)-1;

#ifdef __BORLANDC__
#if sizeof(ushort) != 2
#error
#endif
#endif
  p1 = sm_realloc(dopsize);
  dopsize -= 2;     // skip READED counter
  *p2++ = declcnt;  // counter
  smr.noff = (uint32)(p1 - smBuf);
  smr.fcnt = 0;
  do {
    ea_t      refea;
    unsigned  nxcnt;
    uchar     rectype = SMT_FULL_FRAME;
    if ( SMF_mode ) {  // >=JDK6
      if ( !dopsize ) goto declerr_w;
      --dopsize;
      rectype = read1();
      *p1++ = rectype;
    }
    {
      unsigned off;
      if ( rectype < SMT_SAME_FRM_S1 ) {
        if ( rectype > SMT_SAME_FRM_S1_max ) goto declerr_w; // reserved
        off = rectype;
        if ( rectype >= SMT_SAME_FRM_S1_min ) off -= SMT_SAME_FRM_S1_min;
      } else {
        if ( dopsize < 2 ) goto declerr_w;
        dopsize -= 2;
        off = read2();
        *p2++ = (ushort)off;
      }
      if ( SMF_mode) off += (prevoff + 1 );  // >=JDK6
      if ( (uint32)off >= curSeg.CodeSize ) goto declerr_w;
      prevoff = off;
      refea = curSeg.startEA + off;
    }
    if ( temp.supval(refea, NULL, 0) != -1 ) { // for CLDC only
      --result;
      goto declerr_w;
    }
    nxcnt = smr.fcnt;
    if ( rectype == SMT_FULL_FRAME ) {
      for(int pass = 0; pass < 2; pass++) {
        ushort cnt;

        if ( dopsize < 2 ) goto declerr_w;
        dopsize -= 2;
        *p2++ = cnt = read2(); // number of locals / number of stacks
        if ( !pass ) nxcnt = cnt;
        if ( cnt && !sm_chkargs(&p1, &dopsize, cnt) ) goto declerr_w;
      }
    } else if ( rectype > SMT_SAME_FRM_S0 ) {
      rectype -= SMT_SAME_FRM_S0;
      if ( !sm_chkargs(&p1, &dopsize, rectype) ) goto declerr_w;
      nxcnt += rectype;
    } else if ( rectype >= SMT_SAME_FRM_S1 ) {
      rectype = (uchar)SMT_SAME_FRM_S0 - rectype;
      if ( (int)(nxcnt -= rectype) < 0 ) goto declerr_w;
    } else if ( rectype >= SMT_SAME_FRM_S1_min ) {
      if ( !sm_chkargs(&p1, &dopsize, 1) ) goto declerr_w;
    }
    smr.eoff = (uint32)(p1 - smBuf);
    temp.supset(refea, &smr, sizeof(smr));
    smr.noff = smr.eoff;
    smr.fcnt = nxcnt;
  }while ( --declcnt );
//
  temp.altset(-1, smr.noff);
  temp.setblob(smBuf, smr.noff, 0, BLOB_TAG);
  ++result;
declerr_w:
  *pDopSize = dopsize;
  return(result);
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
static void LoadAttrib(uchar mode)
{
  static int32  savesize = -1;
  static uchar  sde = 0;

  char      atrs[MAX_ATTR_NMSZ+2], diastr[128];
  ushort    k;
  unsigned  i, j, r;
  uint32    dopsize;
  ConstOpis opis;
  netnode   temp;
  uval_t    *pann;
  uchar     eflg, lvtb = 0, lntb = 0, fat = !(loadMode & MLD_FORCE);
  opis._name = 0;  // for vc

  j = read2();
  for(i = 0; i < j; i++) {
    if ( savesize >= 0 && (savesize -= 6) < 0 ) {
recurserr:
      error("Illegal size of declaration%s", mk_diag(mode, diastr));
    }
    k = read2();  // nameindex
    dopsize = read4();
    if ( savesize >= 0 && (savesize -= dopsize) < 0 ) goto recurserr;

    eflg = 0;  // flag(additional attributes/locvars/annotation/stackmap)
    atrs[0] = ' ';  // for additinal attibutes (mark SourceDebugExtension)
    switch ( attrStr(k, mode, &atrs[1]) ) {
      case a_SourceDebugExtension:
        if ( sde ) goto duplerr_w;
        ++sde;
        if ( dopsize < 0x10000 ) {
          if ( !dopsize ) {
            deb(IDA_DEBUG_LDR,
                "Ignore zero length SourceDebugExtension attribute\n");
            break;
          }
          uint32 pos = qftell(myFile), ssz = FileSize;
          if ( LoadUtf8((ushort)-1, (ConstOpis*)dopsize) ) {
            curClass.extflg |= XFL_C_DEBEXT;
            break;
          }
          qfseek(myFile, pos, SEEK_SET);
          FileSize = ssz;
        }
        if(askyn_c(1, "HIDECANCEL\n"
             "SourceDebugExtension attribute have a non standard encoding\n"
             "or large size and can not be represented in assembler.\n\n"
             "\3Do you want to store it in external file?") == 1)
                                                              goto attr2file;
        goto skipAttr;

      case a_UNKNOWN:
        atrs[0] = mode;
        if ( loadMode & MLD_EXTATR ) {
attr2file:
          const char *p = CopyAttrToFile(atrs, dopsize, k);
          if ( !p ) break;
          error("%s %sattribute '%s'%s", p,
                atrs[0] == ' ' ? "" : "additional ", &atrs[1],
                mk_diag(mode, diastr));
        }
        if ( idpflags & IDM_REQUNK ) {
          idpflags &= ~IDM_REQUNK;
          if(askyn_c(1, "HIDECANCEL\n"
                        "\3File contains unknown attribute(s).\n"
                        "Do you want store it in external files?\n\n") == 1) {
            loadMode |= MLD_EXTATR;
            goto attr2file;
          }
        }
        eflg = 1;
        goto unkAttr;
      case a_NONAME:
        qsnprintf(atrs, sizeof(atrs), "(with index %u)", k);
        goto notify;
      case a_TRUNCATED:
        qstrncat(atrs, "...", sizeof(atrs));
unkAttr:
        atrs[0] = '"';
        qstrncat(atrs, "\"", sizeof(atrs));
notify:
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4191)
#endif
#define VMSG (void (*)(const char *,...))msg
        ((eflg && !(idpflags & IDM_WARNUNK)) ? VMSG : load_msg)(
            "Ignore%s %s attribute (size %u)%s\n",
            (uchar)atrs[0] == ' ' ? "" : " unknown",
            atrs, dopsize, mk_diag(mode, diastr));
#undef VMSG
#ifdef _MSC_VER
#pragma warning(pop)
#endif
skipAttr:
        if ( dopsize ) {
real_skipAttr:
          skipData(dopsize);
        }
        break;

      case a_ConstantValue:
        if ( dopsize != 2 || !LoadOpis(k = read2(), 0, &opis) ) {
declerr:
          ++fat;
declerr_w:
          load_msg("Illegal declaration of %s%s\n",
                                    &atrs[1], mk_diag(mode, diastr));
          goto skipAttr;
        }

        if ( !(temp = curField.valNode) ) {
          temp.create();
          curField.valNode = temp;
          r = 0;
        } else r = (unsigned)temp.altval(0);
        switch ( opis.type ) {
          case CONSTANT_Integer:
          case CONSTANT_Long:
          case CONSTANT_Float:
          case CONSTANT_Double:
          case CONSTANT_String:
            temp.supset(++r, &opis, sizeof(opis));
            break;
          default:
            BadRef(curClass.startEA + curField.id.Number, "value", k, mode);
            temp.altset(++r, (((uint32)k) << 16) | 0xFFFF);
            break;
        }
        temp.altset(0, r);
        break;

      case a_Code:
        if ( curSeg.CodeSize ) {
//duplerr:
          ++fat;
duplerr_w:
          (fat ? error : load_msg)("Duplicate %s attribute declaration%s",
                                   &atrs[1], mk_diag(mode, diastr));
          goto skipAttr;
        }
        r = curClass.JDKsubver ? 12 : 8;
        if ( dopsize < r ) goto declerr;
        dopsize -= r;
        r -= 8;
        curSeg.stacks = r ? read2() : read1();
        curSeg.DataSize = r ? read2() : read1();     //max_locals
        if ( (curSeg.CodeSize = r ? read4() : read2()) != 0 ) {
          if ( dopsize < curSeg.CodeSize ) goto declerr;
          dopsize -= curSeg.CodeSize;
          if ( FileSize < curSeg.CodeSize) errtrunc( );
          FileSize -= curSeg.CodeSize;
          {
            segment_t *S = _add_seg(-1);  // expand size
            if ( curSeg.DataSize )
              SetDefaultRegisterValue(S, rVds, _add_seg(2)->sel); //dataSeg
          }
        }

        if ( (k = read2()) != 0 ) {               //except. table
          if ( !curSeg.CodeSize ) goto declerr;

          r = ((uint32)k) * (2*4);
          if ( r > dopsize ) goto declerr;
          dopsize -= r;
          temp.create();
          curSeg.excNode = temp;
          temp.altset(0, k);
          ea_t ea = curSeg.startEA + curSeg.CodeSize;
          r = 1;
          uchar err = 0;
          do {
            Exception exc;

            exc.start_pc    = read2();
            exc.end_pc      = read2();
            exc.handler_pc  = read2();

            exc.filter.Ref &= 0;  // for 'finally'
            if ( (exc.filter.Dscr = read2()) != 0 )
            {
              if ( !LoadNamedClass(exc.filter.Dscr, &opis) )
                BadRef(ea, ".catch", exc.filter.Dscr, mode);
              else {
                exc.filter.Name = opis._name;
                xtrnRef(ea, &opis);
              }
            }
            temp.supset(r++, &exc, sizeof(exc));
            err |= set_exception_xref(&curSeg, exc, ea); // as procedure for base converter
          }while ( (ushort)r <= k );
          if ( err ) {
            QueueMark(Q_noValid, ea);
            load_msg("Invalid address(es) in .catch%s\n",
                     mk_diag(mode, diastr));
          }
        } // exception table

        savesize = dopsize;
        LoadAttrib(ARQ_CODE);  //Additional attr
        savesize = -1;
        break;

      case a_Exceptions:
        if ( curSeg.thrNode ) goto duplerr_w;
        if ( dopsize < (2+2) || (dopsize % 2) ) goto declerr_w;
        dopsize -= 2;
        if ( (dopsize / 2) != (uint32)read2() ) goto declerr_w;
        dopsize /= 2;
        temp.create();
        curSeg.thrNode = temp;
        r = 0;
        do if ( (k = read2()) == 0 )
          load_msg("Ignore zero exception index%s\n", mk_diag(mode, diastr));
        else {
          uint32 refd = (uint32)k << 16;
          if ( !LoadNamedClass(k, &opis) )
            BadRef(curSeg.startEA, ".throws", k, mode);
          else {
            refd |= opis._name;
            xtrnRef(curSeg.startEA, &opis);
          }
          temp.altset(++r, refd);
        }while ( --dopsize );
        temp.altset(0, r);
        break;

      case a_LineNumberTable:
        if ( lntb ) goto duplerr_w;
        ++lntb;
        r = dopsize - 2;
        if ( dopsize < 2 || (r % 4) ) goto declerr_w;
        dopsize -= 2;
        if ( (r /= 4) != (uint32)read2() ) goto declerr_w;
        if ( !dopsize ) {
//Symantec error (strip) #1
          deb(IDA_DEBUG_LDR,
              "Stripped declaration of LineNumber table%s\n",
              mk_diag(mode, diastr));
        }
        while ( r-- ) {
          if ( (uint32)(k = read2()) < curSeg.CodeSize )
            set_source_linnum(curSeg.startEA + k, read2());
          else load_msg("Illegal address (%u) of source line %u%s\n", k,
                        read2(), mk_diag(mode, diastr));
        }
        break;

      case a_LocalVariableTypeTable:
        if ( !(lvtb & 1) ) { // ATT: my be can before LocalVariableTable?
          (fat ? error : load_msg)("%s before LocalVariableTable%s",
                                   atrs, mk_diag(mode, diastr));
          goto skipAttr;
        }
        ++eflg; // 2 <= 1 + 1
        //PASS THRU
      case a_LocalVariableTable:
        ++eflg; // 1
        if ( lvtb & eflg ) goto duplerr_w;
        lvtb |= eflg;
        --eflg; // unification (0/1)
        r = dopsize - 2;
        if ( dopsize < 2 || (r % 10) ) goto declerr_w;
        dopsize -= 2;
        if ( (r /= 10) != (uint32)read2() ) goto declerr_w;
        while ( r-- ) {
          LocVar  lv;

          lv.ScopeBeg = read2();  // start_pc
          lv.ScopeTop = read2();  // length
          lv.var.Name = read2();  // name
#ifdef __BORLANDC__
#if offsetof(LocVar,utsign) != offsetof(LocVar,var.Dscr)+sizeof(lv.var.Dscr)\
    || sizeof(lv.var.Dscr)*2 != sizeof(uint32)
#error
#endif
#endif
          *(uint32 *)&lv.var.Dscr &= 0;
          (&lv.var.Dscr)[eflg] = read2(); // LocalVariableTable/LocalVariableTypeTable
          k = read2();   // slot (index)
          if ( !eflg ) { // normal table
            if ( !k && !lv.var.Name && !lv.ScopeBeg && lv.ScopeTop <= 1 ) {
//Symantec error (strip) #2
              deb(IDA_DEBUG_LDR,
                  "Stripped declaration of local variables%s\n",
                  mk_diag(mode, diastr));
              continue;
            }
            if ( (short)lv.ScopeBeg == -1 ) {
//Microsoft VisualJ++ error (purge?)
              LoadAnyString(lv.var.Name);
              LoadAnyString(lv.var.Dscr);
              deb(IDA_DEBUG_LDR,
                  "Purged declaration of LocVar#%u%s\n", k,
                  mk_diag(mode, diastr));
              continue;
            }
          }
          ValidateStoreLocVar(k, lv);
        } // while
        break;

      case a_SourceFile:
        if ( dopsize != 2 ) goto declerr_w;
        if ( LoadAnyString(k = read2()) ) curClass.SourceName = k;
        else  BadRef(BADADDR, "source file name", k, mode);
        break;

      case a_InnerClasses:
        r = dopsize - 2;
        if ( dopsize < 2 || (r % 8) ) goto declerr_w;
        dopsize -= 2;
        if ( (r /= 8) != (uint32)read2() ) goto declerr_w;
        if ( !r ) {
          deb(IDA_DEBUG_LDR, "Stripped declaration of InnerClasses\n");
          break;
        }
        dopsize = r;
        k = 0;
        while ( dopsize-- ) {
          InnerClass  ic;

          *(uchar *)&k = 0;
          ic.inner = read2();
          if ( ic.inner && !LoadNamedClass(ic.inner, &opis) )  k |= 0x101;
          else ic.inner = opis._name;
          ic.outer = read2();
          if ( ic.outer && !LoadNamedClass(ic.outer, &opis) )  k |= 0x101;
          else ic.outer = opis._name;
          ic.name = read2();
          if ( ic.name && !LoadFieldName(ic.name) )            k |= 0x101;
          ic.access = read2();
          r = ic.access & ACC_ACCESS_MASK;
          if ( r & (r-1) )                                     k |= 0x101;
          if ( !(uchar)k ) {
            if ( !(temp = curClass.innerNode) ) {
              temp.create();
              curClass.innerNode = temp;
              r = 0;
            } else r = (unsigned)temp.altval(0);
            temp.supset(++r, &ic, sizeof(ic));
            temp.altset(0, r);
          }
        }
        if ( k) load_msg("Error declaration(s) in Inner Classes\n" );
        break;

      case a_EnclosingMethod:
        if ( curClass.encClass ) goto duplerr_w;
        if ( dopsize != 4 ) goto declerr_w;
        curClass.encClass = LoadNamedClass(read2(), &opis) ? opis._name :
                                                             0xFFFF;
        k = read2();
        if ( curClass.encClass == 0xFFFF ) {
bad_encl:
          msg("Invalid EnclosingMethod description\n");
        } else if ( k ) {
          if(   !LoadOpis(k, CONSTANT_NameAndType, &opis)
             || !(opis.flag & SUB_FLDNAME)
             || !LoadCallDscr(opis._name)) goto bad_encl;
          curClass.encMethod = k;
        }
        break;

      case a_Synthetic:
        if ( dopsize ) goto declerr_w;
        switch ( mode ) {
          default:  // ARQ_CODE
            goto declerr_w; // paranoya
          case ARQ_FIELD:
            curField.id.access |= ACC_SYNTHETIC;
            break;
          case ARQ_METHOD:
            curSeg.id.access |= ACC_SYNTHETIC;
            break;
          case ARQ_FILE:
            curClass.AccessFlag |= ACC_SYNTHETIC;
            break;
        }
        break;

      case a_Deprecated:
        if ( dopsize ) goto declerr_w;
        switch ( mode ) {
          default:  // ARQ_CODE
            goto declerr_w; // paranoya
          case ARQ_FIELD:
            curField.id.extflg |= XFL_DEPRECATED;
            break;
          case ARQ_METHOD:
            curSeg.id.extflg |= XFL_DEPRECATED;
            break;
          case ARQ_FILE:
            curClass.extflg |= XFL_DEPRECATED;
            break;
        }
        break;

      case a_Signature:
        if ( dopsize != 2 || mode == ARQ_CODE ) goto declerr_w;
        if ( CheckSignature(k = read2(), mode)) switch(mode ) {
          case ARQ_FIELD:
            curField.id.utsign = k;
            break;
          case ARQ_METHOD:
            curSeg.id.utsign = k;
            break;
          case ARQ_FILE:
            curClass.utsign = k;
            break;
        }
        break;

      case a_StackMapTable:
        ++eflg;
      case a_StackMap:
        if ( !eflg != (curClass.JDKsubver < 6) ) {
          (fat ? error : load_msg)("JDK1.%u incompatible with attribute%s%s",
                                   curClass.JDKsubver, atrs,
                                   mk_diag(mode, diastr));
          goto skipAttr;
        }
        if ( curSeg.smNode ) goto duplerr_w;
        if ( dopsize < 2 ) goto declerr_w;
        if ( (k = read2()) == 0 ) {
          dopsize -= 2;
          curSeg.smNode = BADNODE;
          deb(IDA_DEBUG_LDR,
              "Empty%s attribute%s\n", atrs, mk_diag(mode, diastr));
          curSeg.id.extflg |= XFL_M_EMPTYSM;
        } else {
          temp.create();
          curSeg.smNode = temp;
          if ( (int)(r = sm_load(k, &dopsize)) <= 0 ) {
            temp.kill();
            curSeg.smNode = BADNODE;
            if ( !r ) goto declerr_w;
            (fat ? error : load_msg)("Inconsistent declaration of %s%s",
                                     &atrs[1], mk_diag(mode, diastr));
            goto skipAttr;
          }
        }
skip_excess:
        if ( dopsize ) {
          deb(IDA_DEBUG_LDR,
              "Excess %u bytes in%s attribute%s\n", dopsize, atrs,
              mk_diag(mode, diastr));
          goto real_skipAttr;
        }
        break;

      case a_AnnotationDefault:
        pann = &curSeg.annNodes[2];
        eflg = 4; // as flag
        goto do_annot1;
      case a_RuntimeInvisibleParameterAnnotations:
        ++eflg;
        //PASS THRU
      case a_RuntimeVisibleParameterAnnotations:
        pann = &curSeg.annNodes[3];
        eflg |= 2;  // flag of secondary loop
do_annot1:
        if ( mode != ARQ_METHOD ) goto declerr_w;  // paranoya
        goto do_annot;
      case a_RuntimeInvisibleAnnotations:
        ++eflg;
        //PASS THRU
      case a_RuntimeVisibleAnnotations:
        switch ( mode ) {
          default:  // ARQ_CODE
            goto declerr_w; // paranoya
          case ARQ_FILE:
            pann = curClass.annNodes;
            break;
          case ARQ_FIELD:
            pann = curField.annNodes;
            break;
          case ARQ_METHOD:
            pann = curSeg.annNodes;
            break;
        }
do_annot:
        if ( eflg & 1 ) ++pann;  // invisible
        if ( *pann ) goto duplerr_w;
        temp.create();
        *pann = temp;
        if ( !dopsize ) goto declerr_w;
        {
#ifdef __BORLANDC__
#if sizeof(ushort) != 2
#error
#endif
#endif
          register uchar *p = annotation_realloc(dopsize);
          r = 1;  // no paramsloop
          if ( eflg & 2 ) { // Parameters
            r = read1();
            *p++ = (uchar)r;
            --dopsize;
            if ( !r ) goto annot_err;
          }
          if ( eflg & 4 ) { // defalut
            if ( (p = annot_elm(p, &dopsize)) != NULL ) goto annot_done;
annot_err:
            temp.kill();
            *pann = (uval_t)-1; // as flag for duplicates
            goto declerr_w;
          }
          do {  // loop for Parameters
            if ( dopsize < 2 ) goto annot_err;
            unsigned cnt = read2();
            dopsize -= 2;
            *(ushort *)p = (ushort)cnt;
            p += sizeof(ushort);
            if ( !cnt ) {
              if ( !(eflg & 2) ) goto annot_err; // no parameters
              continue;
            }
            eflg |= 8;  // flag for parameters
            do {
              if ( dopsize < 2 ) goto annot_err;
              dopsize -= 2;
              ushort id = read2();
              if ( !isSingleClass(id) ) goto annot_err;
              *(ushort*)p = id;
              if ( (p = annotation(p + sizeof(ushort), &dopsize)) == NULL )
                                                              goto annot_err;
            }while ( --cnt );
          }while ( --r );  // parameters loop
          if ( eflg == 2 ) goto annot_err; // empty Parameters annotation
annot_done:
          r = (unsigned)(p - annBuf);
        } // local variable block
        temp.setblob(annBuf, r, 0, BLOB_TAG);
        temp.altset(0, r);
        goto skip_excess;

      default:
        INTERNAL("LoadAttrib");
    }  //switch
  }  // for
}

//-----------------------------------------------------------------------
static uchar CheckSignature(ushort index, uchar mode)
{
  char      diastr[128];
  ConstOpis opis;

  if ( !LoadOpis(index, CONSTANT_Utf8, &opis) ) {
bad:
    if ( mode != ARQ_CODE )  // not debug variable
      load_msg("Invalid signature (#%u)%s\n", index, mk_diag(mode, diastr));
    return(0);
  }

#if HAS_TYPEDSCR >= 0x100 || HAS_CALLDSCR >= 0x100
#error
#endif
  if ( !((uchar)opis.flag & ((mode == ARQ_METHOD ) ? HAS_CALLDSCR :
                                                  HAS_TYPEDSCR))) {
    if ( !opis._Ssize ) goto bad; // PARANOYA
    if ( opis._Sflags & (_OP_EXTSYM_ | _OP_NOSIGN) ) goto bad;
    opis._Sflags &= (_OP_VALPOS | _OP_METSIGN | _OP_CLSSIGN);
    switch ( mode ) {
      case ARQ_METHOD:
        if ( (opis._Sflags &= ~_OP_METSIGN) != _OP_VALPOS ) goto bad;
        break;
      case ARQ_FILE:
        opis._Sflags &= ~_OP_CLSSIGN;
        //PASS THRU
      default:  // FIELD & .var
        if ( opis._Sflags ) goto bad;
        break;
    }
  }
  return(1);
}

//-----------------------------------------------------------------------
//
// This function should read the input file (it is opened in binary mode)
// analyze it and:
//      - loading segment and offset are in inf.BaseAddr &
//      - load it into the database using file2base(),mem2base()
//        or allocate addresses by enable_flags() and fill them
//        with values using putByte(), putWord(), putLong()
//      - (if createsegs) create segments using
//          add_segm(segment_t *,const char *name,const char *sclass,int flags)
//        or
//          add_segm(unsigned short,ea_t,ea_t,char *,char *)
//        see segment.hpp for explanations
//      - set up inf.startIP,startCS to the starting address
//      - set up inf.minEA,inf.maxEA
//
//
void loader(FILE *fp, bool manual)
{
  ushort    j;
  ConstOpis opis;
  unsigned  i;

  memset(&curClass, 0, sizeof(curClass));
  eseek(fp, 0);   //rewind
  FileSize = efilelength(myFile = fp);

  if ( read4() != MAGICNUMBER) error("Illegal magic number" );

  curClass.MinVers = read2();
  curClass.MajVers = read2();

  if ( curClass.MajVers <= JDK_MIN_MAJOR ) {
    if ( curClass.MajVers < JDK_MIN_MAJOR ) goto badvers;
    curClass.JDKsubver = (uchar)(curClass.MinVers >= JDK_1_1_MINOR);
  } else if ( curClass.MajVers > JDK_MAX_MAJOR || curClass.MinVers ) {
badvers:
    error("Unsupported file format (version %u.%u)",
          curClass.MajVers, curClass.MinVers);
  } else curClass.JDKsubver = (uchar)(curClass.MajVers - (JDK_MIN_MAJOR-1));

  if ( curClass.MajVers >= JDK_SMF_MAJOR_MIN ) SMF_mode = 1;
  else if ( curClass.JDKsubver <= 1) switch(curClass.MinVers ) {
    default:
      ask_for_feedback(
         "Class file with version %u.%u (JDK1.%u?) is not tested!",
         curClass.MajVers, curClass.MinVers, curClass.JDKsubver);
      //PASS THRU
    case JDK_1_02_MINOR:
    case JDK_1_1_MINOR:
      break;
  }
//--
  if ( (curClass.maxCPindex = read2()) <= 2) error("Empty constant pool" );
  loadMode = loadDialog(manual);
  ConstantNode.create(constant_pool);
  --curClass.maxCPindex;  // last valid number
  XtrnNode.create();
  make_NameChars(1);  // initialize and set 'load extension'
  ConstantNode.supset(CNS_UNIMAP, &unimap, sizeof(unimap));
  i = LoadPool();
  if ( !_add_seg(0)) XtrnNode.kill( );
  else {
    curClass.xtrnCnt  = (ushort)i;
    curClass.xtrnNode = XtrnNode;
  }
//--
  if ( (curClass.AccessFlag = read2()) & ~ACC_THIS_MASK )
    load_msg("Illegal class access bits (0x%X)\n", curClass.AccessFlag);
  if ( LoadNamedClass(curClass.This.Dscr = read2(), &opis) )
     curClass.This.Name = opis._name;
  else {
    BadRefFile("'this' class", curClass.This.Dscr);
#ifdef __BORLANDC__
#if offsetof(ClassInfo, This.Ref)+2 != offsetof(ClassInfo, This.Dscr) || \
    offsetof(ClassInfo, This.Ref)   != offsetof(ClassInfo, This.Name)
#error
#endif
#endif
    curClass.This.Ref >>= 16;
//    curClass.This.Name = curClass.This.Dscr;
//    curClass.This.Dscr = 0;
  }
//--
  if ( curClass.xtrnNode) setPoolReference( );
  curClass.super.Dscr = read2();
  i = read2();                    // interface counter
  i *= 2;
  if ( FileSize < i) errtrunc( );
  qfseek(fp, i, SEEK_CUR);
  curClass.FieldCnt = read2();
  qfseek(fp, -2 - i, SEEK_CUR);
  _add_seg(3);          // class segment
  if ( curClass.This.Dscr ) {
    enableExt_NameChar();
    curSeg.id.Number = 0;
    SetName(curClass.This.Name, curClass.startEA, curClass.AccessFlag, 0);
    hide_name(curClass.startEA);
  }

  if ( curClass.super.Ref ) {
    if ( !LoadNamedClass(curClass.super.Dscr, &opis) )
      BadRefFile("parent class", curClass.super.Dscr);
    else {
      curClass.super.Name = opis._name;
      xtrnRef(curClass.startEA, &opis);
    }
  }
//--
  if ( (i /= 2) != 0 ) { //InterfaceCount
    netnode   temp;
    unsigned  r = 0;

    do {
      if ( (j = read2()) == 0 ) {
        load_msg("Ignore zero interface index\n");
        continue;
      }
      if ( !r) temp.create( );

      uint32 refd = (uint32)j << 16;
      if ( !LoadNamedClass(j, &opis)) BadRefFile("interface", j );
      else {
        xtrnRef(curClass.startEA, &opis);
        refd |= opis._name;
      }
      temp.altset(++r, refd);
    }while ( --i );
    if ( r ) {
      temp.altset(0, r);
      curClass.impNode = temp;
    }
  }
//---
  ClassNode.create();
  curClass.ClassNode = ClassNode;
  qfseek(fp, 2, SEEK_CUR);
  if ( errload )
    mark_access(curClass.startEA, (curClass.AccessFlag & ~ACC_THIS_MASK) ?
                                                    curClass.AccessFlag : 0);
//---
  for(i = 1; (ushort)i <= curClass.FieldCnt; i++) {
    memset(&curField, 0, sizeof(curField));
    curField.id.Number = (ushort)i;
    curField.id.access = read2();
    j = curField.id.access & ACC_ACCESS_MASK;
    if( (curField.id.access & ~ACC_FIELD_MASK) || (j & (j-1))) {
      load_msg("Illegal Field#%u Attribute 0x%04x\n", i, curField.id.access);
//      curField.id.extflg |= EFL_ACCESS;
      mark_access(curClass.startEA + i, curField.id.access);
    }

    if ( !CheckFieldName(curField.id.name = read2(), NULL) )
        curField.id.extflg |= EFL_NAME;
    if ( !CheckFieldDscr(curField.id.dscr = read2(), &opis) )
        curField.id.extflg |= EFL_TYPE;
    else xtrnRef_dscr(curClass.startEA + curField.id.Number, &opis);
    if ( curField.id.extflg & EFL_NAMETYPE )
      load_msg("Illegal NameAndType of field %u\n", i);
    LoadAttrib(ARQ_FIELD);
    for(int n = 0; n < qnumber(curField.annNodes); n++)
      if ( curField.annNodes[n] == (uval_t)-1 ) ++curField.annNodes[n];
    ClassNode.supset(i, &curField, sizeof(curField));
    if ( !(curField.id.extflg & EFL_NAME) )
      SetName(curField.id.name, curClass.startEA + i, curField.id.access, i);
  }
//--
  curClass.MethodCnt = read2();
  for(i = 1; (ushort)i <= curClass.MethodCnt; i++) {
    memset(&curSeg, 0, sizeof(curSeg));
    curSeg.id.Number = (ushort)i;
    curSeg.id.access = read2();
    j = curSeg.id.access & ACC_ACCESS_MASK;
    if ( !(j & ~ACC_METHOD_MASK) && !(j & (j-1)) ) j = 0;
    else {
      load_msg("Illegal Method#%u Attribute 0x%04x\n", i, curSeg.id.access);
//      curSeg.id.extflg |= EFL_ACCESS;
    }

    _add_seg(1);  //codeSeg create         // this for strnRef_dscr
    if ( !CheckFieldName(curSeg.id.name = read2(), NULL) )
        curSeg.id.extflg |= EFL_NAME;
    if ( !CheckCallDscr(curSeg.id.dscr = read2(), &opis) )
        curSeg.id.extflg |= EFL_TYPE;
    else xtrnRef_dscr(curSeg.startEA, &opis, 1);
    if ( curSeg.id.extflg & EFL_NAMETYPE )
      load_msg("Illegal NameAndType of method %u\n", i);
//    if ( curSeg.id.extflg & EFL_ACCESS )
    if ( j )
      mark_access(curSeg.startEA, curSeg.id.access);
    LoadAttrib(ARQ_METHOD);
    if ( curSeg.smNode == BADNODE ) curSeg.smNode = 0; // remove 'flagged' value
    for(int n = 0; n < qnumber(curSeg.annNodes); n++)
      if ( curSeg.annNodes[n] == (uval_t)-1 ) ++curSeg.annNodes[n];
    if ( curSeg.varNode) resizeLocVars( );
    if ( curSeg.thrNode ) {
      netnode tnode(curSeg.thrNode);
      if ( !tnode.altval(0) ) {
        tnode.kill();
        curSeg.thrNode = 0;
      }
    }
    ClassNode.supset(-(int)i, &curSeg, sizeof(curSeg));
  }
//--
  LoadAttrib(ARQ_FILE); // Source File
  for(int n = 0; n < qnumber(curClass.annNodes); n++)
    if ( curClass.annNodes[n] == (uval_t)-1 ) ++curClass.annNodes[n];
  myFile = NULL;
  if ( curClass.encClass == 0xFFFF ) ++curClass.encClass;  // unification in out
  if ( FileSize )
    warning("This file has extra information (pos=0x%x)", qftell(fp));
//---
  CheckPoolReference(0);
  endLoad_NameChar(); // set 'standart extension'
  if ( !set_parent_object() && (curClass.AccessFlag & ACC_INTERFACE) ) {
    load_msg("This is interface, but superclass is not java.lang.Object!\n");
    mark_and_comment(curClass.startEA, "Interface have nonstandart parent");
  }
  if ( curClass.impNode && !curClass.super.Ref ) {
    load_msg("This have implements without superclass!\n");
    mark_and_comment(curClass.startEA, "Empty supperclass not for Object");
  }
  if ( errload ) curClass.extflg |= XFL_C_ERRLOAD;
  ConstantNode.supset(CNS_CLASS, &curClass, sizeof(curClass));   // load end!
//--
  debugmode = 1; // full pass...
  for(i = 1; (ushort)i <= curClass.MethodCnt; i++) {
    ea_t  ea, end;
    int   sz;

    msg("Analysing method %u...\n", i);
    ClassNode.supval(-(int)i, &curSeg, sizeof(curSeg));
    showAddr(ea = curSeg.startEA);
    end = ea + curSeg.CodeSize;
    if ( !curSeg.CodeSize) doByte(ea, 0x10 );
    else do if ( (sz = create_insn(ea)) == 0) ++sz; while((ea += sz) < end );
    if ( !(curSeg.id.extflg & EFL_NAME) )
      SetName(curSeg.id.name, curSeg.startEA, curSeg.id.access,
                                              curClass.FieldCnt + i);
    add_func(curSeg.startEA, end + 1);
  }
  debugmode = 0;  // all references setting...
  CheckPoolReference(1);
  loadpass = -1;  // no call QueueMark
  ConstantNode.altset(CNA_VERSION, _CUR_IDP_VER);
  ResW_newbase();
  create_filename_cmt();
}

//--------------------------------------------------------------------------

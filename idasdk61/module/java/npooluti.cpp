#include "java.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include "npooluti.hpp"

ClassInfo   curClass;
SegInfo     curSeg;
FieldInfo   curField;
FILE        *myFile;
netnode     ClassNode, XtrnNode, ConstantNode;
uchar       debugmode;
char        loadpass;
uchar       SMF_mode;
// only for npool
uchar       loadMode;
uint32      errload;
ushort      *tsPtr;
uchar       *smBuf, *annBuf;
char        *_spcnamechar;
uint32      FileSize;

char          sm_node = -1;
static uchar  uni_chk = (uchar)-1;  // unicode 'renaming' support
static uchar  name_chk;

//-----------------------------------------------------------------------
NORETURN void errtrunc(void)
{
  error("Premature end of file");
}

//-----------------------------------------------------------------------
void load_msg(const char *format, ...)
{ // this procedure prepare saving load-time message to base
  char    str[MAXSTR];
  va_list va;

  ++errload;
  va_start(va, format);
  int cnt = vsnprintf(str, sizeof(str), format, va);
  va_end(va);
  msg("%s", str);
  for(int i = cnt; i; ) if ( str[--i] > ' ' ) { // remove cr's
    if ( ++i > MAXSPECSIZE ) {
      i = MAXSPECSIZE;
      memcpy(&str[MAXSPECSIZE-3], "...", 3);
    }

    netnode temp;
    uval_t  j;
    if ( !curClass.msgNode ) {
      temp.create();
      curClass.msgNode = temp;
      j = 0;
    } else {
      temp = curClass.msgNode;
      j    = temp.altval(0);
    }
    temp.supset(j, str, i);
    temp.altset(0, j+1);
    break;
  }
}

//-----------------------------------------------------------------------
const char *mk_diag(uchar mode, char str[128])
{
  static const char *const diag[] =
      { "Code in method", "Field", "Method" };
#if ARQ_CODE || ARQ_FIELD != 1 || ARQ_METHOD != 2 || ARQ_FILE != 3
#error
#endif
  str[0] = '\0';
  if ( mode < ARQ_FILE )
      qsnprintf(str, 126, " for %s#%u", diag[mode],
                mode == ARQ_FIELD ? curField.id.Number : curSeg.id.Number);
  return(str);
}

//-----------------------------------------------------------------------
void BadRef(ea_t ea, const char *to, ushort id, uchar mode)
{
  char  diastr[128];

  if ( ea != BADADDR) QueueMark(Q_disasm, ea );
  load_msg("Illegal %s reference (%u)%s\n", to, id, mk_diag(mode, diastr));
}

//-----------------------------------------------------------------------
void mark_access(ea_t ea, ushort acc)
{
  char str[60];

  str[0] = 0;  // for module
  if ( acc) qsnprintf(str, sizeof(str), "Illegal access bits (0x%X)", acc );
  mark_and_comment(ea, str);
}

//-----------------------------------------------------------------------
void *myAlloc(unsigned size)
{
  register void *p = qalloc(size);
  if ( !p) nomem("JavaLoader" );
  return(p);
}

//-----------------------------------------------------------------------
uchar *sm_realloc(register unsigned size)
{
  if ( size > curClass.maxSMsize ) {
    curClass.maxSMsize = size;
    qfree(smBuf);
    smBuf = (uchar*)myAlloc(size+1);
  }
  return(smBuf);
}

//-----------------------------------------------------------------------
uchar *annotation_realloc(register unsigned size)
{
  if ( size > curClass.maxAnnSz ) {
    curClass.maxAnnSz = size;
    qfree(annBuf);
    annBuf = (uchar*)myAlloc(size+1);
  }
  return(annBuf);
}

//-----------------------------------------------------------------------
// visible for converter only
ushort *append_tmp_buffer(register unsigned size)
{
  if ( (ushort)size > curClass.maxStrSz ) {
    curClass.maxStrSz = (ushort)size;
    qfree(tsPtr);
    tsPtr = (ushort*)myAlloc(size*sizeof(ushort)*2+sizeof(ushort));
  }
  return(tsPtr);
}

//-----------------------------------------------------------------------
bool getblob(uval_t ind, void *p, uval_t sz)
{
  if ( (ushort)sz > curClass.maxStrSz) return(false );

  sz *= 2;
  size_t  ts = (size_t)sz + 1;
  return(ConstantNode.getblob(p, &ts, ind, BLOB_TAG) && (uint32)ts == sz);
}

//-----------------------------------------------------------------------
ushort read2(void)
{
  ushort data;
  if ( FileSize < 2) errtrunc( );
  FileSize -= 2;
  fread2bytes(myFile, &data, 1);
  return(data);
}

//-----------------------------------------------------------------------
uint32 read4(void)
{
  uint32 data;
  if ( FileSize < 4) errtrunc( );
  FileSize -= 4;
  fread4bytes(myFile, &data, 1);
  return(data);
}

//-----------------------------------------------------------------------
uchar read1(void)
{
  uchar data;
  if ( !FileSize) errtrunc( );
  --FileSize;
  eread(myFile, &data, 1);
  return(data);
}

//-----------------------------------------------------------------------
void readData(void *data, uint32 size)
{
  if ( FileSize < size) errtrunc( );
  FileSize -= size;
  eread(myFile, data, size);
}

//-----------------------------------------------------------------------
void skipData(uint32 size)
{
  if ( FileSize < size) errtrunc( );
  FileSize -= size;
  qfseek(myFile, size, SEEK_CUR);
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
uchar set_parent_object(void)
{
  static const char object[] = "java/lang/Object";

  if ( curClass.super.Name ) {
    char  tmpstr[sizeof(object)+2];

    if(   fmtName(curClass.super.Name, tmpstr, sizeof(tmpstr), fmt_fullname)
       && !memcmp(tmpstr, object, sizeof(object))) {

      curClass.extflg |= XFL_C_SUPEROBJ;
      return(1);
    }
  }
  return(0);
}

//-----------------------------------------------------------------------
const uchar *get_annotation(uval_t node, unsigned *plen)
{
  netnode temp(node);
  size_t len = (size_t)temp.altval(0);
  if ( len && len <= curClass.maxAnnSz ) {
    *plen = (unsigned)len;
    ++len;
    if ( temp.getblob(annBuf, &len, 0, BLOB_TAG) && len == *plen )
      return(annBuf);
  }
  return(NULL);
}

//-----------------------------------------------------------------------
bool sm_getinfo(SMinfo *pinf)
{ // call ONLY when curSeg.smNode != 0
  static netnode  SMnode;
  static uint32   SMsize;

  sm_info_t smr;
  ea_t      ea;

  switch ( sm_node ) {
    case -1:  // autoanalisys not finished :(
      goto noinfo;

    case 0:
      sm_node = 1;
      SMnode = curSeg.smNode;
      {
        size_t cnt = (size_t)SMnode.altval(-1);
        if ( cnt < 2 || cnt > curClass.maxSMsize ) goto destroyed;
        SMsize = (uint32)cnt;
        ++cnt;
        if ( !SMnode.getblob(smBuf, &cnt, 0, BLOB_TAG) || cnt != SMsize )
                                                                goto destroyed;
      }
    default:
      break;
  }

  if ( (ea = pinf->ea) == BADADDR ) ea = cmd.ea - 1;
  if(   (nodeidx_t)(ea = (ea_t)SMnode.supnxt(ea)) == BADNODE
     || get_item_head(ea) != cmd.ea) goto noinfo;
  if ( SMnode.supval(ea, &smr, sizeof(smr)) != sizeof(smr) ) goto destroyed;
  if ( smr.noff >= 2 && smr.eoff > smr.noff && smr.eoff <= SMsize ) {
    pinf->ea = ea;
    pinf->pb = smBuf + smr.noff;
    pinf->pe = smBuf + smr.eoff;
    pinf->fcnt = smr.fcnt;
    return(true);
  }

destroyed:
    DESTROYED("sm_getinfo");

noinfo:
   return(false);
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
void make_NameChars(uchar on_load)
{
  static const char special_char[] = {
        '$', '_',                       // MUST present (historical/special)
        j_sign, j_endsign,              // special case for <init>, <clinit> :(
  };
  static const char special_sym[] = {
        j_field_dlm,                    // classname (dot) ==> special point
        j_clspath_dlm,                  // classname path (slash)
        j_func, j_endfunc,              // function (for methods)
    0 };

  register char c;
  register char *p = NameChars;
  // in names accepted ONLY english chars (temporary?)
  c = 'A';
  do *p++ = c; while ( ++c <= 'Z' );
  c = 'a';
  do *p++ = c; while ( ++c <= 'z' );
  c = '0';
  do *p++ = c; while ( ++c <= '9' );
  memcpy(p, special_char, sizeof(special_char));
  p += sizeof(special_char);
  // fill national character's
  p = uniremap_init(p); // can use unicode characters of current codepage
  *p++ = '\\';  // is valid for unicode escape sequnce only (special work)
  // class/method path/call chars
  memcpy(p, special_sym, sizeof(special_sym));
  _spcnamechar = p; // dot position
  if ( !on_load ) p[2] = '\0'; // for oldbase convertation
}

//----------------------------------------------------------------------
segment_t *getMySeg(ea_t ea)
{
  register segment_t *s;

  if ( (s = getseg(ea)) == NULL ) goto compat_err;

  if ( curSeg.startEA != s->startEA ) {
    if ( sm_node > 0 ) sm_node = 0;
    if ( !s->orgbase ) {
      if ( s->type != SEG_IMP && s->type != SEG_XTRN ) goto compat_err;
      curSeg.startEA = s->startEA;
    } else {
      if ( ClassNode.supval(s->orgbase, &curSeg, sizeof(curSeg) ) !=
                                        sizeof(curSeg)) DESTROYED("getMySeg");
      if(   -s->orgbase != curSeg.id.Number
         || s->startEA != (s->type == SEG_BSS ? curSeg.DataBase :
                                                curSeg.startEA)) {
compat_err:
        UNCOMPAT("getMySeg");
      }
    }
  }
  return(s);
}

//-----------------------------------------------------------------------
// visible for converter only
void trunc_name(unsigned num, uchar type)
{
  static const char fnam[]   = "...(Field_%u)",
                    metnam[] = "...(Method_%u)",
                    locnam[] = "...(locvar_%u)",
                    xtrn[]   = "...(extern_%u)",
                    clsnam[] = "...",
                    *add_nam[5] = { xtrn, fnam, metnam, locnam, clsnam };

  enableExt_NameChar();
  size_t s = (sizeof(metnam) - 2 + 5 + 1);
  qsnprintf(get_output_ptr()-s, s, add_nam[type], num);
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
int CmpString(ushort index1, ushort index2)
{
DEB_ASSERT((!index1 || !index2), "cs-ind");
  if ( index1 != index2 ) {
    register size_t i;
    uval_t sz,
          ind1 = (uint32)index1 << 16,
          ind2 = (uint32)index2 << 16;

    if(   (sz = ConstantNode.altval(ind1)) == 0
       || (i  = (size_t)ConstantNode.altval(ind2)) == 0) {
do_destroy:
      DESTROYED("CmpString");
    }

    if ( sz != i ) {
diff:
      return(1);
    }

    if ( (i = (ushort)i) == 0) return(-1 );

    sz = i;
    i *= sizeof(ushort);
    uchar *p1 = (uchar *)tsPtr, *p2 = p1 + i;
    if ( !getblob(ind1, p1, sz) || !getblob(ind2, p2, sz) ) goto do_destroy;
    if ( memcmp(p1, p2, i) ) goto diff;
  }
  return(0);
}

//-----------------------------------------------------------------------
static int cmpDscrString(ushort index1, uchar met, ushort index2, uchar self)
{
  uval_t ind1, ind2, i1, i2, siz1, siz2;
  register ushort *p1, *p2;

  ind1 = (uint32)index1 << 16;
  ind2 = (uint32)index2 << 16;
  if(   (i1 = ConstantNode.altval(ind1)) == 0
     || (i2 = ConstantNode.altval(ind2)) == 0
     || (siz1 = (ushort)i1) == 0
     || (siz2 = (ushort)i2) == 0
     || !getblob(ind1, p1 = tsPtr, siz1)
     || !getblob(ind2, p2 = p1 + (size_t)siz1, siz2)) goto int_err;

  if ( met ) {
#define _MCR  ((_OP_ONECLS | _OP_VALPOS) << 16)
    if ( (i1 & _MCR) != _MCR ) goto diff;
#undef _MCR
    i1 = ConstantNode.altval(ind1+1);
    if ( !i1 || (int32)(siz1 -= i1) <= 0 ) goto int_err;  // never signature
    p1 += (size_t)i1;
  }

  if ( self && !(i1 & (_OP_NODSCR << 16))) while(*p1 == j_array ) {
    if ( !--siz1 ) goto int_err;
    ++p1;
  }

  if ( (i1 ^ i2) & (_OP_NODSCR << 16) ) {
    if ( i2 & (_OP_NODSCR << 16) ) {
      if ( *p1 == j_class && p1[(size_t)siz1-1] == j_endclass ) {
        ++p1;
        if ( (int)(siz1 -= 2) <= 0 ) goto int_err;
      }
    } else {
      if ( *p2 == j_class && p2[(size_t)siz2-1] == j_endclass ) {
        ++p2;
        if ( (int)(siz2 -= 2) <= 0 ) goto int_err;
      }
    }
  }

  if ( siz1 != siz2 || memcmp(p1, p2, (size_t)siz1 * sizeof(ushort)) ) goto diff;
  return(0);
int_err:
  INTERNAL("cmpDscrString");
diff:
  return(1);
}

//-----------------------------------------------------------------------
static ushort xtrnDscrSearch(ushort name, uchar met)
{
  ConstOpis cr;
  register ushort j;

  if(   curClass.This.Dscr
     && !cmpDscrString(name, met, curClass.This.Name, 1)) return(0xFFFF);

  for(j = curClass.xtrnLQE; j; j = (ushort)(XtrnNode.altval(j) >> 16)) {
    if(   ConstantNode.supval(j, &cr, sizeof(cr)) != sizeof(cr)
       || cr.type != CONSTANT_Class
       || (j = cr.ref_ip) == 0) INTERNAL("xtrnDscrSearch");
    if ( !cmpDscrString(name, met, cr._name, 0)) return(j );
  }
  return(0);
}

//-----------------------------------------------------------------------
static void mark_strange_name(ea_t ea)
{
  mark_and_comment(ea, "Strange name");
}

//-----------------------------------------------------------------------
void xtrnSet(unsigned cin, register ConstOpis *co, unsigned xip,
             char *str, size_t strsize, bool full, uchar rmod)
{
  static unsigned endcls;
  static uchar    clunic;     // for unicode renaming

  ea_t ea = curClass.xtrnEA + xip;

  if ( !(rmod & 4) ) {
    co->ref_ip = (ushort)xip;
    StoreOpis(cin, co);
    register uval_t rfa = cin;
    if ( full ) {
      rfa |= ((uval_t)curClass.xtrnLQE << 16);
      curClass.xtrnLQE = (ushort)cin;
    }
    XtrnNode.altset(xip, rfa);
    doByte(ea, 1);
  }

  register unsigned js = MAXNAMELEN - 1;
  init_output_buffer(str, strsize);
  name_chk = 0;
  if ( full ) {  // fmt_fullname
    uni_chk = 0;
    if ( fmtString(co->_name, js, fmt_fullname) ) {
      endcls = MAXNAMELEN;
trnc:
      trunc_name(xip);
    } else endcls = (unsigned)strlen(str);
    clunic = uni_chk;
  } else {
    uni_chk = clunic;
    if ( endcls >= MAXNAMELEN - 2 ) {
      set_output_ptr(&str[MAXNAMELEN-1]);
      name_chk = 0;   // no mark here
      goto trnc;
    }
    str[endcls] = '.';
    set_output_ptr(get_output_ptr() + (endcls + 1));
    js -= (endcls + 1);
    if ( fmtString(co->_subnam, js, fmt_name) ) goto trnc;
  }
  term_output_buffer();
  if ( rmod & 1 ) {
    enableExt_NameChar();
    do_name_anyway(ea, convert_clsname(str));
    hide_name(ea);
    disableExt_NameChar();
  }
  if ( (char)uni_chk > 0 && (rmod & 2)) ConstantNode.charset(ea, uni_chk, UR_TAG );
  uni_chk = (uchar)-1;
  if ( name_chk && !(rmod & 4)) mark_strange_name(ea );
}

//-----------------------------------------------------------------------
void SetName(ushort name, ea_t ea, ushort access, uval_t number,  uchar rmod)
{
  char str[MAXNAMELEN];

  init_output_buffer(str, sizeof(str));
  uni_chk = name_chk = 0;
  if ( fmtString(name, sizeof(str) - 1, (number || curSeg.id.Number ) ?
                                                fmt_name : fmt_fullname)) {
    if ( !number) trunc_name(curSeg.id.Number, uchar(3 + !curSeg.id.Number) );
    else if ( number <= (uval_t)curClass.FieldCnt )
                trunc_name((unsigned)number, 1);
         else   trunc_name((unsigned)number - curClass.FieldCnt, 2);
  }
  term_output_buffer();
  convert_clsname(str);

  if ( rmod & 1) switch(access & ACC_ACCESS_MASK ) {
    case ACC_PUBLIC:
      if (rmod & 4) del_global_name(ea);
      add_entry(number, ea, str, 0);
      break;
    case 0:
      if (rmod & 4) del_global_name(ea);
      add_entry(ea, ea, str, 0);
      break;
    default:
      do_name_anyway(ea, str);
      break;
  }
  disableExt_NameChar();
  if ( (char)uni_chk > 0 && (rmod & 2)) ConstantNode.charset(ea, uni_chk, UR_TAG );
  uni_chk = (uchar)-1;
  if ( name_chk && !(rmod & 4)) mark_strange_name(ea );
}

//-----------------------------------------------------------------------
// as procedure for rename_unichars
void set_lv_name(ushort name, ea_t ea, uchar rmod)
{
  char  str[MAXNAMELEN];

  uni_chk = name_chk = 0;
  if ( fmtName(name, str, sizeof(str), fmt_name) ) {
    if ( rmod & 1) do_name_anyway(ea, str );
    hide_name(ea);
    if ( (char)uni_chk > 0 && (rmod & 2)) ConstantNode.charset(ea, uni_chk, UR_TAG );
    if ( name_chk && !(rmod & 4)) mark_strange_name(ea );
  }
  uni_chk = (uchar)-1;
}

//--------------------------------------------------------------------------
void rename_uninames(int32 mode)
{
  nodeidx_t id = ConstantNode.char1st(UR_TAG);
  if ( id != BADNODE ) {
    char  str[MAXNAMELEN];  // for imports

    show_wait_box("HIDECANCEL\nRenaming labels with national characters");

    ushort  lcls = 0;  // for imports
    uchar   rmod = 7;  // rename+save (+renamemode)
    switch ( mode ) {
      case 0:   // change table but renaming not needed (recreate records only)
        rmod = 2; // save only
        break;
      case -1:  // change processor flag only
        rmod = 5; // rename only
        //PASS THRU
      default:  // change table and renaming needed
        break;
    }
    do {
      adiff_t dif;
      ea_t  ea = id;
      uchar type = ConstantNode.charval(ea, UR_TAG);
      showAddr(ea);
      if ( !type || type > 3 ) goto destroy;
      if ( !(type & 2) && mode == -1 ) continue;
      switch ( getMySeg(ea)->type ) {
        default:
destroy:
          DESTROYED("rename_uninames");

        case SEG_BSS:
          if(   !curSeg.varNode
             || (dif = ea - curSeg.DataBase) < 0
             || dif >= curSeg.DataSize
             || isAlign(get_flags_novalue(ea))) goto destroy;
          {
            netnode tmp(curSeg.varNode);
            LocVar  lv;
            if ( tmp.supval((nodeidx_t)dif, &lv, sizeof(lv)) != sizeof(lv) )
                                                                  goto destroy;
            set_lv_name(lv.var.Name, ea, rmod);
          }
          break;

        case SEG_CODE:
          if ( ea != curSeg.startEA ) goto destroy;
          SetName(curSeg.id.name, ea, curSeg.id.access,
                  curClass.FieldCnt + curSeg.id.Number, rmod);
          break;

        case SEG_IMP: // class/fields
          dif = ea - curClass.startEA;
          if ( dif < 0 ) goto destroy;
          if ( !dif ) { // class
            {
              ushort sv = curSeg.id.Number;
              curSeg.id.Number = 0;
              SetName(curClass.This.Name, ea, curClass.AccessFlag, 0, rmod);
              curSeg.id.Number = sv;
            }
            break;
          }
          if ( dif > curClass.FieldCnt ) goto destroy;
          if ( ClassNode.supval((nodeidx_t)dif, &curField, sizeof(curField) ) !=
             sizeof(curField)) goto destroy;
          SetName(curField.id.name, ea, curField.id.access, (int)dif, rmod);
          break;

        case SEG_XTRN:
          dif = ea - curClass.xtrnEA;
          if ( dif <= 0 || dif > curClass.xtrnCnt ) goto destroy;
          {
            uchar     cmod = rmod;
            ConstOpis co;
            {
              register unsigned j;
              if(   (j = (unsigned)XtrnNode.altval((nodeidx_t)dif)) == 0
                 || !LoadOpis((ushort)j, 0, &co)) goto destroy;
            }
            switch ( co.type ) {
              default:
                goto destroy;

              case CONSTANT_Fieldref:
              case CONSTANT_InterfaceMethodref:
              case CONSTANT_Methodref:
                if ( co._name != lcls ) {
                  cmod = 4; // set internal static variables only
              case CONSTANT_Class:
                  lcls = co._name;
                  xtrnSet(-1, &co, (unsigned)dif, str, sizeof(str), true, cmod);
                  if ( co.type == CONSTANT_Class ) break;
                }
                xtrnSet(-1, &co, (unsigned)dif, str, sizeof(str), false, rmod);
                break;
            }
          }
          break;
      }
    }while ( (id = ConstantNode.charnxt(id, UR_TAG)) != BADNODE );
    hide_wait_box();
  }
}

//-----------------------------------------------------------------------
void xtrnRef(ea_t ea, register const ConstOpis *opis)
{
  if ( (loadMode & MLD_EXTREF) && opis->ref_ip )
    add_dref(ea, opis->ref_ip == 0xFFFF ?
                                      curClass.startEA :
                                      curClass.xtrnEA + opis->ref_ip, dr_I);
}

//-----------------------------------------------------------------------
void xtrnRef_dscr(ea_t ea, register ConstOpis *opis, uchar met)
{
  if ( !met ) {
    if(   !(loadMode & MLD_VARREF)
       || (opis->flag & (HAS_CLSNAME | HAS_TYPEDSCR)) == HAS_CLSNAME) return;
  } else if ( !(loadMode & MLD_METHREF) ) return;

  ConstOpis cr(*opis);
  opis = &cr;
  opis->ref_ip = xtrnDscrSearch(opis->_name, met);
  xtrnRef(ea, opis);
}

//-----------------------------------------------------------------------
void deltry(unsigned bg, unsigned ic, unsigned ui, register const ConstOpis *pco)
{
  ConstOpis co;
  register unsigned i, j;

  for(i = bg; (ushort)i <= curClass.xtrnCnt; i++) {
    if ( (j = (unsigned)XtrnNode.altval(i, '0')) == 0 ) continue;
    ConstantNode.supval(j, &co, sizeof(co));
    if(   co.type   != pco->type
       || co.flag   != pco->flag
       || co.ref_ip != (ushort)ic
       || CmpString(co._subnam, pco->_subnam)
       || CmpString(co._dscr, pco->_dscr)) continue;
    co.ref_ip = (ushort)ui;
    StoreOpis(j, &co);
    XtrnNode.altdel(i, '0');
  }
}

//-----------------------------------------------------------------------
segment_t *_add_seg(int caller)
{
  static const char *const
      _cls[4] = { "xtrn",   "met_",    "_var",    "head" };
  static const char *const
      fm[4]   = { "import", "met%03u", "var%03u", "_Class" };
  static ea_t      startEA = 0;
  static ushort    cursel = 1;
  ushort           sel;
  uval_t           end, top, size;
  register segment_t *S;
  uchar            type;

  switch ( caller ) {
    default:
      INTERNAL("_add_seg");

    case 1:   // method
      curSeg.startEA = startEA;
    case -1:  // code
      startEA = curSeg.startEA;
      type = SEG_CODE;
      size = curSeg.CodeSize;
      break;

    case 2:  // data
      curSeg.DataBase = startEA;
      size = curSeg.DataSize;
      type = SEG_BSS;
      break;

    case 3: // class
      curClass.startEA = startEA;
      size = curClass.FieldCnt + 1;
      type = SEG_IMP;
      break;

    case 0: // header
      curClass.xtrnEA = startEA = toEA(inf.baseaddr, 0);
      if ( !curClass.xtrnCnt) return(NULL );
      size = curClass.xtrnCnt;
      type = SEG_XTRN;
      break;
  }
  end = ((top = startEA + size) + (0xF + 1)) & ~0xF;

  if ( caller < 0 ) {
    if ( (S = getseg(startEA) ) == NULL ||
       !set_segm_end(curSeg.startEA, end, SEGMOD_KILL)) qexit(1);
    uint32 pos = qftell(myFile);
    linput_t *li = make_linput(myFile);
    file2base(li, pos, startEA, top, FILEREG_PATCHABLE);
    unmake_linput(li);
    qfseek(myFile, pos + curSeg.CodeSize, SEEK_SET);
  } else {
    if ( startEA > 0x100000l) set_selector(sel = cursel++, startEA>>4 );
    else                    sel = (ushort)(startEA >> 4);
    if ( !add_segm(sel, startEA, end, NULL, _cls[caller])) qexit(1 );
    S = getseg(startEA);
    S->orgbase = -(uval_t)curSeg.id.Number;
    S->type = type;
    if ( caller != 1) S->set_hidden_segtype(true );  // no out comment of segment type
    set_segm_name(S, fm[caller], curSeg.id.Number);
    if ( caller <= 1 ) goto end_create;  // method/header
    for(uval_t i = 0; startEA < top; startEA++, i++) { // data & class
      doByte(startEA, 1);
      if ( caller == 2 ) { // data
        char  str[MAXNAMELEN];
        qsnprintf(str, sizeof(str), "met%03u_slot%03" FMT_EA "u", curSeg.id.Number, i);
        if ( do_name_anyway(startEA, str)) make_name_auto(startEA );
        else hide_name(startEA);
      }
    }
  }

  doByte(top, end - top);  // !header && !method
end_create:
  startEA = end;
  return(S);
}

//-----------------------------------------------------------------------
void resizeLocVars(void)
{
  netnode temp(curSeg.varNode);
  int     slot = curSeg.DataSize;

  for(int32 cur, prev = 1; --slot >= 0; prev = cur)
    if ( (cur = (int32)temp.altval(slot)) < 0 && !prev ) {
      do_unknown(curSeg.DataBase + slot+1, DOUNK_SIMPLE);
      doWord(curSeg.DataBase + slot, 2);
    }
}

//-----------------------------------------------------------------------
const char *CopyAttrToFile(const char *astr, uint32 size, ushort id)
{
  char    fname[QMAXPATH], *ptr;
  uval_t  *pnode = NULL;
  netnode temp;

  if ( FileSize < size) errtrunc( );  // here for alloc diagnostic

  qstrncpy(fname, database_idb, sizeof(fname));
  if ( (ptr = (char *)get_file_ext(fname)) == NULL ) {
    ptr = &fname[strlen(fname)];
    *ptr++ = '.';
  }

  uint32 sz = uint32(ptr - fname);

  if ( astr[0] == ' ' ) { // SourceDebugExtension
    if ( sz > sizeof(fname)-sizeof("SDE.utf8") ) {
too_long:
      return("PathName too long");
    }
    memcpy(ptr, "SDE.utf8", sizeof("SDE.utf8"));
  } else {
    if ( sz > (sizeof(fname)-30) ) goto too_long;

    switch ( (uchar)astr[0] ) {
      default:  // ARQ_FILE:
        pnode = &curClass.genNode;
        break;
      case ARQ_FIELD:
        ptr += qsnprintf(ptr, 30, "fld%03u_",  curField.id.Number);
        pnode = &curField.genNode;
        break;
      case ARQ_CODE:
      case ARQ_METHOD:
        pnode = &curSeg.genNodes[astr[0] == ARQ_CODE];
        ptr += qsnprintf(ptr, 30, "%smet%03u.",
                         astr[0] == ARQ_CODE ? "code_" : "",
                         curSeg.id.Number);
        break;
    }

    uchar err = 0;
    for(sz = 1; ptr < &fname[sizeof(fname) - sizeof(".attr")]; sz++) {
      register uchar c;
      switch ( c = astr[sz] ) {
        case 0:
          goto full_copy;
        default:
          if ( c > CHP_MIN && c < CHP_MAX ) {
            *ptr++ = c;
            break;
          }
          //PASS THRU
        case '/':
        case '\\':
        case '>':
        case '<':
        case '?':
        case '*':
        case '=':
          err = 1;
          break;
      }
    }
    ptr[-1] = '!';  // as marker of truncated name
full_copy:
    memcpy(ptr, ".attr", sizeof(".attr"));
    if ( err )
      msg("Convert unprintable filename for attribute '%s'\n", &astr[1]);
  }
#ifndef __UNIX__
  ptr = fname;
  while ( (ptr = strchr(ptr, '\\')) != NULL ) *ptr = '/';
#endif

  if ( (ptr = (char *)qalloc(size+1)) == NULL )  // +1 for zero_size extension!
      return("Not enough memory for loading");

  readData(ptr, size);

  FILE *f;
  if ( (f = qfopen(fname, "wb")) == NULL ) {
    qfree(ptr);
    return("Can't create file for storing");
  }

  uchar err = 0;
  if ( qfwrite(f, ptr, size) != size ) ++err;
  qfree(ptr);
  if ( qfclose(f) && !err ) {
    unlink(fname);
    return("Error writing");
  }
  if ( pnode ) {
    netnode temp;
    uint32  pos = 0;
    if ( *pnode ) {
      temp = *pnode;
    } else {
      temp.create();
      *pnode = temp;
      pos = (uint32)temp.altval(0);
    }
    ++pos;
    temp.altset(pos, id);
    temp.supset(pos, fname, strlen(fname));
    temp.altset(0, pos);
  }
  return(NULL);
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
bool fmtName(ushort index, char *buf, size_t bufsize, fmt_t fmt)
{
  init_output_buffer(buf, bufsize);
  register int i = fmtString(index, bufsize-1, fmt);
  term_output_buffer();
  return(!i && buf[0]);
}

//--------------------------------------------------------------------------
//  Procedures for "press Enter on any name"
static int is_locvar_name(const char *name)
{
  LocVar  lv;
  uint32  idx = (uint32)cmd.Op1.addr;
  char    tmp[MAXSTR];

  if ( cmd.Op1.type == o_mem ) {
    if ( cmd.Op1.ref ) goto bad;
  } else if ( cmd.Op1.type == o_void ) {
    if ( (char)cmd.Op1.ref < 0 || (int32)(idx -= (uint32)curSeg.DataBase) < 0 )
                                                                      goto bad;
  }

  if(   netnode(curSeg.varNode).supval(idx, &lv, sizeof(lv)) == sizeof(lv)
     && fmtName(lv.var.Name, tmp, sizeof(tmp), fmt_name)
     && !strcmp(name, tmp)) return(idx);
bad:
  return(-1);
}

//--------------------------------------------------------------------------
static inline int strstrpos(const char *s1, const char *s2)
{
  return((s2 = strstr(s1, s2)) == NULL ? -1 : (int)(s2 - s1));
}
//----------------------------------------
ea_t idaapi get_ref_addr(ea_t ea, const char *name, int pos)
{
  char      buf[MAXSTR*2];
  uchar     clv;

  register int  r;

  if ( (unsigned)strlen(name) <= (unsigned)pos ) goto not_found;

  switch ( clv = getMySeg(ea)->type ) {  // also set curSeg
    case SEG_XTRN:
      if ( !jasmin() ) goto not_found; // short form. Can't search by text
      //PASS THRU
    default:
      break;
    case SEG_CODE:
      if ( (unsigned)strstrpos(name, ash.cmnt) <= (unsigned)pos )
        clv |= 0x80;  // flag for 'modified autocomment' (see make_locvar_cmt)
      break;
  }

  enableExt_NameChar();
  if ( !strchr(NameChars, (uchar)name[r = pos]) ) {
    disableExt_NameChar();
not_found:
    return(BADADDR);
  }

  while ( r && strchr(NameChars, (uchar)name[r-1]) ) --r;
  int start = r;
  for(r = pos+1; name[r]; r++)
    if ( !strchr(NameChars, (uchar)name[r]) ) break;
  disableExt_NameChar();
  if ( name[r] == '\\' && !name[r+1] ) goto not_found; //\\+++ not work with prompt?
  memcpy(buf, &name[start], r);
  buf[r] = '\0';
  switch ( clv & ~0x80 ) {
    case SEG_CODE:
    case SEG_BSS:
      if ( (r = check_special_label(buf, r)) >= 0 )
        return(curSeg.startEA + r);
      //PASS THRU
    default:
      break;
  }
  if ( (clv&0x80) && curSeg.varNode && (start = is_locvar_name(buf)) >= 0 )
    return(curSeg.DataBase + start);
// append(new)
  ea_t rea = get_name_ea(BADADDR, convert_clsname(buf));
  if ( rea == BADADDR && jasmin() && (clv&~0x80)==SEG_CODE ) { // fieldnames
    register char *p = strrchr(buf, j_field_dlm);
    if ( p ) {
      *p++ = '\0';
      if ( get_name_ea(BADADDR, buf) == curClass.startEA )
        rea = get_name_ea(BADADDR, p);
    }
  }
  return(rea);
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
extern const TXS tp_decl[];
const TXS tp_decl[] = {
                  TXS_DECLARE("void"), // ATTENTION: only for fmtStr
                  TXS_DECLARE("boolean"),
                  TXS_DECLARE("char"),
                  TXS_DECLARE("float"),
                  TXS_DECLARE("double"),
                  TXS_DECLARE("byte"),
                  TXS_DECLARE("short"),
                  TXS_DECLARE("int"),
                  TXS_DECLARE("long")
                };
static const char tp_type[]= {
                      j_class, j_typeref,  // ATT: unsync!
                      j_void_ret,          // ATT: for fmtStr
                      j_bool, j_char, j_float, j_double,
                      j_byte, j_short, j_int, j_long,
                               0 };

//-----------------------------------------------------------------------
const TXS *get_base_typename(uchar tag)
{
  ssize_t i;
  if ( !tag || (i = strchr(&tp_type[3], tag) - &tp_type[3]) < 0) return(NULL );
  return(&tp_decl[i+1]);
}

//-----------------------------------------------------------------------
// for IDF_SHOWBADSTR (index my be not string :)
bool is_valid_string_index(ushort index)
{
  return(   index
         && index <= curClass.maxCPindex
         && ConstantNode.altval(((uint32)index) << 16));
}

//-----------------------------------------------------------------------
/*           signatures encoding
 *
 *     methodOrFieldSignature ::= type
 *     classSignature         ::= [ typeparams ] supertype { interfacetype }
 *
 *     type       ::= ... | classtype | methodtype | typevar
 *     classtype  ::= classsig { '.' classsig }
 *     classig    ::= 'L' name [typeargs] ';'
 *     methodtype ::= [ typeparams ] '(' { type } ')' type
 *     typevar    ::= 'T' name ';'
 *     typeargs   ::= '<' type { type } '>'
 *     typeparams ::= '<' typeparam { typeparam } '>'
 *     typeparam  ::= name ':' type
*/
//-----------------------------------------------------------------------
static size_t _one_line(void)
{
  out_zero();
  return(0);
}

//-----------------------------------------------------------------------
int fmtString(ushort index, ssize_t size, fmt_t mode, _PRMPT_ putproc)
{
#define SWT_STR(u)                   \
  do                                 \
    if ( u )                         \
    {                                \
      if ( (size=putproc()) == 0 )   \
        return -1;                   \
      else                           \
        ++strcnt;                    \
    }                                \
  while ( 0 )

#define IS_TAG(u) (u == j_class || u == j_typeref)

  static const TXS  sfx[4] = {
                      TXS_DECLARE(" extends "),
                      TXS_DECLARE(" super "),
                      TXS_DECLARE(" implements "),
                      TXS_DECLARE(" throws ")
                    };

  ushort    *tp = NULL;
  uint32    ostsz, dimcnt, strcnt, intag;
  uchar     cs, nextp, tagmode, quotation;

  if ( size < 0 ) {
interr:
    INTERNAL("fmtString");
  }

  if ( !index ) {
badbase:
    DESTROYED("fmtString");
  }

  if ( !putproc ) putproc = _one_line;

  strcnt = ((uint32)index) << 16;
  if ( (ostsz = (uint32)ConstantNode.altval(strcnt)) == 0 ) goto badbase;
#ifdef __BORLANDC__
#if offsetof(_STROP_, size) || sizeof(((_STROP_ *)0)->size) != sizeof(ushort)
#error
#endif
#endif
  if ( !(uni_chk & 1) && (ostsz & (_OP_UNICHARS<<16)) ) ++uni_chk;  // rename unicode
  if ( ostsz & (_OP_BADFIRST<<16) ) name_chk = 1;
  cs = !(ostsz & (_OP_NODSCR<<16)); // for checking ONLY
  if ( mode & FMT_ENC_RESERVED ) { // support jasmin reserved words
#ifdef __BORLANDC__
#if ( fmt_fullname+1) != fmt_name || (fmt_name+1 ) != fmt__ENDENUM
#error
#endif
#endif
    if ( (mode = (fmt_t)(mode ^ FMT_ENC_RESERVED)) < fmt_fullname ) goto interr;
    if ( (ostsz & (_OP_JSMRES_ << 16)) && (idpflags & IDM_OUTASM) )
                                                          mode = fmt_quoted;
  }
  if(   (ostsz = (ushort)ostsz) != 0
     && !getblob(strcnt, tp = tsPtr, ostsz)) goto badbase;

  quotation = '"';
  nextp = tagmode = 0;
#ifdef __BORLANDC__
#if ( fmt_prefsgn+1) != fmt_retdscr || (fmt_retdscr+1 ) != fmt_paramstr || \
    (fmt_paramstr+1) != fmt_throws || (fmt_throws+1) != fmt_clssign
#error
#endif
#endif
  if ( mode <= fmt_clssign && mode >= fmt_prefsgn ) {  // method part out
DEB_ASSERT((jasmin()), "f:callmode");
    if ( mode == fmt_clssign ) {
      if ( !ostsz ) goto badbase;
      if ( *tp == j_sign ) --tagmode;  // = -1
      goto start_out;
    }
    dimcnt = (uint32)ConstantNode.altval(strcnt+1); // offset to return type
    if ( !dimcnt || dimcnt >= ostsz || tp[dimcnt-1] != j_endfunc ) goto badbase;
    strcnt = (uint32)ConstantNode.altval(strcnt+2); // lng of <...:...> + throw off
    intag = strcnt >> 16; // offset to throws (here for strcnt == 0)
    if ( strcnt ) {
      if ( cs ) goto badbase;  // PARANOYA
      strcnt  = (ushort)strcnt; // length of <...:...> == offset to '('
      if ( strcnt >= dimcnt || tp[strcnt] != j_func ) goto badbase;
      if ( intag ) {
        if(   intag <= dimcnt
           || intag >= ostsz
           || tp[intag] != j_throw) goto badbase;
      }
    }
    switch ( mode ) {
//      case fmt_paramstr:  // out parameter list
      default:
        tp += strcnt; // skip <...:...> signature
        ostsz = dimcnt - strcnt;
        break;
      case fmt_retdscr:     // out return type
        tp += dimcnt;
        if ( intag ) ostsz = intag;
        ostsz -= dimcnt;
        break;
      case fmt_prefsgn:     // out <...:...> signature
        if ( !strcnt ) goto done;
        ostsz = strcnt;
        if ( *tp != j_sign ) goto badbase;
        --tagmode;  // = -1
        break;
      case fmt_throws:      // out throws specification
        strcnt = 0; // unification
        if ( !intag ) goto done;
        ++intag;  // skip j_throw
        tp += intag;
        ostsz -= intag;
        break;
    }
  }

start_out:
  strcnt = dimcnt = 0;
  intag  = 2;  // for decrement checking ONLY
  switch ( mode ) {
    case fmt_debug:
      if ( !(idpflags & IDF_MULTDEB) ) mode = fmt_string;  // optimize
      goto start_string;
    case fmt_string:
      if ( idpflags & IDF_AUTOSTR ) mode = fmt_debug;
start_string:
      SWT_STR((size <= 1));
      cs = quotation;
//add_char:
      goto _put_entry;
    case fmt_quoted:
      quotation = '\'';
      goto start_string;
    case fmt_throws:
      cs = 3; // throws
      goto do_table;
    default:
      break;
  }

DEB_ASSERT((!ostsz), "f:size");
  while ( ostsz ) {
    if ( tagmode == 1 ) {
      ++tagmode; // = 2
DEB_ASSERT((!IS_TAG(*tp)), "f:>x");
      goto do_extends;
    }

#ifdef __BORLAND__
#if fmt_debug || (fmt_debug+1) != fmt_string || (fmt_string+1) != fmt_quoted
#error
#endif
#endif
    {
      --ostsz;
      register ushort cw = *tp++;

      if ( cw >= 0x100 ) {
        if ( (cs = uni_remap(cw)) == 0 ) {
          if ( !(uni_chk & 2) && uni_remap_check(cw) ) uni_chk |= 2;
do_unicode:
          SWT_STR((size < 6));
          size -= out_snprintf("\\u%04X", cw);  //UNICODE-format
          continue;
        } else {
          uni_chk |= 2;
#ifdef __debug__
          if ( mode > fmt_string ) goto oem_mapped;
#endif
        }
      } else if ( (cs = (uchar)cw) >= CHP_MAX ) {
#if CHP_MAX >= 0x100
#error
#endif
        if ( mode <= fmt_string ) goto do_oct3;
        goto do_unicode;
      } else if ( mode > fmt_string ) {
        if ( cs <= CHP_MIN ) goto do_unicode;
        if ( mode == fmt_quoted && (cs == '\\' || cs == '\'') ) goto do_unicode; // PARANOYA
      }
    } // cw declaration

    if ( mode <= fmt_string ) {
      if ( cs < 0xD ) {
        if ( cs < 8 || cs == 0xB ) goto checkdig;
        {
          static const char casc[(0xD-8)+1] = { 'b', 't', 'n', '?', 'f', 'r' };
          if(   (cs = casc[cs-8]) == 'n'
             && mode == fmt_debug
             && ostsz
             && size > 2) size = 2;
        }
do_escape:
        SWT_STR((size < 2));
        size -= 2;
        OutChar('\\');
        goto _put_only;
      }
      if ( cs >= ' ' ) {
        if ( cs == '\\' || cs == '"' ) goto do_escape;
puts:
        SWT_STR((size <= 0));
_put_entry:
        --size;
_put_only:
        OutChar(cs);
        continue;
      }
checkdig:
      if ( ostsz && *tp <= '7' && *tp >= '0' ) {
do_oct3:
        SWT_STR((size < 4));
        size -= out_snprintf("\\%.3o", cs);
        continue;
      }
      if ( cs <= 7 ) {
        cs += '0';
        goto do_escape;
      }
      SWT_STR((size < 3));
      size -= out_snprintf("\\%o", cs);
      continue;
    } // mode <= fmt_string
DEB_ASSERT(((tp[-1] >= CHP_MAX || tp[-1] <= CHP_MIN) && mode > fmt_string), "f:chr");
#ifdef __debug__
oem_mapped:
#endif
    if ( jasmin() ) goto puts;

//  encoder
    switch ( cs ) {
      case j_clspath_dlm:
        cs = '.';
        //PASS THRU
#if j_field_dlm != '.'
#error
#endif
      case  j_field_dlm:
DEB_ASSERT((!(intag&1) && mode!=fmt_fullname && mode!=fmt_classname), "f:/");
        goto puts;

      case j_tag:
        if ( tagmode != (uchar)-1 ) goto badbase;
        --tagmode;  // = -2
        if ( ostsz && *tp == j_tag ) {
          --ostsz;
          ++tp;
        }
DEB_ASSERT((!ostsz || intag <= 2), "f:<:>");
do_extends:
        cs = 0; // extends
do_table:
        SWT_STR((size < sfx[cs].size));
        size -= sfx[cs].size;
        OutLine(sfx[cs].str);
        nextp = 0;
      case j_throw:
DEB_ASSERT((!ostsz || !IS_TAG(*tp) || (intag&1)), "f:special");
        intag &= ~1;  // PARANOYA
        continue;

      case j_wild:
DEB_ASSERT((intag <= 2 || !ostsz || *tp != j_endsign), "f:wild");
        cs = '?';
        goto puts;

      case j_wild_e:
      case j_wild_s:
DEB_ASSERT((intag <= 2 || !ostsz || !IS_TAG(*tp)), "f:wild+-");
        SWT_STR((size <= 0));
        --size;
        OutChar('?');
        cs = cs == j_wild_s;  // s: super, e: extends
        goto do_table;

      case j_sign:
        nextp = 0;
DEB_ASSERT(((int32)intag <= 0 || !ostsz), "f:sig++");
        intag <<= 1;
        goto puts;

      case j_endsign:
DEB_ASSERT((intag <= 2), "f:sig--");
        if ( (intag >>= 1) == 2 ) tagmode = 1;
        goto puts;

      case j_endfunc:
      case j_func:
        nextp = 0;
DEB_ASSERT((mode != fmt_paramstr || dimcnt || intag != 2), "f()");
        goto puts;

      case j_endclass:
        if ( !(intag & 1) ) {
DEB_ASSERT((mode < fmt_fullname), "f:tag");
          break;
        }
        --intag;  // &= 1
DEB_ASSERT((mode == fmt_classname && ostsz), "f:extract");
        if ( !ostsz ) goto endtag;
        switch ( intag ) {
          case 2:
            if ( tagmode == 2 ) {
              ++tagmode;  // = 3
              cs = 2; // implements
              goto do_table;
            }
#ifdef __BORLANDC__
#if ( fmt_throws+1 ) != fmt_clssign
#error
#endif
#endif
            if ( mode > fmt_clssign || mode < fmt_throws ) goto endtag;
            break;
          case 4:
            if ( tagmode == (uchar)-2 ) ++tagmode;  // = -1
            //PASS THRU
          default:
            break;
        }
        switch ( *tp ) {
          default:
            if ( !tagmode) tagmode = (uchar )-3;
            goto next_list;

          case j_endclass:
          case j_endsign:
          case j_endfunc:
            continue;
        }

      default:
        break;
    }

    if ( (intag & 1) || tagmode == (uchar)-1 ) goto puts;

    if ( nextp ) {
DEB_ASSERT((mode != fmt_paramstr || dimcnt), "f:list");
next_list:
      nextp = 0;
      SWT_STR((size < 2));
      size -= 2;
      OutLine(", ");
      if ( tagmode ) continue;
    }

    if ( intag > 2 ) {
      if ( IS_TAG(cs) ) {
        intag |= 1;
        continue;
      }
      // for <init>/<cinit>
DEB_ASSERT((cs == j_array), "f:<[]>");
      goto puts;
    }

    if ( cs == j_array ) {
DEB_ASSERT((!ostsz || mode > fmt_fullname || intag > 2), "f:[]");
      ++dimcnt;
      continue;
    }

#ifdef __BORLANDC__
#if ( fmt_cast+1) != fmt_classname || (fmt_classname+1 ) != fmt_fullname || \
    (fmt_fullname+1) != fmt_name || (fmt_name+1) != fmt__ENDENUM
#error
#endif
#endif
    if ( mode > fmt_fullname ) goto puts;
    if ( mode >= fmt_cast && !dimcnt ) {
      mode = fmt_fullname;
      goto puts;
    }

    {
      register ssize_t  i;

      if ( (i = strchr(tp_type, cs) - &tp_type[2]) < 0 ) {  // j_class, j_typeref
        if ( i < -2) UNCOMPAT("fmtString" );
DEB_ASSERT((!ostsz), "f:tag");
        intag |= 1;
        continue;
      }

      SWT_STR((size < (short)tp_decl[i].size));
      size -= tp_decl[i].size;
      OutLine(tp_decl[i].str);
    }
endtag:
    nextp = 1;
    if ( intag <= 2 ) {
DEB_ASSERT((!ostsz != (mode != fmt_paramstr)), "f:mode");
      while ( dimcnt ) {
        SWT_STR((size < 2));
        size -= 2;
        OutLine("[]");
        --dimcnt;
      }
    }
  } // while ( ostsize )
#ifdef __BORLAND__
#if fmt_debug || (fmt_debug+1) != fmt_string || (fmt_string+1) != fmt_quoted
#error
#endif
#endif
DEB_ASSERT((intag != 2 && mode > fmt_string), "f:endlev");

#ifdef __BORLANDC__
#if ( fmt_retdscr-1) != fmt_prefsgn || (fmt_prefsgn-1 ) != fmt_dscr || \
   (fmt_dscr-1) != fmt_quoted || (fmt_quoted-1) != fmt_string || \
   (fmt_string-1) != fmt_debug || fmt_debug
#error
#endif
#endif
  if ( mode <= fmt_retdscr ) {
    SWT_STR((size <= 0));
    OutChar((mode <= fmt_quoted) ? quotation : ' ');
  }
  out_zero();
done:
  return(strcnt);
#undef SWT_STR
#undef IS_TAG
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
uchar LoadUtf8(ushort index, ConstOpis *co)
{
  _STROP_   _opstr;
  uint32    Flags = 0;
  uint32    ind = ((uint32)index) << 16;
  uchar     result = 0, is_sde = 0, unicode = 0;
  unsigned  size;

  if ( index == (ushort)-1 ) { // SourceDebugExtension
#ifdef __BORLANDC__
#if offsetof(_STROP_, size) || sizeof(_opstr.size) != sizeof(ushort)
#error
#endif
#endif
    *(uint32*)&_opstr = (ushort)(size_t)co;
    co = NULL;
    is_sde = 1;
  } else {
    _opstr.flags = _OP_UTF8_;
    _opstr.size  = read2();
  }
  if ( (size = _opstr.size) != 0 ) {
    register ushort  *po = append_tmp_buffer(size);
    register union {
      ushort        cw;
      uchar         cs;
    };
    register uchar  c;
    do {
      --size;
      if ( (cw = (uchar)read1()) == 0 || cs >= 0xf0 ) goto errcoding;
      if ( (char)cs < 0 ) {
        if ( !size ) goto errchar;
        --size;
        --_opstr.size;
        c = cs;
        cs &= 0x1F;
        cw <<= 6;
        {
          uchar c2;
          if ( ((c2 = read1()) & 0xC0) != 0x80 ) goto errchar;
          cs |= (c2 & 0x3F);
        }
        if ( (c & 0xE0) != 0xC0 ) {
          if(   !size
             || (c & 0xF0) != 0xE0
             || ((c = read1()) & 0xC0) != 0x80) {
errchar:
              if ( is_sde ) goto done;
              error("Illegal byte in CONSTANT_Utf8 (%u)", index);
          }
          --size;
          --_opstr.size;
          cw <<= 6;
          cs |= (c & 0x3F);
          if ( cw < 0x800 ) goto errcoding;
        } else if ( cw < 0x80 && cs ) {
errcoding:
            if ( is_sde ) goto done;
            error("Illegal symbol encoding in CONSTANT_Utf8 (%u)", index);
        }
      } // end encoding
      *po++ = cw;
      if ( !is_sde ) {
        if ( cw >= CHP_MAX ) {
          if ( !javaIdent(cw) ) goto extchar;
          unicode = 1;
        } else if ( cs <= CHP_MIN ) {
extchar:
          Flags |= _OP_EXTSYM_;
          unicode = (uchar)-1;
        }
      }
    }while ( size );

    if(   !is_sde
       && _opstr.size == 1
       && (loadMode & MLD_STRIP)
       && (cw >= 0x80 || !strchr(&tp_type[3], cs))) {
//Symantec error (strip) #3
       char   str[16];
       uchar  *ps = (uchar *)str;

       _opstr.size = (ushort)qsnprintf(str, sizeof(str), "_?_%04X", cw);
       po = append_tmp_buffer(_opstr.size);
       do *po++ = *ps++; while ( *ps );
       Flags |= _OP_NODSCR | _OP_NOSIGN;
       co->flag = HAS_CLSNAME | HAS_FLDNAME;
       unicode = 0;   // PARANOYA
    }
    result = !Flags;
    ConstantNode.setblob(tsPtr, (uchar *)po - (uchar *)tsPtr, ind, BLOB_TAG);
  }
  if ( !is_sde ) {
    if ( unicode == 1 ) Flags |= _OP_UNICHARS;
    _opstr.flags |= (ushort)Flags;
    co->_Sopstr = *(int32 *)&_opstr;
  }
  ConstantNode.altset(ind, *(uint32 *)&_opstr);
done:
  return(result);
}

//-----------------------------------------------------------------------
void Parser(ushort index, ConstOpis *co)
{
// all nexts used only here (for parsing)
#define _op_PARAM_    0x00010000  // start paramlist '('
#define _op_PAREND_   0x00020000  // last char is end of paramlist ')'
#define _op_RETTYPE_  0x00040000  // have valid position for call return type
#define _op_FRSPRM_   0x00080000  // not first descriptor (parameter)
#define _op_CLSBEG_   0x00100000  // begin 'L...;' detected
#define _op_TYPBEG_   0x00200000  // begin 'T...;' (signtype) detected
#define _op_NAME_     0x00400000  // non empty class/typeref-name
#define _op_ARRAY_    0x00800000  // previous char is '['
// next needed for 'complex' classnames
#define _op_ISARRAY_  0x01000000  // have any '[' in name
#define _op_PRIMSIG_  0x02000000  // <...:...> signature presnt
#define _op_INPRSIG_  0x04000000  // currently parse <...:...> signature
#define _op_MUSTNAM_  0x08000000  // part must be name (before ':')

#define _op_isTAG_   (_op_CLSBEG_ | _op_NAME_ | _op_TYPBEG_)

  unsigned  Flags  = 0, size = co->_Ssize;
  uint32    posit  = 0, possgn = 0;
  ushort    *po    = tsPtr; // ATT: call ONLY after LoadUtf8, size!=0
  uchar     sgnlev = 0, prim = 0, *pprim = NULL;
  register uchar cs;  // for prev

  if ( *po == j_sign ) {  // check <...:...> signature and <init>/<clinit>
    while ( ++posit < size )
      if ( !javaIdent(po[posit]) ) {
        if ( posit != 1 ) {
          size -= posit+1;  // +1 => balance for while, or align for <init>
          switch ( po[posit] ) {
            case j_tag:
              if ( size < 7) break; // Lx;>Lx; or Lx;>( )V => only_string
              Flags |= _OP_FULLNM | _OP_NOFNM | _OP_NODSCR |
                       _op_PRIMSIG_ | _op_INPRSIG_;
              po += posit;
              posit &= 0;
              ++sgnlev;
              goto accept_tag;

            case j_endsign:
              if ( !size ) { // <init>/<clinit>
                Flags |= _OP_NODSCR | _OP_NOSIGN;
                goto set_flags;
              }
              //PASS THRU
            default:
              break;  // only_string
          } // switch
        } // posit != 1
        break;
      } // special_char
    goto only_string;
  } // first '<'

  if ( *po == j_func ) {  // check method descriptor/signature
to_func:
    if ( --size < 2) goto only_string; //  )V
    ++po;
    Flags |= _op_PARAM_;
  } else pprim = &prim;
  do {
    --size;
    cs = 0;   // as flag (for wide characters)
#if CHP_MAX >= 0x100
#error
#endif
    if ( *po < CHP_MAX) cs = (uchar )*po;  // for 'L', 'T'...
    if ( javaIdent(*po, pprim) ) {   // letter/digit/$_
      if ( pprim ) {
        if ( !prim ) Flags |= _OP_BADFIRST;
        pprim = NULL;
      }
      goto norm_char;
    }
    pprim = NULL; // for speed
    if ( cs <= CHP_MIN ) goto only_string; // also >= CHP_MAX

    if ( Flags & _op_MUSTNAM_) {  // only in <...:...> signature (formal name )
      if ( cs != j_tag ) goto only_string;
      Flags &= ~_op_MUSTNAM_;
      if ( size < 7) goto only_string; // Lx;>Lx; or Lx;>( )V
accept_tag:
      if ( po[1] == j_tag ) {  // iface
        --size;
        ++po;
      }
      goto only_tag;
    }
    switch ( cs ) {  // validate special char's
      case j_endfunc: // always can be present in in name
        if(   sgnlev
           || (Flags & (_op_PARAM_ | _op_ARRAY_ | _op_isTAG_)) != _op_PARAM_)
                                                            goto only_string;
        Flags ^= (_op_PARAM_ | _op_PAREND_);
        continue;

      case j_array: // class name can be full qualified array :(
        if ( !sgnlev && !(Flags & (_op_isTAG_ | _OP_NOSIGN)) ) {
          Flags |= _OP_FULLNM;
          break;
        }
        //PASS THRU
      default:
        goto only_string;

      case j_clspath_dlm: // '/'
      case j_field_dlm:   // '.'
        Flags |= _OP_FULLNM;
        continue;

      case j_sign:
        if(   size < 3  // *>;
           || (Flags & (_op_NAME_ | _OP_NOSIGN)) != _op_NAME_
           || ++sgnlev >= 30) goto only_string;
        CASSERT((int32)(2 << 30) < 0); // "fmtString check method"
        Flags |= _OP_FULLNM | _OP_NOFNM | _OP_NODSCR;
        Flags &= ~_op_isTAG_;
        --size;
        switch ( *++po ) {
          case j_wild:
            if ( *++po != j_endsign ) goto only_string;
            --size;
            goto end_signW;

          case j_wild_s:
          case j_wild_e:
            goto only_tag;

          default:
            goto skipped_only_tag;
        }

      case j_endsign:
        if ( !size || !sgnlev ) goto only_string;
end_signW:
        //end of <...:...> signature must resolve in endclass
        if ( !--sgnlev && (Flags & _op_INPRSIG_) ) goto only_string;
        if ( *++po != j_endclass ) goto only_string;
        --size;
        Flags |= _op_NAME_; // restore
        //PASS THRU
      case j_endclass:
        if ( (Flags & (_op_NAME_ | _op_PAREND_ | _op_ARRAY_)) != _op_NAME_ )
                                                            goto only_string;

        if ( !size && (Flags & (_op_CLSBEG_ | _OP_NOSIGN)) == _op_CLSBEG_ )
                                                        Flags |= _OP_ONECLS;
        Flags &= ~_op_isTAG_;

        if ( sgnlev == 1 && (Flags & _op_INPRSIG_) ) { // parse <...:...>
          if ( size < 4) goto only_string;  // >Lx; or >( )V
          switch ( po[1] ) {
            default:
              Flags |= _op_MUSTNAM_;  // next substitution
              continue;
            case j_tag:
              goto only_string;
            case j_endsign: // end of <...:...>
              break;
          }
          ++po;   // skip ';'
          --size; // balance next '>'
          sgnlev = 0;
          Flags &= ~_op_INPRSIG_;
          if ( po[1] != j_func ) goto only_tag; // superclass{ifaces}
          ++po;   // skip '>' (go=> before do-while)
          possgn = (uint32)(po - tsPtr);
          goto to_func;
        } // end resolve end of <...:...>

        if ( sgnlev ) {
          if ( po[1] == j_endsign ) continue;
          if ( size > 2 ) goto only_tag; // Lx;
          goto only_string;
        }
        Flags |= _OP_FULLNM;
        // class name can be full qualified array :(
        if ( (Flags&(_op_ISARRAY_|_op_PARAM_|_op_RETTYPE_)) != _op_ISARRAY_ ) {
          if ( Flags & _OP_NOSIGN ) goto only_string;  // speed only
          Flags |= _OP_NOFNM;
        }
        if ( Flags & (_op_RETTYPE_ | _op_PRIMSIG_) ) {
          Flags &= ~_op_FRSPRM_;
          if ( Flags & _op_RETTYPE_ ) goto check_throw;
        }
        continue;
    } // switch ( specchar ) FULLNM
norm_char:
    if ( Flags & (_OP_NOSIGN | _op_MUSTNAM_ | _op_NAME_) ) continue;

    if ( Flags & _op_isTAG_ ) {
      Flags |= _op_NAME_;
      continue;
    }
    if ( sgnlev ) continue;

    if ( Flags & _op_PAREND_ ) {
      posit = (uint32)(po - tsPtr);
      Flags &= ~(_op_PAREND_ | _op_FRSPRM_);
      Flags |= _op_RETTYPE_;
      if ( cs == j_void_ret ) goto check_throw;
    }

//chkdscr
    if ( (Flags & (_op_PARAM_ | _op_FRSPRM_)) == _op_FRSPRM_ ) goto nodscsg;

    if ( cs == j_array ) {
      Flags |= _op_ARRAY_ | _op_ISARRAY_;
      continue;
    }

    Flags = (Flags & ~_op_ARRAY_) | _op_FRSPRM_;
    switch ( cs ) {
      case j_class:   // 'L'
        Flags |= _op_CLSBEG_;
        continue;
      case j_typeref: // 'T'
        Flags |= _op_TYPBEG_;
        continue;
      default:
        break;
    }
    if ( !cs || !strchr(&tp_type[3], cs) ) {
nodscsg:
      if ( Flags & (_OP_FULLNM | _op_RETTYPE_) ) goto only_string;
      Flags |= _OP_NODSCR | _OP_NOSIGN;
    } else if ( Flags & _op_RETTYPE_ ) {
check_throw:
      if ( !size ) break;
      if ( size < 4 || po[1] != j_throw ) goto only_string; // ^Lx;
      Flags |= _OP_FULLNM | _OP_NOFNM | _OP_NODSCR;
      ++po;   // skip rettype/previous-';'
      --size;
      if ( possgn < 0x10000) possgn |= ((uint32)(po - tsPtr) << 16 );
only_tag:
      --size;
      ++po;
skipped_only_tag:
      switch ( *po ) {
        default:
          goto only_string;
        case j_class: // never set CLSBEG (no ONECLS)
        case j_typeref:
          Flags |= _op_TYPBEG_;
          break;
      }
    }
  }while ( ++po, size );

  if ( (Flags & (_op_PARAM_ | _op_PAREND_ | _op_ARRAY_)) || sgnlev ) {
only_string:
    Flags |= (_OP_NODSCR | _OP_NOSIGN | _OP_NOFNM | _OP_FULLNM);
  } else {
    if ( Flags & (_op_CLSBEG_ | _op_TYPBEG_) )
      Flags |= _OP_NODSCR | _OP_NOSIGN;
    else if ( !(Flags & _OP_NOSIGN) ) {
      if ( posit ) {
        Flags |= _OP_VALPOS;
        if ( possgn ) Flags |= _OP_METSIGN;
      } else if ( possgn ) Flags |= _OP_CLSSIGN;
    }
    // check for reserved words
    if ( !(Flags & _OP_NOWORD)) ResW_validate((uint32 *)&Flags, po );
  }
  if ( (ushort)Flags ) {
set_flags:  // <init>/<cinit>/V nor reserved :)
    uint32 ind = ((uint32)index) << 16;
    co->_Sflags |= (ushort)Flags;
    ConstantNode.altset(ind, co->_Sopstr);
#if _OP_VALPOS >= 0x10000u
#error
#endif
    if ( Flags & _OP_VALPOS ) {
      ConstantNode.altset(ind+1, posit);
      if ( Flags & _OP_METSIGN) ConstantNode.altset(ind+2, possgn );
      if ( !(Flags & _OP_NODSCR) ) co->flag |= HAS_CALLDSCR;
      return;
    }
  }

  cs = 0;
  if ( !(Flags & _OP_NODSCR) ) cs |= HAS_TYPEDSCR;
  if ( !(Flags & _OP_NOFNM) )  cs |= HAS_CLSNAME;
  if ( !(Flags & _OP_FULLNM) ) cs |= HAS_FLDNAME;
  co->flag |= cs;
}

//-----------------------------------------------------------------------

#include "java.hpp"
#include "oututil.hpp"

char    *bufbeg;
uint32  bufsize;
uint32  maxpos, curpos;
uchar   user_limiter;
//nexts only for out
bool   no_prim;
size_t outcnt;
char   *ref_pos;

//--------------------------------------------------------------------------
int out_commented(const char *p, color_t ntag)
{
  if ( ntag != _CURCOL) out_tagon(ntag );
  register int i = out_snprintf("%s %s", ash.cmnt, p);
  if ( ntag != _CURCOL) out_tagoff(ntag );
  return(i);
}


//----------------------------------------------------------------------
bool change_line(bool main)
{
  *set_output_ptr(bufbeg) = '\0';
  outcnt = 0;
  uchar sv = inf.indent;
  inf.indent = (uchar)curpos;
  bool res = MakeLine(bufbeg, main ? -1 : curpos);
  inf.indent = sv;
  init_output_buffer(bufbeg, bufsize);  // for autocomment with call fmtName
  return res;
}

//----------------------------------------------------------------------
static size_t putLine(void)
{
  register color_t ntag = _CURCOL;

  out_zero();
  {
    register char *p = strrchr(bufbeg, COLOR_ON);
    if ( p && p[1] && !strchr(p+2, COLOR_OFF) ) {  // second - PARANOYA
      ntag = (color_t)*(p + 1);
      out_tagoff(ntag);
    }
  }
  out_symbol('\\');
  if ( change_line(curpos != 0 && !no_prim)) return(0 );
  curpos = 0;
#ifdef __BORLANDC__
#if _CURCOL != 0
#error
#endif
#endif
  if ( ntag) out_tagon(ntag );
  ref_pos = get_output_ptr();
  return(maxpos);
}

//----------------------------------------------------------------------
bool checkLine(size_t size)
{
  return((maxpos - curpos > outcnt + size) || putLine());
}

//----------------------------------------------------------------------
uchar chkOutLine(const char *str, size_t len)
{
  if ( !checkLine(len)) return(1 );
  outcnt += len;
  OutLine(str);
  return(0);
}

//----------------------------------------------------------------------
uchar chkOutKeyword(const char *str, unsigned len)
{
  if ( !checkLine(len)) return(1 );
  OutKeyword(str, len);
  return(0);
}
#define CHK_OUT_KEYWORD(p)  chkOutKeyword(p, sizeof(p)-1)

//----------------------------------------------------------------------
uchar chkOutSymbol(char c)
{
  if ( !checkLine(1)) return(1 );
  ++outcnt;
  out_symbol(c);
  return(0);
}

//----------------------------------------------------------------------
uchar chkOutChar(char c)
{
  if ( !checkLine(1)) return(1 );
  ++outcnt;
  OutChar(c);
  return(0);
}

//----------------------------------------------------------------------
uchar chkOutSymSpace(char c)
{
  if ( !checkLine(2)) return(1 );
  out_symbol(c);
  OutChar(' ');
  outcnt += 2;
  return(0);
}

//----------------------------------------------------------------------
uchar putShort(ushort value, uchar wsym)
{
  char  tmpstr[32];

  register char *p = get_output_ptr();

  out_tagon(COLOR_ERROR);
  if ( wsym) OutChar(wsym );
  OutLong(value,
#ifdef __debug__
                debugmode ? 16 :
#endif
                10);
  out_tagoff(COLOR_ERROR);

  register size_t len = get_output_ptr() - p;
  memcpy(tmpstr, p, len);
  tmpstr[len] ='\0';
  *p = '\0';
  set_output_ptr(p);
  return(chkOutLine(tmpstr, tag_strlen(tmpstr)));
}

//----------------------------------------------------------------------
char outName(ea_t from, int n, ea_t ea, uval_t off, uchar *rbad)
{
  char  buf[MAXSTR];

  if ( get_name_expr(from, n, ea + off, off, buf, sizeof(buf)) <= 0 ) {
    if ( loadpass >= 0) QueueMark(Q_noName, cmd.ea );
    return(0);
  }
  if ( chkOutLine(buf, tag_strlen(buf)) ) {
    *rbad = 1;
    return(0);
  }
  return(1);
}

//---------------------------------------------------------------------------
uchar putVal(op_t &x, uchar mode, uchar warn)
{
  char    str[MAXSTR];
  uint32  sv_bufsize = bufsize;
  char    *sv_bufbeg = bufbeg, *sv_ptr = get_output_ptr();

  init_output_buffer(str, sizeof(str));
  {
    flags_t sv_uFlag = uFlag;
    uFlag = 0;
    OutValue(x, mode);
    uFlag = sv_uFlag;
  }
  out_zero();
  init_output_buffer(sv_bufbeg, sv_bufsize);
  set_output_ptr(sv_ptr);
  if ( warn) out_tagon(COLOR_ERROR );
  {
    register size_t i;
    if ( !warn) i = tag_strlen(str );
    else      i = tag_remove(str, str, 0);
    if ( chkOutLine(str, i)) return(0 );
  }
  if ( warn) out_tagoff(COLOR_ERROR );
  return(1);
}

//----------------------------------------------------------------------
//static _PRMPT_ outProc = putLine;
#if ( MIN_ARG_SIZE < 2) || (MIN_ARG_SIZE >= 30 )
#error
#endif
uchar OutUtf8(ushort index, fmt_t mode, color_t ntag)
{
  register size_t size = (maxpos - curpos) - outcnt;

  if ( (int)size <= MIN_ARG_SIZE ) {
DEB_ASSERT(((int)size < 0), "OutUtf8");
   if ( (size = putLine/*outProc*/()) == 0) return(1 );
  }

  if ( ntag) out_tagon(ntag );
  ref_pos = get_output_ptr();
  if ( fmtString(index, size, mode, /**outProc*/putLine) < 0) return(1 );
  outcnt += get_output_ptr() - ref_pos;
  if ( ntag) out_tagoff(ntag );
  return(0);
}

//---------------------------------------------------------------------------
uchar out_index(ushort index, fmt_t mode, color_t ntag, uchar as_index)
{
  if ( as_index ) {
    if(   !(idpflags & (IDM_BADIDXSTR | IDM_OUTASM))   // no store in file
       || !is_valid_string_index(index)) return(putShort(index));
    ntag = COLOR_ERROR;
    mode = fmt_string;
  }
  return(OutUtf8(index, mode, ntag));
}

//--------------------------------------------------------------------------
uchar out_alt_ind(uint32 val)
{
  if ( (ushort)val) return(OutUtf8((ushort)val, fmt_fullname, COLOR_IMPNAME) );
  return(putShort((ushort)(val >> 16)));
}

//--------------------------------------------------------------------------
// special label format/scan procedures
//--------------------------------------------------------------------------
void out_method_label(uchar is_end)
{
  gl_xref = gl_comm = 1;
  printf_line(0, COLSTR("met%03u_%s%s", SCOLOR_CODNAME), curSeg.id.Number,
              is_end ? "end" : "begin", COLSTR(":", SCOLOR_SYMBOL));
}

//---------------------------------------------------------------------------
static char putMethodLabel(ushort off)
{
  char  str[32];
  int   len = qsnprintf(str, sizeof(str), "met%03u_%s", curSeg.id.Number,
                        off ? "end" : "begin");

  if ( !checkLine(len)) return(1 );
  out_tagon(COLOR_CODNAME);
  outLine(str, len);
  out_tagoff(COLOR_CODNAME);
  return(0);
}

//--------------------------------------------------------------------------
// procedure for get_ref_addr
int check_special_label(char buf[MAXSTR], register int len)
{
  if(   (unsigned)len >= sizeof("met000_end")-1
     && (*(uint32*)buf & 0xFFFFFF) == ('m'|('e'<<8)|('t'<<16))) {

    switch ( *(uint32*)&buf[len -= 4] ) {
      case ('_'|('e'<<8)|('n'<<16)|('d'<<24)):
        break;
      case ('e'|('g'<<8)|('i'<<16)|('n'<<24)):
        if(    (unsigned)len >= sizeof("met000_begin")-1 - 4
           &&  *(ushort*)&buf[len -= 2] == ('_'|('b'<<8))) break;
        //PASS THRU
      default:
        len |= -1; // as flag
        break;
    }
    if ( (unsigned)len <= sizeof("met00000")-1 ) {
      uint32 off = curSeg.CodeSize;
      if ( buf[len+1] == 'b' ) off &= 0;
      register unsigned n = 0, j = sizeof("met")-1;
      for( ; ; ) {
        if ( !qisdigit((uchar)buf[j]) ) break;
        n = n*10 + (buf[j] - '0');
        if ( ++j == len ) {
          if ( n >= 0x10000 || (ushort)n != curSeg.id.Number ) break;
          return((int)off);
        }
      }
    }
  }
  return(-1);
}

//--------------------------------------------------------------------------
// end of special-label procedures
//----------------------------------------------------------------------
uchar outOffName(ushort off)
{
  if ( !off || off == curSeg.CodeSize) return(putMethodLabel(off) );
  if ( off < curSeg.CodeSize ) {
    uchar err = 0;
    if(outName(curSeg.startEA + curSeg.CodeSize, 0,
               curSeg.startEA, off, &err)) return(0); // good
    if ( err) return(1 ); // bad
  }
  return(putShort(off, 0));
}

//----------------------------------------------------------------------
bool block_begin(uchar off)
{
  return MakeLine(COLSTR("{", SCOLOR_SYMBOL), off);
}

//----------------------------------------------------------------------
bool block_end(uint32 off)
{
  return(MakeLine(COLSTR("}", SCOLOR_SYMBOL), off));
}

//----------------------------------------------------------------------
bool block_close(uint32 off, const char *name)
{
  if ( !jasmin()) return(block_end(off) );
  return(printf_line(off, COLSTR(".end %s", SCOLOR_KEYWORD), name));
}

//----------------------------------------------------------------------
bool close_comment(void)
{
  return(MakeLine(COLSTR("*/", SCOLOR_AUTOCMT), 0));
}

//---------------------------------------------------------------------------
uchar out_nodelist(uval_t nodeid, uchar pos, const char *pref)
{
  uval_t cnt, off = 0;
  netnode   node(nodeid);

  if ( (cnt = node.altval(0)) == 0) DESTROYED("out::nodelist" );

  if ( pref ) {  // jasmin
    if ( change_line() ) {
bad:
      return(0);
    }
    off = strlen(pref);
  }

  for(register unsigned i = 0; ;  ) {
    if ( pref) { // jasmin (single directive per line )
      curpos = pos;
      out_keyword(pref);
      outcnt = (size_t)off;
    } else if ( i && chkOutSymSpace(',') ) goto bad; // prompted list
    if ( out_alt_ind((uint32)node.altval(++i)) ) goto bad;
    if ( i >= cnt) return(1 );
    if ( pref && change_line() ) goto bad; // jasmin
  }
}

//----------------------------------------------------------------------
void init_prompted_output(char str[MAXSTR*2], uchar pos)
{
  maxpos = inf.margin;
//  if ( maxpos < 32 ) maxpos = 32;
//  if ( maxpos > MAXSTR - 4 ) maxpos = MAXSTR - 4;

#ifdef __debug__
  if ( debugmode == (uchar )-1 &&
     inf.s_showpref && inf.margin == 77 && !inf.binSize) maxpos -= gl_psize;
#endif
  init_output_buffer(bufbeg = str, bufsize = (MAXSTR*2)-STR_PRESERVED);
  curpos = pos;
  outcnt = 0;
}

//----------------------------------------------------------------------
uchar OutConstant(op_t& x, uchar impdsc)
{
  register uchar    savetype = x.dtyp;
  register fmt_t    fmt = fmt_dscr;
  register color_t  ntag;

  switch ( (uchar)x.cp_type ) {
    default:
      warning("OC: bad constant type %u", (uchar)x.cp_type);
      break;

    case CONSTANT_Long:
      x.dtyp = dt_qword;
      goto outNum;
    case CONSTANT_Double:
      x.dtyp = dt_double;
      goto outNum;
    case CONSTANT_Integer:
      x.dtyp = dt_dword;
      goto outNum;
    case CONSTANT_Float:
      x.dtyp = dt_float;
outNum:
      if ( putVal(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM, 0) ) break;
badconst:
      return(0);

    case CONSTANT_String:
      if ( OutUtf8(x._name, fmt_string, COLOR_STRING) ) goto badconst;
      break;

    case CONSTANT_Class:
#ifdef __BORLANDC__
#if ( fmt_cast+1) != fmt_classname || (fmt_classname+1 ) != fmt_fullname
#error
#endif
#endif
      if ( OutUtf8(x._name, (fmt_t )x.addr_shorts.high,
                 (   (fmt_t)x.addr_shorts.high < fmt_cast
                  || (fmt_t)x.addr_shorts.high > fmt_fullname) ?
                 COLOR_KEYWORD : (cmd.xtrn_ip == 0xFFFF ? COLOR_DNAME :
                                                          COLOR_IMPNAME)))
                                                                goto badconst;
      break;

    case CONSTANT_InterfaceMethodref:
    case CONSTANT_Methodref:
        fmt = fmt_retdscr;
    case CONSTANT_Fieldref:
#ifdef VIEW_WITHOUT_TYPE
        if ( impdsc )
#endif
          if ( !jasmin() && OutUtf8(x._dscr, fmt, COLOR_KEYWORD) ) goto badconst;
        out_tagon(ntag = (x._class == curClass.This.Dscr) ? COLOR_DNAME :
                                                            COLOR_IMPNAME);
        if ( jasmin() || (ntag == COLOR_IMPNAME && !impdsc) ) { // other class
          if ( OutUtf8(x._name, fmt_classname) || chkOutDot() ) goto badconst;
        }
        if ( OutUtf8(x._subnam, fmt_name) ) goto badconst; // Field
        out_tagoff(ntag);
        if ( jasmin() ) {
          if ( fmt == fmt_retdscr ) fmt = fmt_signature; // no space at end
          else if ( chkOutSpace() ) goto badconst;
        } else {
          if ( fmt != fmt_retdscr ) break;
          fmt = fmt_paramstr;
        }
        if ( OutUtf8(x._dscr, fmt, COLOR_KEYWORD) ) goto badconst;
        break;
  }
  x.dtyp = savetype;
  return(1);
}

//--------------------------------------------------------------------------
void myBorder(void)
{
  MakeNull();
  if ( user_limiter ) {
    inf.s_limiter = LMT_THIN;
    MakeBorder();
  }
  inf.s_limiter = 0;  // fo not output border between method & vars :(
}

//--------------------------------------------------------------------------
uchar out_problems(char str[MAXSTR], const char *prefix)
{
  if ( curClass.extflg & XFL_C_ERRLOAD ) {
    myBorder();
    printf_line(inf.indent,
       COLSTR("%s This class has had loading time problem(s)", SCOLOR_ERROR),
                prefix);
    if ( curClass.msgNode ) {
      MakeNull();
      if ( print_loader_messages(str, prefix) == -1) return(1 );
    }
    myBorder();
  }
  return(0);
}

//--------------------------------------------------------------------------
uchar putScope(ushort scope, uint32 doff)
{
  if ( !scope || scope == curSeg.CodeSize) return(putMethodLabel(scope) );

  if ( scope < curSeg.CodeSize ) {
    uchar err = 0;
    if(outName(curSeg.DataBase + doff, 0,
               curSeg.startEA, scope, &err)) return(0);
    if ( err) return(1 );
  }

  return(putShort(scope, 0));
}

//----------------------------------------------------------------------
size_t debLine(void)
{
  OutChar('"');
  out_tagoff(COLOR_STRING);
  if ( change_line()) return(0 );
  return(putDeb(1));
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------
void instr_beg(char str[MAXSTR*2], int mode)
{
  static const char *const addonce[] =
      { "", "_w", "_quick", "2_quick", "_quick_w" };

  init_prompted_output(str, 4);
  OutMnem(2, addonce[uchar(cmd.wid)]);
  out_zero();
  if ( mode) outcnt = tag_strlen(str );
  else {
    char *ptr = str + (outcnt = tag_remove(str, str, 0));
    set_output_ptr(ptr);
    *ptr = '\0';
  }
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------
extern const TXS  tp_decl[];

bool idaapi outop(op_t& x)
{
  uchar warn = 0;

  switch ( x.type ) {
    case o_near:
      if ( x.ref ) ++warn;
      else {
        if ( outName(cmd.ea + x.offb, x.n, curSeg.startEA, x.addr, &warn) ) break;
        if ( warn ) goto badop;
      }
      if ( putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32, warn) ) break;
      //PASS THRU
    case o_void:
badop:
      return(false);

    case o_imm:
      if ( x.ref == 2 ) ++warn;
      if ( putVal(x, OOFW_IMM | OOF_NUMBER | (x.ref ? OOFS_NOSIGN : OOF_SIGNED ),
                warn)) break;
      goto badop;

    case o_mem:
      if ( jasmin() ) goto putVarNum;
      if ( x.ref ) {
putAddr:
        ++warn;
      } else {
        if ( outName(cmd.ea + x.offb, x.n, curSeg.DataBase, x.addr, &warn) ) break;
        if ( warn ) goto badop;
      }
putVarNum:
      if ( putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16, warn) ) break;
      goto badop;

    case o_cpool:
      if ( !x.cp_ind) OUT_KEYWORD("NULL" );
      else {
        if ( x.ref ) goto putAddr;
        if ( !OutConstant(x) ) goto badop;
      }
      break;

    case o_array:
      if ( !x.ref ) {
        int i = (uchar)x.cp_type - (T_BOOLEAN-1); // -1 - correct tp_decl
        if ( chkOutKeyword(tp_decl[i].str, tp_decl[i].size) ) goto badop;
      } else {
        static const char tt_bogust[] = "BOGUST_TYPE-";

        if ( !checkLine(sizeof(tt_bogust) + 2) ) goto badop;
        out_tagon(COLOR_ERROR);
        outcnt += out_snprintf("%c%s%u", WARN_SYM, tt_bogust, (uchar)x.cp_type);
        out_tagoff(COLOR_ERROR);
      }
      break;

    default:
      warning("out: %a: bad optype %d", cmd.ip, x.type);
      break;
  }
  return(true);
}

//--------------------------------------------------------------------------
void idaapi footer(void)
{
  if ( !jasmin()) block_end(0 );
}

//----------------------------------------------------------------------

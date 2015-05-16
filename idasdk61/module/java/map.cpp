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
int32 print_loader_messages(char str[MAXSTR], const char *cmt)
{
  ssize_t i, j, len;
  netnode temp(curClass.msgNode);

  i = 0;
  if ( (j = (size_t)temp.altval(i)) == 0 ) {
badbase:
    DESTROYED("loader_message");
  } else do {
    if ( (len = temp.supstr(i, str, MAXSTR)) <= 0 ) goto badbase;
    if ( cmt ) {
      if ( printf_line(0, "%s%s", cmt, str)) return(-1 );
    } else {
      qfwrite(myFile, str, len);
      if ( qfputc('\n', myFile) == EOF) return(-1 );
    }
  }while ( ++i < j );
  return((int32)i);
}

//----------------------------------------------------------------------
static uchar no_prompt;

//----------------------------------------------------------------------
static uchar prompt(void)
{
  if ( ferror(myFile)) return(0 );
  if ( no_prompt) return((uchar)!feof(myFile) );

  if ( qfputc('\n', myFile) == EOF) return(0 );
  qfprintf(myFile, "%*c", curpos, ' ');
  return(1);
}

//----------------------------------------------------------------------
static size_t wrtutf(void)
{
  *set_output_ptr(bufbeg) = '\0';
  qfprintf(myFile, "%s", bufbeg);
  if ( !prompt()) return(0 );
  return(maxpos - 1);
}

//----------------------------------------------------------------------
static int utfstr(ushort index, const ConstOpis *)
{
  register int i;

  init_output_buffer(bufbeg, bufsize);
  i = fmtString(index, maxpos -= curpos, fmt_string, wrtutf);
  term_output_buffer();
  maxpos += curpos;
  if ( i < 0) return(0 );
  qfprintf(myFile, "%s\n", bufbeg);
  return(++i);
}

//----------------------------------------------------------------------
static int outnum(ushort type, const ConstOpis *co)
{
  char  str[40];
  op_t  x;

  x.value = co->value;
  x.addr = co->value2;
#ifdef __EA64__
  x.value = make_ulonglong((uint32)x.value, (uint32)x.addr);
#endif
  x.type = o_imm;
  x.dtyp = (uchar)(type - 3);
  x.offb = 0;
  init_output_buffer(str, sizeof(str));
  OutValue(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM);
  term_output_buffer();
  tag_remove(str, str, 0);
  qfprintf(myFile, "value = %s\n", str);
  return(1);
}

//----------------------------------------------------------------------
static char ind_fmt[] = "%s=%-5u";

//----------------------------------------------------------------------
static int outref(ushort count, const ConstOpis *co)
{
  static const char typ[] = " Descriptor", nam[] = " Name";

  switch ( count ) {
    case 3:
      qfprintf(myFile, ind_fmt, "Class", co->_class);
      qfprintf(myFile, ind_fmt, " ref",  co->_name);
      qfprintf(myFile, ind_fmt, typ,     co->_dscr);
      qfprintf(myFile, ind_fmt, nam,     co->_subnam);
      break;
   case 2:
      qfprintf(myFile, ind_fmt, &typ[1], co->_name);
      qfprintf(myFile, ind_fmt, nam, co->_class);
      break;
   case 1:
      qfprintf(myFile, ind_fmt, "Index", co->_name);
      break;
  }
  qfputc('\n', myFile);
  return(1);
}

//----------------------------------------------------------------------
static char rfmt[] = "                %5u=> ";
static int refput(ushort index)
{
  if ( !LoadOpis(index, CONSTANT_Utf8, NULL)) return(0 );

  qfprintf(myFile, rfmt, index);
  return(utfstr(index, NULL));
}

//----------------------------------------------------------------------
int32 idaapi gen_map_file(FILE *fp)
{
  static const char frm[] =
                      "Map format\n\n"
                      "<~W~idth:D:3:::> [72-%D], 0 - unlimited \n"
                      " Printing\n"
                      "<~A~ll:R>       Included constant types\n"
                      "<~U~nused  :R>>    <Utf~8~:C>\n"
                      " Sorting by<~C~lass:C>\n"
                      "<~T~ype:R><~R~eferences:C>\n"
                      "<U~n~sorted:R>><Na~m~eAndType :C>\n"
                      " Number in pool<Num~b~ers:C>\n"
                      "<~D~ecimal :R><~S~tring:C>>\n"
                      "<~H~ex:R>>\n\n"
                      "<~O~ut Utf8 string without encoding :C>\n"
                      "<~I~nclude loader problem messages  :C>>\n\n";

  static const struct {
    ushort  mask;
    ushort  skip;
    char    name[8];
    int     (*proc)(ushort index, const ConstOpis *);
    ushort  arg;
  }defr[MAX_CONSTANT_TYPE] = {
                     {0x01, 0, "Utf8   ", utfstr, 0},
                     {0x00, 0, "",        NULL, 0}, // unicode
                     {0x10, 4, "Integer", outnum, 3 + dt_dword},
                     {0x10, 4, "Float  ", outnum, 3 + dt_float},
                     {0x10, 8, "Long   ", outnum, 3 + dt_qword},
                     {0x10, 8, "Double ", outnum, 3 + dt_double},
                     {0x02, 2, "Class  ", outref, 1},
                     {0x20, 2, "String ", outref, 1},
                     {0x04, 4, "Fld_ref", outref, 3},
                     {0x04, 4, "Met_ref", outref, 3},
                     {0x04, 4, "Int_ref", outref, 3},
                     {0x08, 4, "nam&typ", outref, 2}
                   };

#define STR_MIN_RESERVED     32
  char   str[MAXSTR];
  uchar  tflag;
  int32  width, pos, numstr = 0;
  uint32 save_flags = idpflags;
  ushort curbit = 1;
  short  unus = 1, unsort = 1, hexnum = 0, typemask = 0x3F, encinc = 2;
  ConstOpis opis;
  register ushort i, j;
  static char lft_fmt[] = "%08lX %5u%c %s ";

  if ( !(idpflags & IDF_ENCODING) ) ++encinc;  // |= 1
  uFlag = decflag();  // Decimal OutValue
  width = 80;
  bufsize = pos = sizeof(str)-32;
  if(!AskUsingForm_c(frm, &width, &pos, &unus, &unsort,
                     &typemask, &hexnum, &encinc)) return(0);
  if ( encinc & 2 ) unus = 0; // from error - all
  idpflags &= ~IDF_ENCODING;
  if ( !(encinc & 1) ) idpflags |= IDF_ENCODING;
#if ( MAXSTR-STR_MIN_RESERVED ) <= 72
#error
#endif
  no_prompt = 0;
  if ( width < 72 ) {
    if ( width ) width = 72;
    else {
      no_prompt = 0;
set_max:
      width = sizeof(str)-STR_MIN_RESERVED;
    }
  } else if ( width > (MAXSTR-STR_MIN_RESERVED) ) goto set_max;
  if ( !typemask ) typemask = 0x3F;

  if ( hexnum ) {
    lft_fmt[7] = ind_fmt[5] = rfmt[17] = '4';
    lft_fmt[8] = ind_fmt[6] = rfmt[18] = 'X';
    curpos = 8 + 1 + 4 + 1 + 1 + 0 + 1;
  } else {
    lft_fmt[7] = ind_fmt[5] = rfmt[17] = '5';
    lft_fmt[8] = ind_fmt[6] = rfmt[18] = 'u';
    curpos = 8 + 1 + 5 + 1 + 1 + 0 + 1;
  }
  if ( unsort ) {
    curpos += 7;
    curbit = typemask;
  }
  maxpos  = width;
  bufbeg  = str;
  myFile  = fp;

  do {
    while ( !(typemask & curbit) ) curbit <<= 1;

    for(tflag = (uchar)unsort, pos = 10, i = 1; i <= curClass.maxCPindex; i++) {
      if ( !LoadOpis(i, 0, &opis) || opis.type == CONSTANT_Unicode )
                                                        DESTROYED("map::CP");
      j = opis.type - 1;
DEB_ASSERT((j >= MAX_CONSTANT_TYPE), "map:type");
      if ( (!unus || !(opis.flag & _REF)) && (curbit & defr[j].mask) ) {
        if ( !numstr ) {
          static const char fmh[]= "This file generated by IDA";

          for(int k = (maxpos - sizeof(fmh)) / 2; k; k--) qfputc(' ', fp);
          char dname[MAXSTR];
          if ( ConstantNode.supstr(CNS_SOURCE, dname, sizeof(dname)) < 0 )
            DESTROYED("map:srcname");
          qfprintf(fp, "%s\n\n"
                       "   Constant Pool for \"%s\"\n\n"
                       " offset  #(%s)\n",
                   fmh, dname, hexnum ? "hex" : "dec");
          numstr =  5;
        }
        if ( !tflag ) {
          qfprintf(fp, "\n-----CONSTANT-%s-----\n",
                   (defr[j].arg < 3) ? defr[j].name :
                                       ((defr[j].arg == 3) ?
                                          "(program references)" :
                                          "(numeric values)"));
          ++tflag;
          numstr += 2;
        }
        qfprintf(fp, lft_fmt, pos, i, (opis.flag & _REF) ? ' ' : '*',
                       (unsort || defr[j].arg >= 3) ? defr[j].name : "");
        {
          register int n = defr[j].proc(defr[j].arg ? defr[j].arg : i, &opis);
          if ( n <= 0 ) goto do_eof;
          numstr += n;
        }
        if ( unus && unsort && opis.type >= CONSTANT_Class ) {
          numstr += refput(opis._name);
          if ( opis.type > CONSTANT_String ) {
            if ( opis.type == CONSTANT_NameAndType )
              numstr += refput(opis._class);
            else {
              numstr += refput(opis._subnam);
              numstr += refput(opis._dscr);
            }
          }
        }
        if ( feof(fp) || ferror(fp) ) goto do_eof;
      }

      ++pos;
      switch ( j = defr[j].skip ) {
        case 0: // Utf8 / Unicode
          pos += opis._Ssize + 2;
          break;
        case 8: // Long / Double
DEB_ASSERT((i == curClass.maxCPindex), "map:CPend");
          ++i;
        default:
          pos += j;
          break;
      }
    }
  }while ( (typemask ^= curbit) != 0 );

  if ( numstr ) {  // if error print before - header problems!
    qfprintf(fp, "\nEnd of map\n");
    numstr += 2;

    if ( (encinc & 2) && curClass.msgNode ) {
      qfprintf(fp, "\nLoader problem messages\n\n");
      int32 slen = print_loader_messages(str, NULL);
      if ( slen == -1 ) goto do_eof;
      numstr += slen + 5;
      qfprintf(fp, "\nEnd of messages\n");
    }
    if ( feof(fp) || ferror(fp) ) {
do_eof:
      numstr = EOF;
    }
  }
  myFile = NULL;
  idpflags = save_flags;
  return(numstr);
}

//----------------------------------------------------------------------
uchar loadDialog(bool manual)
{
  static const char fmt[] =
"HELP\n"
"Java-VM class file loading options Ü\n"
" ßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßßß\n"
"\n"
"Do not create 'import' segment with external-references\n"
"\n"
"  Prohibits the creation of a segment with external names, classes, and\n"
"  methods.\n"
"\n"
"\n"
"Create 'import' segment with with references from commands\n"
"\n"
"  Only regular references to the import segment will be collected.\n"
"  If this option is off, then all references (including simple text\n"
"  references) will be collected.\n"
"\n"
"\n"
"Field/variable declarations are included in references\n"
"\n"
"  Cross references from field declarations are collected in the import\n"
"  segment. For example, a field declaration\n"
"\n"
"    Field borland.ui.AboutDialog about\n"
"\n"
"  creates a reference to class borland.ui.AboutDialog\n"
"\n"
"\n"
"Method return types are included in references\n"
"\n"
"  Cross references from the return type and arguments of method\n"
"  declarations are collected in the import segment.\n"
"  NOTE: The import segment does not contain classes that appear only in\n"
"        the arguments of the method declarations.\n"
"\n"
"Store unknown attributes to external files\n"
"\n"
"  This option allows to extract non-standard attributes (if present)\n"
"  and store them to a set of files in the current directory.\n"
"  Filenames will have <classname>.<tagname>.<attributename> form\n"
"\n"
"\n"
"Rename local (slot) variables (if information is available)\n"
"\n"
"  This option allows to use names from variable declarations to\n"
"  rename local variables if the input file has this information.\n"
"\n"
"\n"
"Create visible representation of stripped names\n"
"\n"
"  Some java classes have their local\n"
"  names stripped. This option allows IDA to recreate such local names.\n"
"  NOTE: If this option is selected then all one-character names with\n"
"        the character code >= 0x80 will be ignored.\n"
"\n"
"\n"
"Continue loading after errors in additional attributes\n"
"\n"
"  Normally all errors in the classfile structure are fatal.\n"
"  If this option is on, errors in the additional attributes\n"
"  produce only warnings and the loading process continues.\n"
"\n"
"ENDHELP\n"
"Java loading options\n"
"\n"
"            Class File version %D.%D (JDK1.%D%A)\n"
"\n"
"\n"
"<~D~o not create 'import' segment with external-references :R>\n"
"<~C~reate 'import' segment with references from commands   :R>\n"
"<~F~ield/variable declarations are included in references  :R>\n"
"<~M~ethod return types are included in references          :R>>\n"
"\n"
"<~S~tore unknown attributes to external files              :C>\n"
"<~R~ename local (slot) variables (if info is available)    :C>\n"
"<Create ~v~isible representation of stripped names         :C>\n"
"<Continue ~l~oading after errors in additional attributes  :C>>\n"
"\n"
"\n";

#if ( (MLD__DEFAULT & MLD_METHREF) && !(MLD__DEFAULT & MLD_VARREF) ) || \
    ((MLD__DEFAULT & MLD_VARREF)  && !(MLD__DEFAULT & MLD_EXTREF))
#error
#endif

  if ( !manual) return(MLD__DEFAULT );

  short rtyp =
#if ( MLD__DEFAULT & MLD_METHREF )
                3,
#elif ( MLD__DEFAULT & MLD_VARREF )
                2,
#elif ( MLD__DEFAULT & MLD_EXTREF )
                1,
#else
                0,
#endif
        mod   = (MLD__DEFAULT & (MLD_EXTATR | MLD_LOCVAR | MLD_STRIP |
                                 MLD_FORCE)) >> 3;
#if ( MLD_EXTATR >> 3) != 1 || (MLD_LOCVAR >> 3 ) != 2 || \
    (MLD_STRIP >> 3) != 4 || (MLD_FORCE >> 3) != 8
#error
#endif
  {
    uval_t maxv = curClass.MajVers,
           minv = curClass.MinVers,
           jdk  = curClass.JDKsubver;

    if(!AskUsingForm_c(fmt, &maxv, &minv, &jdk,
                       jdk == 3 ? "/CLDC" : "",
                       &rtyp, &mod)) qexit(1);
  }

  idpflags &= ~IDM_REQUNK;  // do not use 'request mode' when 'manual options'

  uchar ans = 0;

#if MLD_EXTATR != (1<<3) || MLD_LOCVAR != (2<<3) || MLD_STRIP != (4<<3) || \
    MLD_FORCE != (8<<3)
#error
#endif
  ans |= ((uchar)mod) << 3;
#if MLD_EXTREF != 1 || MLD_VARREF != 2 || MLD_METHREF  != 4
#error
#endif
  ans |= (uchar)((1 << rtyp) - 1);
  return(ans);
}

//----------------------------------------------------------------------

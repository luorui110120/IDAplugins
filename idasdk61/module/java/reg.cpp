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
#include <diskio.hpp>
#include <ieee.h>
#include "npooluti.hpp"

uint32 idpflags = IDFM__DEFAULT;

static int start_asm_list;

//-----------------------------------------------------------------------
#ifdef __debug__
NORETURN void _destroyed(const char *from)
#else
NORETURN void _destroyed(void)
#endif
{
  error("Database is corrupted!"
#ifdef __debug__
                               " [at: %s]", from
#endif

                                                );
}

//-----------------------------------------------------------------------
//UNCOMPAT
#ifdef __debug__
NORETURN void _faterr(uchar mode, const char *from)
#else
NORETURN void _faterr(uchar mode)
#endif
{
  error("Internal error (%s)"
#ifdef __debug__
                               " [at: %s]"
#endif
        , mode ? "compatibility" : "idp"
#ifdef __debug__
        , from
#endif
       );
}

//-----------------------------------------------------------------------
static void sm_validate(SegInfo *si)
{
  static uchar  primmsg;

  ea_t        segTopEA = si->startEA + si->CodeSize;
  netnode     temp(si->smNode);
  nodeidx_t   nid = temp.sup1st();

  if ( (ea_t)nid < si->startEA ) goto destroyed;
  do {
    if(   (ea_t)nid >= segTopEA
       || temp.supval(nid, NULL, 0) != sizeof(sm_info_t)) goto destroyed;
    if ( !isHead(get_flags_novalue((ea_t)nid)) ) {
      QueueMark(Q_head, (ea_t)nid);
      if ( !primmsg ) {
        primmsg = 1;
        msg("\n");
      }
      msg("StackMap refers to nonHead offset %X in Method#%u\n",
          (uint32)((ea_t)nid - si->startEA), si->id.Number);
    }
  }while ( (nid = temp.supnxt(nid)) != BADNODE );
  return;

destroyed:
  DESTROYED("sm_validate");
}

//----------------------------------------------------------------------
// visble for upgrade ONLY
void coagulate_unused_data(const SegInfo *ps)
{
  unsigned size = 0;
  ea_t      ea = ps->DataBase;
  for(ea_t top = ea + ps->DataSize; ea < top; ea++)
    if(   isHead(get_flags_novalue(ea))
       && get_first_dref_to(ea) == BADADDR) {

      ConstantNode.chardel(ea, UR_TAG);  // unicode renaming support
      del_global_name(ea);
      do_unknown(ea, DOUNK_SIMPLE);
      ++size;
      //correct kenel error :(
      ea_t to;
      while ( (to = get_first_dref_from(ea)) != BADADDR) del_dref(ea, to );
    } else if ( size ) {
      do_data_ex(ea-size, alignflag(), size, BADNODE);
      size &= 0;
    }
  if ( size) do_data_ex(ea-size, alignflag(), size, BADNODE );
}

//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
static int idaapi out_asm_file(FILE *fp, const char *line,
                               bgcolor_t, bgcolor_t)
{
  if ( line ) {
    char buf[MAXSTR];

    tag_remove(line, buf, sizeof(buf));
    if ( inf.s_entab) entab(buf );
    size_t len = strlen(buf), chk = len;

    if ( len && buf[len-1] == '\\' ) --len;
    if(   qfwrite(fp, buf, len) != len
       || (chk == len && qfputc('\n', fp) == EOF)) return(0);
  }
  return(1);
}

//--------------------------------------------------------------------------
static int notify(processor_t::idp_notify msgid, ...) // Various messages:
{
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

  int retcode = invoke_callbacks(HT_IDP, msgid, va);
  if ( retcode ) goto done;

  ++retcode;  // = 1;

  switch ( msgid ) {
    case processor_t::init:
      inf.mf = 1;       //reverse byte!
      break;

    case processor_t::rename:
      va_arg(va, ea_t);
      for(char const *pn, *p = va_arg(va, const char *);
          (pn = strchr(p, '\\')) != NULL; p = pn+1)
      {
        if ( *++pn != 'u' ) {
inv_name:
          --retcode;  // 0
          warning("Backslash is accepted only as a unicode escape sequence in names");
          break;
        }
        for(int i = 0; i < 4; i++) if ( !qisxdigit((uchar)*++pn) ) goto inv_name;
      }
      break;

    case processor_t::newfile:
      if ( inf.filetype != f_LOADER )
      {
        database_flags |= DBFL_KILL; // clean up the database files
        error("The input file does not have a supported Java file format");
      }
      myBase(va_arg(va, char *));
      inf.lowoff  = inf.highoff = BADADDR;
      break;

    case processor_t::oldfile:
      myBase(NULL);
      break;

    case processor_t::closebase:
      memset(&curClass, 0, sizeof(curClass));
    case processor_t::term:
      qfree(tsPtr);
      qfree(smBuf);
      qfree(annBuf);
      if ( msgid != processor_t::term )
      {
        tsPtr   = NULL;
        smBuf   = NULL;
        annBuf  = NULL;
    case processor_t::savebase:
        ConstantNode.altset(CNA_IDPFLAGS, (ushort)idpflags);
      }
      break;

#ifdef __debug__
    case processor_t::newprc:
      if ( va_arg(va, int) == 1 ) {   // debug mode
        ph.flag &= ~(PR_DEFNUM | PR_NOCHANGE);
        ph.flag |= PRN_HEX;
        if ( inf.margin == 77 && !inf.binSize && !inf.s_showpref ) {
          ++inf.s_showpref;
          --debugmode;
        } else ++debugmode;
      } else {                  // normal node
        ph.flag &= ~PR_DEFNUM;
        ph.flag |= (PRN_DEC | PR_NOCHANGE);
        if(   debugmode == (uchar)-1
           && inf.s_showpref
           && !inf.binSize
           && inf.margin == 77) inf.s_showpref = 0;
        debugmode = 0;
      }
      break;
#endif

    case processor_t::loader:
      {
        linput_t *li = va_arg(va, linput_t *);
        loader(qlfile(li), va_argi(va, bool));
        retcode = 0;
      }
      if ( start_asm_list) set_target_assembler(1 );
      break;

    case processor_t::out_src_file_lnnum:
      if ( jasmin() ) {
        va_arg(va, const char *); // skip file name
        printf_line(2, COLSTR(".line %lu", SCOLOR_ASMDIR), va_arg(va, size_t));
        ++retcode;  // = 2
      }
      break;

    case processor_t::gen_asm_or_lst:
      {
        static bool mode_changed;

        if ( va_argi(va, bool)) {           // starting (else end of generation )
          va_arg(va, FILE *);             // output file (skip)
          bool isasm = va_argi(va, bool); // assembler-true, listing-false
          if ( isasm && (idpflags & IDF_CONVERT) ) {
            va_arg(va, int);              // flags of gen_file() (skip)
            *va_arg(va, gen_outline_t**) = out_asm_file;
            idpflags |= IDM_OUTASM;
          }
          if ( isasm == jasmin() ) break;    // need change mode?
        } else {                          // end of generation.
          idpflags &= ~IDM_OUTASM;
          if ( !mode_changed ) break;        // mode changed?
        }
        mode_changed = !mode_changed;
        set_target_assembler(!inf.asmtype);
      }
      break;

    case processor_t::get_autocmt:
      {
        char *buf = va_arg(va, char *);
        if ( make_locvar_cmt(buf, va_arg(va, size_t)) ) ++retcode; // = 2
      }
      break;

    case processor_t::auto_empty:
      if ( !(curClass.extflg & XFL_C_DONE) ) {  // kernel BUGs
        curClass.extflg |= XFL_C_DONE;
        msg("JavaLoader finalization stage...");
        for(int n = curClass.MethodCnt; n; n--) {
          SegInfo si;
          if ( ClassNode.supval(-n, &si, sizeof(si)) != sizeof(si) )
            DESTROYED("postprocess");
          if ( si.smNode || si.DataSize ) {
            showAddr(si.startEA);
            if ( si.smNode) sm_validate(&si );
            if ( si.DataSize) coagulate_unused_data(&si );
          }
        }
        ConstantNode.supset(CNS_CLASS, &curClass, sizeof(curClass));  // all chgs
        sm_node = 0; // anebale work (out) with StackMap
        msg("OK\n");
      }
    default:
      break;
  }
  va_end(va);
done:
  return(retcode);
}

//----------------------------------------------------------------------
//  floating point conversion
static int idaapi j_realcvt(void *m, eNE e, ushort swt)
{
  inf.mf = 0;
  int i = ieee_realcvt(m, e, swt);
  inf.mf = 1;
  return(i);
}

//----------------------------------------------------------------------
void check_float_const(ea_t ea, void *m, char len)
{
  if ( !has_cmt(get_flags_novalue(ea)) && j_realcvt(m, NULL, (uchar)len) < 0 ) {
    char  cmt[2+5*5+2], *p = cmt;

    *p++ = '0';
    *p++ = 'x';
    do p += qsnprintf(p, 5, "%04X", ((ushort *)m)[uchar(len)]); while ( --len >= 0 );
    QueueMark(Q_att, ea);
    append_cmt(ea, cmt, false);
  }
}

//----------------------------------------------------------------------
// Set IDP options. Either from the configuration file either allow the user
// to specify them in a dialog box.
static const char *idaapi set_idp_options(
        const char *keyword,
        int value_type,
        const void *value)
{
  static const char form[] =
"HELP\n"
"JAVA specific options Ü\n"
" ßßßßßßßßßßßßßßßßßßßßßß\n"
"\n"
" Multiline .debug\n"
"\n"
"       If this option is on, IDA forces new .debug directive at every\n"
"       LR ('\\n') in the input string\n"
"\n"
" Hide StackMap(s)\n"
"\n"
"       If this option is on, IDA hides .stack verification declarations\n"
"\n"
" Auto strings\n"
"\n"
"       If this option is on, IDA makes 'prompt-string' after every CR in\n"
"       the quoted-string operand\n"
"\n"
" Save to jasmin\n"
"\n"
"      If this option is on, IDA creates asm-file in the jasmin-\n"
"      compatibe form: concatenates 'prompted' string, reserved names\n"
"      will be enclosed in quotes.\n"
"      Also when this option is on IDA changes unicode-to-oem encoding to\n"
"      unicode-to-ansi encoding because jasmin expects ansi encoding.\n"
"\n"
" Enable encoding\n"
"\n"
"       If this option is on, IDA converts unicode characters which\n"
"       can be representated in current locale to ascii characters.\n"
"\n"
" Nopath .attribute\n"
"      If this option is on, IDA prints filename in '.attribute'\n"
"      directives without the path part.\n"
"\n"
"\n"
" Bad index as string\n"
"      If this option is on, IDA will show invalid name/type references\n"
"      as a quoted string.\n"
"ENDHELP\n"
"JAVA specific options\n"
"\n"
" <~M~ultilne .debug   :C>\n"
" <~H~ide StackMap(s)  :C>\n"
" <~A~uto strings      :C>\n"
" <~S~ave to jasmin    :C>\n"
" <~E~nable encoding   :C>\n"
" <~N~opath .attribute :C>>\n"
"\n"
" <~B~ad index as string :C>>\n"
"\n"
"\n";


  if ( !keyword ) {
    uint32 tmp = (idpflags >> 16) & IDM__REQMASK, old = idpflags;
    AskUsingForm_c(form, (ushort *)&idpflags, (ushort *)&tmp);
    idpflags = (idpflags & ~(IDM__REQMASK << 16)) | (tmp << 16);
    if ( (idpflags ^ old) & IDF_ENCODING) rename_uninames(-1 );
    return(IDPOPT_OK);
  }

  if ( value_type != IDPOPT_BIT) return(IDPOPT_BADTYPE );

  if ( !strcmp(keyword, "JAVA_MULTILINE_DEBUG") ) {
    setflag(idpflags, IDF_MULTDEB, *(int*)value);
    return(IDPOPT_OK);
  }
  if ( !strcmp(keyword, "JAVA_HIDE_STACKMAP") ) {
    setflag(idpflags, IDF_HIDESM, *(int*)value);
    return(IDPOPT_OK);
  }
  if ( !strcmp(keyword, "JAVA_AUTO_STRING") ) {
    setflag(idpflags, IDF_AUTOSTR, *(int*)value);
    return(IDPOPT_OK);
  }
  if ( !strcmp(keyword, "JAVA_ASMFILE_CONVERT") ) {
    setflag(idpflags, IDF_CONVERT, *(int*)value);
    return(IDPOPT_OK);
  }
  if ( !strcmp(keyword, "JAVA_ENABLE_ENCODING") ) {
    setflag(idpflags, IDF_ENCODING, *(int*)value);
    return(IDPOPT_OK);
  }
  if ( !strcmp(keyword, "JAVA_NOPATH_ATTRIBUTE") ) {
    setflag(idpflags, IDF_NOPATH, *(int*)value);
    return(IDPOPT_OK);
  }

  if ( !strcmp(keyword, "JAVA_UNKATTR_REQUEST") ) {
    setflag(idpflags, IDM_REQUNK, *(int*)value);
    return(IDPOPT_OK);
  }
  if ( !strcmp(keyword, "JAVA_UNKATTR_WARNING") ) {
    setflag(idpflags, IDM_WARNUNK, *(int*)value);
    return(IDPOPT_OK);
  }
  if ( !strcmp(keyword, "JAVA_STARTASM_LIST") ) {
    start_asm_list = *(int*)value;
    return(IDPOPT_OK);
  }

  return(IDPOPT_BADKEY);
}

//----------------------------------------------------------------------
static void idaapi func_header(func_t *) {}
static void idaapi func_footer(func_t *) {}
static bool idaapi java_specseg(ea_t ea, uchar)    { java_data(ea); return false; }

//----------------------------------------------------------------------
static asm_t jasmin_asm = {
  AS_COLON | ASH_HEXF3 | ASO_OCTF1 | ASD_DECF0 | AS_ONEDUP | ASB_BINF3,
  UAS_JASMIN,
  "Jasmin assembler",
  0,        // no help screen
  NULL,     // header
  NULL,     // bad instructions
  NULL,     // origin
  NULL,     // end of file

  ";",      // comment string
  '"',      // string delimiter
  '\'',     // char delimiter
  "\"'\\",  // special symbols in char and string constants

  "",         // ascii string directive
  "",         // byte directive
  NULL,       // word directive
  NULL,       // double words
  NULL,       // qwords
  NULL,       // oword  (16 bytes)
  NULL,       // float
  NULL,       // double
  NULL,       // no tbytes
  NULL,       // no packreal
  NULL,     // arrays:
            // #h - header(.byte,.word)
            // #d - size of array
            // #v - value of array elements
  NULL,         //".reserv  %s",  // uninited data (reserve space)
  " = ",        // equ
  NULL,         // seg prefix
  NULL,         // preline for checkarg
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg operations
  NULL,         // XlatAsciiOutput
  NULL,         // a_curip
  func_header,  // func header
  func_footer,  // func footer
  "",     // public (disable ouput)
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "!",     // not
  "<<",    // shl
  ">>",    // shr
  NULL,    // sizeof
};

//----------------------------------------------------------------------
static asm_t list_asm = {
  AS_COLON | ASH_HEXF3 | ASO_OCTF1 | ASD_DECF0 | AS_ONEDUP | ASB_BINF3,
  0,
  "User friendly listing",
  0,        // no help screen
  NULL,     // header
  NULL,     // bad instructions
  NULL,     // origin
  NULL,     // end of file

  "//",     // comment string
  '"',      // string delimiter
  '\'',     // char delimiter
  "\"'\\",  // special symbols in char and string constants

  "",         // ascii string directive
  "",         // byte directive
  NULL,       // word directive
  NULL,       // double words
  NULL,       // qwords
  NULL,       // oword  (16 bytes)
  NULL,       // float
  NULL,       // double
  NULL,       // no tbytes
  NULL,       // no packreal
  NULL,     // arrays:
            // #h - header(.byte,.word)
            // #d - size of array
            // #v - value of array elements
  NULL,         //".reserv  %s",  // uninited data (reserve space)
  " = ",        // equ
  NULL,         // seg prefix
  NULL,         // preline for checkarg
  NULL,         // checkarg_atomprefix
  NULL,         // checkarg operations
  NULL,         // XlatAsciiOutput
  NULL,         // a_curip
  func_header,  // func header
  func_footer,  // func footer
  "",     // public (disable ouput)
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "!",     // not
  "<<",    // shl
  ">>",    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
static asm_t *asms[] = { &jasmin_asm, &list_asm, NULL };

static const char *RegNames[] = { "vars" , "optop", "frame", "cs", "ds" };

static const char *shnames[] =
{
  "java",
#ifdef __debug__
  "_javaPC",
#endif
  NULL
};

static const char *lnames[] =
{
  "java",
#ifdef __debug__
  "java full (IBM PC, debug mode)",
#endif
  NULL
};

//--------------------------------------------------------------------------
static uchar retcode_0[] = { j_ret },
             retcode_1[] = { j_ireturn },
             retcode_2[] = { j_lreturn },
             retcode_3[] = { j_freturn },
             retcode_4[] = { j_dreturn },
             retcode_5[] = { j_areturn },
             retcode_6[] = { j_return  },
             retcode_7[] = { j_wide, j_ret };

static bytes_t retcodes[] = {
 { sizeof(retcode_0), retcode_0 },
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { sizeof(retcode_4), retcode_4 },
 { sizeof(retcode_5), retcode_5 },
 { sizeof(retcode_6), retcode_6 },
 { sizeof(retcode_7), retcode_7 },
 { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,
  PLFM_JAVA,
  PRN_DEC | PR_RNAMESOK | PR_NOCHANGE | PR_NO_SEGMOVE,
  8,                  // 8 bits in a byte for code segments
  8,                  // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  header,
  footer,

  segstart,
  segend,

  NULL,

  ana,
  emu,

  out,
  outop,
  java_data,
  NULL,          //  cmp_opnd,  // 0 if not cmp 1 if eq
  can_have_type, //(&op)  int : 1 -yes 0-no

  qnumber(RegNames),  // Number of registers
  RegNames,           // Regsiter names
  NULL,               // get abstract register

  0,                  // Number of register files
  NULL,               // Register file names
  NULL,               // Register descriptions
  NULL,               // Pointer to CPU registers

  rVcs,rVds,
  0,                  // size of a segment register
  rVcs,rVds,

  NULL,               // No known code start sequences
  retcodes,

  0,j_last,
  Instructions,
  NULL,               // isFarJump or Call
  NULL,               //  Offset Generation Function. Usually NULL.
  0,                  // size of tbyte
  j_realcvt,
  {0,7,15,0},         // real width
  NULL,               // is this instruction switch
  gen_map_file,       // generate map-file
  get_ref_addr,       // extract address from a string
  NULL,               // is_sp_based
  NULL,               // create_func_frame
  NULL,               // get_func_retsize
  NULL,               // gen_stkvar_def
  java_specseg,       // out special segments
  j_ret,              // icode_return
  set_idp_options,    // Set IDP options
  NULL,               // Is alignment instruction?
  NULL,               // Micro virtual machine description
  0,                  // high_fixup_bits
};

//-----------------------------------------------------------------------

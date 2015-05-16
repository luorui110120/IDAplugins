//#define __debug__

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

#ifndef _JAVA_HPP
#define _JAVA_HPP

#define VIEW_WITHOUT_TYPE // no show return/filed type in command if !jasmin()

#include <pro.h>
#include "../idaidp.hpp"
#include <fpro.h>
#include "classfil.hpp"
#include "ins.hpp"

#pragma pack(1)
//----------------------------------------------------------------------
// Redefine temporary names
//
#define         wid         segpref
#define         xtrn_ip     auxpref

#define         swit        Op1.specflag2
#define         ref         specflag1
#define         _name       value_shorts.low
#define         _class      value_shorts.high
#define         _dscr       addr_shorts.low
#define         _subnam     addr_shorts.high
#define         cp_ind      specval_shorts.low
#define         cp_type     specval_shorts.high
// nexts for Utf8 (on load) and _Ssize used in MAP only
#define         _Ssize      addr_shorts.low
#define         _Sflags     addr_shorts.high
#define         _Sopstr     value2

// command aliases
#define         o_cpool     o_idpspec0
#define         o_array     o_idpspec1

//----------------------------------------------------------------------
struct TXS
{
  const char  *str;
  uchar       size;
};
#define TXS_DECLARE(p) { p, (uchar)(sizeof(p)-1) }
#define TXS_EMPTY()    { NULL, 0 }

//----------------------------------------------------------------------
typedef struct {
                 uchar type;   // CONSTANT_type
                 uchar flag;
#define _REF          0x01   // has reference
#define HAS_FLDNAME   0x02   // Utf8 is valid Field/Variable Name
#define HAS_TYPEDSCR  0x04   // Utf8 is valid Descriptor
#define HAS_CALLDSCR  0x08   // Utf8 is valid Descriptor for Method
#define HAS_CLSNAME   0x10   // Utf8 is valid as Class Name (Not FLD!)
#define SUB_FLDNAME   0x20
#define SUB_TYPEDSCR  0x40
#define SUB_CALLDSCR  0x80
#define SUB_SHIFT 4
#if ( HAS_FLDNAME  << SUB_SHIFT ) != SUB_FLDNAME  || \
    (HAS_TYPEDSCR << SUB_SHIFT) != SUB_TYPEDSCR || \
    (HAS_CALLDSCR << SUB_SHIFT) != SUB_CALLDSCR
#error
#endif

#define NORM_FIELD (HAS_CLSNAME | SUB_FLDNAME | SUB_TYPEDSCR)
#define NORM_METOD (HAS_CLSNAME | SUB_FLDNAME | SUB_CALLDSCR)

                ushort ref_ip;      // in xtrn-segment...
                union {
                        uint32 value;         // low part of # value
                        struct {
                                ushort low;   // BegInd Utf8 (name)
                                ushort high;  // index to _Class
                              }value_shorts;  // univication
                      };
                union {
                        uint32 value2;        // hi part of # value
                        struct {
                                ushort low;     //TypeName
                                ushort high;    //Descriptor
                               }addr_shorts;
                      };
               }ConstOpis;

typedef union { // in IDP_JDK12 format was in reverse order!
                struct {
                  ushort  Name;         // index to name
                  ushort  Dscr;         // index to descriptor
                };
                uint32    Ref;          // used in out
              }Object;

typedef struct {
                ushort  name;           // index to name
                ushort  dscr;           // index to descriptor
                ushort  access;         // access flag
// Number not needed for search/out
                ushort  Number;         // Number of current Field or Method
                uchar   extflg;         // for ERROR diagnostic and other flags
#define EFL_NAME    1
#define EFL_TYPE    2
#define EFL_NAMETYPE  (EFL_NAME | EFL_TYPE)
//#define _OLD_EFL_ACCESS  4
#define EFL__MASK (EFL_NAME | EFL_TYPE | 4)  // for check on conversion
// next constant added in JDK15 store-format
// java-2 store format only
#define XFL_DEPRECATED  0x04
#define XFL_UNICODENAME 0x08            // name contain unicode character
#define XFL_M_LABSTART  0x10            // for METHOD set label at entry
#define XFL_C_SUPEROBJ  0x10            // for THIS - parent(.super) == Object
#define XFL_M_LABEND    0x20            // for METHOD set label at exit
#define XFL_C_DEBEXT    0x20            // for THIS - have stored SourceDebugExtension
#define XFL_M_EMPTYSM   0x40            // for METHOD - have empty StackMap
#define XFL_C_ERRLOAD   0x40            // for THIS - have loadtime problems
#define XFL_C_DONE      0x80            // analisys pass complete
// next fields added in JDK15 store-format
                uchar   _UNUSED_ALING;  // = 0
                ushort  utsign;         // index to signature attribute
               }_FMid_;

typedef struct {
                _FMid_  id;             // for search procedure
                uval_t  valNode;        // init value's node
// next fields added in JDK15 store-format
                uval_t  annNodes[2];    // nodes for Vis/Invis annotation
                uval_t  genNode;        // list of stored generic attributes
               }FieldInfo;

typedef struct {
                _FMid_  id;             // for search procedure
                uint32  CodeSize;       // CODE size
                ea_t    startEA;        // EA of Code (checker & slb)
                ea_t    DataBase;       // EA of loc variable segment
                ushort  DataSize;       // max locals (DATA size)
                ushort  stacks;         // stack size
                uval_t  excNode;        // Node for exception table
                uval_t  thrNode;        // Node for throws  (fmt change!)
// next fields added in JDK15 store-format
                uval_t  varNode;        // LocVar descriptors
                uval_t  smNode;         // StackMap descriptors
                // Visible, Invisible, VisibleParam, InvisibleParam, Default
                uval_t  annNodes[5];    // nodes for all types of annotations
                uval_t  genNodes[2];    // list of stored generic attributes + code
               }SegInfo;

typedef struct {
                ushort  maxCPindex;     // max valid index in ConstantPool
                ushort  MinVers;        //-> of file
                Object  This;           // class name/descriptor
                Object  super;          // .super class (parent)
                ushort  AccessFlag;     // access flags
                ushort  FieldCnt;       // Field Declaration Counter
                uval_t  ClassNode;      // Field (>0) & Method (<0) (0?)
                ushort  MethodCnt;      // Method's Segment fot this Class
                ushort  SourceName;     // Index of Utf8 Source File Name
                uval_t  impNode;        // Node for Interfaces (fmt change!)
                ea_t    startEA;        // для SearchFM
                uint32  maxSMsize;      // optimize memory allocation (StackMap)
                                        // ATT: JDK15 - previous errload
                ea_t    xtrnEA;         // beg header segment
                uval_t  xtrnNode;       // node for xtrn Segment
                ushort  xtrnCnt;        // header size
                ushort  xtrnLQE;
// next fields added in JDK15 store-format
                ushort  MajVers;        // -> of file
                uchar   extflg;         // XFL_.... consts
                uchar   JDKsubver;      // for speed/size ONLY
                uval_t  innerNode;      // Node for Inner classes
                ushort  encClass;       // EnclosingMethod class
                ushort  encMethod;      // EnclosingMethod NameAndType
                uval_t  msgNode;        // node for store loading messages
                ushort  utsign;         // signature attribute index
                ushort  maxStrSz;       // optimize memory allocation (string)
                uval_t  annNodes[2];    // nodes for Visible/Invisible
                uint32  maxAnnSz;       // optimize memory allocation (annotation)
                uval_t  genNode;        // list of stored generic attributes
               }ClassInfo;


typedef struct {
                ushort  start_pc;
                ushort  end_pc;
                ushort  handler_pc;
                Object  filter;
               }Exception;

typedef struct{
                ushort  ScopeBeg;       // scope start
                ushort  ScopeTop;       // scope end
                Object  var;            // name & descriptor
                ushort  utsign;         // signature attribute index
              }LocVar;

typedef struct {
                ushort  inner;
                ushort  outer;
                ushort  name;
                ushort  access;
              }InnerClass;


//------------------------------------------------------------------------
extern ClassInfo  curClass;
extern SegInfo    curSeg;
extern FieldInfo  curField;
extern uchar      debugmode;
extern char       loadpass, sm_node;
extern netnode    ClassNode, XtrnNode, ConstantNode;
#define CNS_UNIMAP    -3
#define CNS_SOURCE    -2
#define CNS_CLASS     0
//>0 - opis[i]
//>=0x10000 - string blobs
#define CNA_VERSION   -1
#define CNA_KWRDVER   -2
#define CNA_IDPFLAGS  -3
//>=0x10000 - string info
#define UR_TAG  'r'

//----------------------------------------------------------------------
extern FILE   *myFile;
extern uchar  SMF_mode;
extern uchar  user_limiter;
extern uint32 maxpos, curpos;
extern char   *bufbeg;
extern uint32 bufsize;


//------------------------------------------------------------------------
// !DO NOT CHANGE ORDER!
enum fmt_t {
    fmt_debug = 0,  // as fmt_string, but have prompting
    fmt_string,     // string as text
    fmt_quoted,     // as fmt_string, but in '\'' quotes (for reserbed word/uniname)
    fmt_dscr,       // field descriptor
    fmt_prefsgn,    // function substitution signature
    fmt_retdscr,    // function return descriptor
    fmt_paramstr,   // function parameter descriptor
    fmt_throws,     // function signature throws specification
    fmt_clssign,    // class signature (start width <...:...>)
    fmt_signature,  // signature (==dscr, without space)
    fmt_cast,       // if have '[' desriptor, else fieldname
    fmt_classname,  // extract class from descriptor
    fmt_fullname,   // full qualified name
    fmt_name,       // field name (different only for xtrnSet)
    fmt__ENDENUM
   };
#define FMT_ENC_RESERVED  (uchar)0x80

typedef struct {  // for sm_getinfo
  const uchar *pb;
  const uchar *pe;
  unsigned    fcnt;
  ea_t        ea;
}SMinfo;

typedef size_t (*_PRMPT_)(void);
int         fmtString(ushort index, ssize_t size, fmt_t mode, _PRMPT_ pr=NULL);
uchar       loadDialog(bool manual);
bool        LoadOpis(ushort index, uchar type, ConstOpis *p);
int         CmpString(ushort index1, ushort index2);
void        myBase(const char *arg);
segment_t   *getMySeg(ea_t ea);
void        check_float_const(ea_t ea, void *m, char len);
void        mark_and_comment(ea_t ea, const char *cmt);
int32       print_loader_messages(char str[MAXSTR], const char *cmt);
ea_t        extract_name_ea(char buf[MAXSTR], const char *name, int pos,
                            uchar clv);
int         check_special_label(char buf[MAXSTR], int len);
size_t      make_locvar_cmt(char *buf, size_t bufsize);
bool        fmtName(ushort index, char *buf, size_t bufsize, fmt_t fmt);
bool        is_valid_string_index(ushort index);
void        coagulate_unused_data(const SegInfo *ps);
bool        sm_getinfo(SMinfo *pinf);
const uchar *get_annotation(uval_t node, unsigned *plen);
const TXS   *get_base_typename(uchar tag);
NORETURN extern void  _destroyed(
#ifdef __debug__
                              const char *from
#else
                              void
#endif
                             );
NORETURN extern void  _faterr(uchar mode
#ifdef __debug__
                           , const char *from
#endif
                          );

#ifndef __debug__
#define UNCOMPAT(p)   _faterr(1)
#define INTERNAL(p)   _faterr(0)
#define DESTROYED(p)  _destroyed()
#else
#define UNCOMPAT(p)   _faterr(1, p)
#define INTERNAL(p)   _faterr(0, p)
#define DESTROYED(p)  _destroyed(p)
#endif

char *uniremap_init(char *pnmch);
uchar uni_remap(ushort w);
uchar uni_remap_check(ushort w);
uchar javaIdent(ushort v, uchar *isStart = NULL);

typedef struct {
  unsigned  count;
  ushort    uchars[0x80];
}UNIMAP;
extern UNIMAP unimap;
void rename_uninames(int32 mode);

// information record of StackMap
struct sm_info_t {
  uint32    noff;   // start offset in blob
  uint32    eoff;   // end offset in blob
  unsigned  fcnt;   // locals at entry
};

//------------------------------------------------------------------------
#ifdef __debug__
#define DEB_ASSERT(cond, text)   if ( cond) error(text )
#else
#define DEB_ASSERT(cond, text)
#endif

//------------------------------------------------------------------------
enum j_registers { Rvars=0, Roptop, Rframe, rVcs, rVds };

//------------------------------------------------------------------------
void  idaapi header(void);
void  idaapi footer(void);

void  idaapi segstart(ea_t ea);
void  idaapi segend(ea_t ea);

int   idaapi ana(void);
int   idaapi emu(void);
void  idaapi out(void);
bool  idaapi outop(op_t &op);

void  idaapi java_data(ea_t ea);

void  loader(FILE *fp, bool manualload);
int32 idaapi gen_map_file(FILE *fp);
ea_t  idaapi get_ref_addr(ea_t ea, const char *str, int pos);

int   cmp_opnd(op_t &op1, op_t &op2);
bool  idaapi can_have_type(op_t &op);


//----------------------------------------------------------------------
#define UAS_JASMIN   0x0001     // is jasmin assembler?

inline bool jasmin(void) { return (ash.uflag & UAS_JASMIN) != 0; }

//----------------------------------------------------------------------
inline void out_zero(void)            { *get_output_ptr()  = '\0'; }
inline void reset_output_buffer(void) { init_output_buffer(NULL, 0); }

//------------------------------------------------------------------------
#define MLD_EXTREF    0x01
#define MLD_VARREF    0x02  // if present EXTREF must be present
#define MLD_METHREF   0x04  // if present VARREF must be present

#define MLD_EXTATR    0x08  // store additional attributes to file(s)
#define MLD_LOCVAR    0x10  // Rename local variables
#define MLD_STRIP     0x20  // Semantic error names show
#define MLD_FORCE     0x40  // Ignore 'additional error' on load

#define MLD__DEFAULT  ((MLD_EXTREF|MLD_VARREF) /* | MLD_LOCVAR */)


//------------------------------------------------------------------------
extern uint32 idpflags;
#define IDF_MULTDEB       0x0001    // multiline debug
#define IDF_HIDESM        0x0002    // hide stackmap
#define IDF_AUTOSTR       0x0004    // fmt_string as fmt_debug (next string at \n)
#define IDF_CONVERT       0x0008    // convert (to jasmin) when write asm file
#define IDF_ENCODING      0x0010    // enable unicode-encoding (also see map)
#define IDF_NOPATH        0x0020    // .attribute's filename without path

// not stored (in base) flags
#define IDM_BADIDXSTR 0x00010000    // show invalid indexes as string's

// ... and used loader only
#define IDM_REQUNK    0x20000000    // make request of ;unknown attribute'
#define IDM_WARNUNK   0x40000000    // 'unknown attribute' produced warnings
// ... in module, but temporary
#define IDM_OUTASM    0x80000000    // currently write asm file

#define IDM__REQMASK  ((~(IDM_REQUNK | IDM_WARNUNK | IDM_OUTASM)) >> 16)

// curent modes
#define IDFM__DEFAULT ( (IDF_MULTDEB|IDF_CONVERT|IDF_ENCODING) | IDM_WARNUNK )

//------------------------------------------------------------------------
#pragma pack()
#endif

//------------------------------------------------------------------------

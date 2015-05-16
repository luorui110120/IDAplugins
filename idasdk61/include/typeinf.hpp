/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-2008 Hex-Rays

 *      Type Information.
 *      Designed by Iouri Kharon <yjh@styx.cabel.net>
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _TYPEINF_HPP
#define _TYPEINF_HPP
#include <idp.hpp>
#include <name.hpp>
#pragma pack(push, 1)
//
// This file describes the type information records in IDA
//
// The type information is kept as an array of bytes terminated by 0.
// (we chose this format to be able to use string functions on them)
//
// Numbers used in the type declarations are encoded so that no zero
// bytes will appear in the type string. We use the following encodings:
//
//       nbytes  get function    set function   value range                comment
//
//   db  1       x = *ptr++;     *ptr++ = x;    1-0xFF                     very small nonzeros
//   dt  1..2    get_dt          set_dt         0-0x7FFE                   16bit numbers
//   da  1..9    get_da          set_da         0-0x7FFFFFFF, 0-0xFFFFFFFF arrays
//   de  1..5    get_de          set_de         0-0xFFFFFFFF               enum deltas
//
// p_string: below we use p_string type. p_string is a pascal-like string:
//                   dt length, db characters
// p_list:   one or more p_strings concatenated make a p_list
//
// Items in brackets [] are optional and sometimes are omitted.
// type_t... means a sequence type_t bytes which defines a type.

// NOTE: to work with the types of instructions or data in the database,
// use get/set_ti() and similar functions.
//
// The type string has been designed by Yury Haron <yjh@styx.cabel.net>

typedef uchar type_t;
typedef uchar p_string;   // pascal-like string: dt length, characters
typedef uchar p_list;     // several p_strings
struct til_t;             // type information library
class lexer_t;            // lexical analyzer

//------------------------------------------------------------------------
#define RESERVED_BYTE 0xFF  // multifunctional purpose
//------------------------------------------------------------------------
const type_t TYPE_BASE_MASK  = 0x0F;  // the low 4 bits define the basic type
const type_t TYPE_FLAGS_MASK = 0x30;  // type flags (they have different
                                      // meaning for each basic type)
const type_t TYPE_MODIF_MASK = 0xC0;  // modifiers
                                      // for BT_ARRAY see ATT3 below
                                      // BT_VOID can have them ONLY in 'void *'

const type_t TYPE_FULL_MASK = (TYPE_BASE_MASK | TYPE_FLAGS_MASK);

//----------------------------------------
// BASIC TYPES: unknown & void
const type_t  BT_UNK         = 0x00;    // unknown
const type_t  BT_VOID        = 0x01;    // void
// ATT1: BT_UNK and BT_VOID with non-zero type flags can be used in function
// (and struct) declarations to describe the function arguments or structure
// fields if only their size is known. They may be used in ida to describe
// the user input. For struct used also as 'single-field-alignment-suffix'
// [__declspec(align(x))] with TYPE_MODIF_MASK == TYPE_FULL_MASK.
const type_t    BTMT_SIZE0   = 0x00;    // BT_VOID - normal void; BT_UNK - don't use
const type_t    BTMT_SIZE12  = 0x10;    // size = 1  byte  if BT_VOID; 2 if BT_UNK
const type_t    BTMT_SIZE48  = 0x20;    // size = 4  bytes if BT_VOID; 8 if BT_UNK
const type_t    BTMT_SIZE128 = 0x30;    // size = 16 bytes if BT_VOID; unknown if BT_UNK
                                        // (IN struct alignment - see below)

// convenience definitions of unknown types:
const type_t BT_UNK_BYTE  = (BT_VOID | BTMT_SIZE12);   // 1 byte
const type_t BT_UNK_WORD  = (BT_UNK  | BTMT_SIZE12);   // 2 bytes
const type_t BT_UNK_DWORD = (BT_VOID | BTMT_SIZE48);   // 4 bytes
const type_t BT_UNK_QWORD = (BT_UNK  | BTMT_SIZE48);   // 8 bytes
const type_t BT_UNK_OWORD = (BT_VOID | BTMT_SIZE128);  // 16 bytes
const type_t BT_UNKNOWN   = (BT_UNK  | BTMT_SIZE128);  // unknown size - for parameters

const type_t BTF_VOID = (BT_VOID | BTMT_SIZE0);

//----------------------------------------
// BASIC TYPES: integers
const type_t  BT_INT8        = 0x02;    // __int8
const type_t  BT_INT16       = 0x03;    // __int16
const type_t  BT_INT32       = 0x04;    // __int32
const type_t  BT_INT64       = 0x05;    // __int64
const type_t  BT_INT128      = 0x06;    // __int128 (for alpha & future use)
const type_t  BT_INT         = 0x07;    // natural int. (size provided by idp module)
const type_t    BTMT_UNKSIGN = 0x00;    // unknown signness
const type_t    BTMT_SIGNED  = 0x10;    // signed
const type_t    BTMT_USIGNED = 0x20;    // unsigned
const type_t    BTMT_CHAR    = 0x30;    // BT_INT8:          char
                                        // BT_INT:           segment register
                                        // others BT_INT(x): don't use

// convenience definition:
const type_t BT_SEGREG    = (BT_INT | BTMT_CHAR);      // segment register

//----------------------------------------
// BASIC TYPE: bool
const type_t  BT_BOOL        = 0x08;    // bool
const type_t    BTMT_DEFBOOL = 0x00;    // size is model specific or unknown(?)
const type_t    BTMT_BOOL1   = 0x10;    // size 1byte
const type_t    BTMT_BOOL2   = 0x20;    // size 2bytes
const type_t    BTMT_BOOL4   = 0x30;    // size 4bytes

//----------------------------------------
// BASIC TYPE: float
const type_t  BT_FLOAT       = 0x09;    // float
const type_t    BTMT_FLOAT   = 0x00;    // float (4 bytes)
const type_t    BTMT_DOUBLE  = 0x10;    // double (8 bytes)
const type_t    BTMT_LNGDBL  = 0x20;    // long double (compiler specific)
const type_t    BTMT_SPECFLT = 0x30;    // if ph.use_tbyte() : ph.tbyte_size bytes
                                        // otherwise 2 bytes


const type_t _BT_LAST_BASIC  = BT_FLOAT; // the last basic type

//----------------------------------------
// DERIVED TYPE: pointer
const type_t  BT_PTR         = 0x0A;    // *
                                        // has the following format:
                                        // [db sizeof(ptr)]; type_t...
// ATT2: pointers to undeclared yet BT_COMPLEX types are prohibited.
const type_t    BTMT_DEFPTR  = 0x00;    // default for model
const type_t    BTMT_NEAR    = 0x10;    // near
const type_t    BTMT_FAR     = 0x20;    // far
const type_t    BTMT_CLOSURE = 0x30;    // if ptr to BT_FUNC - __closure
                                        // in this case next byte MUST be
                                        // RESERVED_BYTE, and after it - BT_FUNC
                                        // else the next byte contains sizeof(ptr)
                                        // allowed values are 1-ph.max_ptr_size.
                                        // if value is bigger than ph.max_ptr_size,
                                        // based_ptr_name_and_size() is called
                                        // (see below) to find out the typeinfo

//----------------------------------------
// DERIVED TYPE: array
const type_t  BT_ARRAY       = 0x0B;    // []
// ATT3: for BT_ARRAY the BTMT_... flags must be equivalent to BTMT_... of elements
const type_t    BTMT_NONBASED= 0x10;    // if set
                                        //    array base==0
                                        //    format: dt num_elem; type_t...
                                        //    if num_elem==0 then the array size is unknown
                                        // else
                                        //    format: da num_elem, base; type_t...
const type_t    BTMT_ARRESERV= 0x20;    // reserved bit


//----------------------------------------
// DERIVED TYPE: function
const type_t  BT_FUNC        = 0x0C;    // ()
                                        // format:
        //  optional: CM_CC_SPOILED | num_of_spoiled_regs
        //            num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
        //  cm_t... calling convention and memory model
        //  type_t... return type;
        //  [argloc_t of returned value (if CM_CC_SPECIAL{PE} && !return void);
        //  if !CM_CC_VOIDARG:
        //    dt N (N=number of parameters)
        //    if ( N == 0 )
        //      if CM_CC_ELLIPSIS or CM_CC_SPECIALE
        //        func(...)
        //      else
        //        parameters are unknown
        //    else
        //      N records:
        //        type_t... (i.e. type of each parameter)
        //        [argloc_t (if CM_CC_SPECIAL{PE})] (i.e. place of each parameter)

// Ellipsis is not taken into account in the number of parameters
// ATT4: the return type can not be BT_ARRAY or BT_FUNC

const type_t    BTMT_DEFCALL  = 0x00;   // call method - default for model or unknown
const type_t    BTMT_NEARCALL = 0x10;   // function returns by retn
const type_t    BTMT_FARCALL  = 0x20;   // function returns by retf
const type_t    BTMT_INTCALL  = 0x30;   // function returns by iret
                                        // in this case cc MUST be 'unknown'

//----------------------------------------
// DERIVED TYPE: complex types
const type_t  BT_COMPLEX     = 0x0D;    // struct/union/enum/typedef
                                        // format:
                                        //   [dt N (N=field count) if !BTMT_TYPEDEF]
                                        //   if N == 0:
                                        //     p_string name (unnamed types have names "anon_...")
                                        //   else
const type_t    BTMT_STRUCT  = 0x00;    //     struct:
                                        //       (N >> 3) records: type_t...
const type_t    BTMT_UNION   = 0x10;    //     union:
                                        //       (N >> 3) records: type_t...
                                        // for STRUCT & UNION (N & 7) - alignment
                                        // if ( !(N & 7)) get_default_align( )
                                        // else         (1 << ((N & 7) - 1))
                                        // ATTENTION: if ( N>>3 ) == 0 - error
                                        // NOTE: for struct any type may be
                                        //       postfixed with sdacl-byte
const type_t    BTMT_ENUM    = 0x20;    //     enum:
                                        //       next byte bte_t (see below)
                                        //       N records: de delta(s)
                                        //                  OR
                                        //                  blocks (see below)
const type_t    BTMT_TYPEDEF = 0x30;    // named reference
                                        //   always p_string name

const type_t BT_BITFIELD     = 0x0E;    //bitfield (only in struct)
                                        //['bitmasked' enum see below]
                                        // next byte is dt
                                        //  ((size in bits << 1) | (unsigned ? 1 : 0))
const type_t BTMT_BFLDI8    = 0x00;     // __int8
const type_t BTMT_BFLDI16   = 0x10;     // __int16
const type_t BTMT_BFLDI32   = 0x20;     // __int32
const type_t BTMT_BFLDI64   = 0x30;     // __int64


const type_t BT_RESERVED     = 0x0F;        //RESERVED


const type_t BTF_STRUCT  = (BT_COMPLEX | BTMT_STRUCT);
const type_t BTF_UNION   = (BT_COMPLEX | BTMT_UNION);
const type_t BTF_ENUM    = (BT_COMPLEX | BTMT_ENUM);
const type_t BTF_TYPEDEF = (BT_COMPLEX | BTMT_TYPEDEF);
//------------------------------------------------------------------------
// TYPE MODIFIERS:

const type_t  BTM_CONST      = 0x40;    // const
const type_t  BTM_VOLATILE   = 0x80;    // volatile

//------------------------------------------------------------------------
// special enum definitions
typedef uchar bte_t;

const bte_t   BTE_SIZE_MASK = 0x07;   // storage size
                                        // if == 0 get_default_enum_size()
                                        // else 1 << (n -1) = 1,2,4...64
const bte_t   BTE_RESERVED    = 0x08; // reserved for future use
const bte_t   BTE_BITFIELD    = 0x10; // 'subarrays'. In this case ANY record
                                      // has the following format:
                                      //   'de' mask (has name)
                                      //   'dt' cnt
                                      //   cnt records of 'de' values
                                      //      (cnt CAN be 0)
                                      // ATT: delta for ALL subsegment is ONE
const bte_t   BTE_OUT_MASK  = 0x60;   // ouput style mask
const bte_t   BTE_HEX         = 0x00; // hex
const bte_t   BTE_CHAR        = 0x20; // char or hex
const bte_t   BTE_SDEC        = 0x40; // signed decimal
const bte_t   BTE_UDEC        = 0x60; // unsigned decimal
const bte_t   BTE_ALWAYS    = 0x80;   // this bit MUST be present

//------------------------------------------------------------------------
// convenience functions:

inline bool is_type_const(type_t t)   { return (t & BTM_CONST) != 0; }
inline bool is_type_volatile(type_t t){ return (t & BTM_VOLATILE) != 0; }

inline type_t get_base_type(type_t t) { return (t & TYPE_BASE_MASK); }
inline type_t get_type_flags(type_t t){ return (t & TYPE_FLAGS_MASK); }
inline type_t get_full_type(type_t t) { return (t & TYPE_FULL_MASK); }

// is the type_t the last byte of type declaration?
// (there are no additional bytes after a basic type)
inline bool is_typeid_last(type_t t)  { return(get_base_type(t) <= _BT_LAST_BASIC); }

inline bool is_type_partial(type_t t) { return(get_base_type(t) <= BT_VOID) && get_type_flags(t) != 0; }
inline bool is_type_void(type_t t)    { return(get_full_type(t) == BTF_VOID); }
inline bool is_type_unknown(type_t t) { return(get_full_type(t) == BT_UNKNOWN); }

inline bool is_type_ptr(type_t t)     { return(get_base_type(t) == BT_PTR); }
inline bool is_type_complex(type_t t) { return(get_base_type(t) == BT_COMPLEX); }
inline bool is_type_func(type_t t)    { return(get_base_type(t) == BT_FUNC); }
inline bool is_type_array(type_t t)   { return(get_base_type(t) == BT_ARRAY); }

inline bool is_type_typedef(type_t t) { return(get_full_type(t) == BTF_TYPEDEF); }
// struct/union/enum
inline bool is_type_sue(type_t t)     { return is_type_complex(t) && !is_type_typedef(t); }
inline bool is_type_struct(type_t t)  { return(get_full_type(t) == BTF_STRUCT); }
inline bool is_type_union(type_t t)   { return(get_full_type(t) == BTF_UNION); }
inline bool is_type_struni(type_t t)  { return(is_type_struct(t) || is_type_union(t)); }
inline bool is_type_enum(type_t t)    { return(get_full_type(t) == BTF_ENUM); }

inline bool is_type_bitfld(type_t t)  { return(get_base_type(t) == BT_BITFIELD); }

inline bool is_type_int64(const type_t t)
{
  return get_full_type(t) == (BT_INT64|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT64|BTMT_SIGNED);
}

inline bool is_type_long(const type_t t)
{
  return get_full_type(t) == (BT_INT32|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT32|BTMT_SIGNED);
}

inline bool is_type_short(const type_t t)
{
  return get_full_type(t) == (BT_INT16|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT16|BTMT_SIGNED);
}

inline bool is_type_char(const type_t t) // chars are signed by default(?)
{
  return get_full_type(t) == (BT_INT8|BTMT_CHAR)
      || get_full_type(t) == (BT_INT8|BTMT_SIGNED);
}

inline bool is_type_uint(const type_t t)   { return get_full_type(t) == (BT_INT|BTMT_USIGNED); }
inline bool is_type_uchar(const type_t t)  { return get_full_type(t) == (BT_INT8|BTMT_USIGNED); }
inline bool is_type_ushort(const type_t t) { return get_full_type(t) == (BT_INT16|BTMT_USIGNED); }
inline bool is_type_ulong(const type_t t)  { return get_full_type(t) == (BT_INT32|BTMT_USIGNED); }
inline bool is_type_uint64(const type_t t) { return get_full_type(t) == (BT_INT64|BTMT_USIGNED); }
inline bool is_type_ldouble(const type_t t){ return get_full_type(t) == (BT_FLOAT|BTMT_LNGDBL); }
inline bool is_type_double(const type_t t) { return get_full_type(t) == (BT_FLOAT|BTMT_DOUBLE); }
inline bool is_type_float(const type_t t)  { return get_full_type(t) == (BT_FLOAT|BTMT_FLOAT); }
inline bool is_type_floating(const type_t t){return get_base_type(t) == BT_FLOAT; }
inline bool is_type_bool(const type_t t)   { return get_base_type(t) == BT_BOOL; }

// function used ONLY within structures for sdacl-suffix: __declspec(align(x))
// if FIRST type byte is sdacl - ALL structure have sdacl-extension
inline bool is_type_sdacl(type_t t)
    { return(((t & ~TYPE_FLAGS_MASK) ^ TYPE_MODIF_MASK) <= BT_VOID); }
inline int sdacl_unpack(type_t t)
    { return(((t & TYPE_FLAGS_MASK) >> 3) | (t & 1)); }
inline int sdacl_pack(int algn)  // param<=MAX_SDACL_VALUE (MUST be checked before call)
    { return((((algn & 6) << 3) | (algn & 1)) | TYPE_MODIF_MASK); }
#define MAX_DECL_ALIGN   7

//---------------------------------------------------------------------------
// store argloc_t for CM_CC_SPECIAL{P}
idaman type_t *ida_export set_argloc(type_t *pt, int reg, int reghi=-1, bool ret=false);

// store spoil list for __spoil<> functions
// regs[n] must be in interval 0-127, and lens[n] 1-255.
// if the spoil information is present, it overrides the standard spoiled registers
idaman type_t *ida_export set_spoils(type_t *pt, uint reg, uint size);

inline unsigned get_spoil_cnt(type_t t) { return (unsigned)t & 0xF; }

//-------------------------
// FUNCTIONS TO WORK WITH NUMBERS
//
// store 1-2 byte number. (0-32766)
idaman type_t *ida_export set_dt(type_t *pt, int value);

#define MAX_DT  0x7FFE


// store 2 long values (9 bytes) num_el=0-0x7FFFFFFF, base=0-0xFFFFFFFF
idaman type_t *ida_export set_da(type_t *pt, uint32 num_el, uint32 base = 0);


// store 1-5 byte number - for enum.
// usage:
//         pt = set_de(buff, val[0]);
//         for(int i = 1; i < valcnt; i++)
//                     pt = set_de(pt, val[i]-val[i-1]);
idaman type_t *ida_export set_de(type_t *pt, uint32 val);


// functions to retrieve numbers:
idaman int  ida_export get_dt(const type_t * &pt);                             // returns < 0 - error
idaman bool ida_export get_da(const type_t * &pt, uint32 *num_el, uint32 *base); // returns false - error
idaman bool ida_export get_de(const type_t * &pt, uint32 *val);                 // returns false - error


// convenience functions to form type string
idaman bool ida_export append_dt(qtype *type, int n);
idaman bool ida_export append_de(qtype *type, uint32 n);
idaman bool ida_export append_da(qtype *type, uint32 n1, uint32 n2);
idaman bool ida_export append_name(qtype *fields, const char *name);

//------------------------------------------------------------------------
inline const type_t *skip_ptr_type_header(const type_t *type)
{
  if ( get_type_flags(*type++) == BTMT_CLOSURE
    && *type++ == RESERVED_BYTE ) // skip reserved byte (or possibly sizeof(ptr))
  {
    type++;                       // skip BT_FUNC. todo: check that this byte is BT_FUNC
  }
  return type;
}

inline const type_t *skip_array_type_header(const type_t *type)
{
  if ( get_type_flags(*type++) & BTMT_NONBASED )
  {
    int n = get_dt(type);
    if ( n < 0 )
      type = NULL;
  }
  else
  {
    uint32 num, base;
    if ( !get_da(type, &num, &base) )
      type = NULL;
  }
  return type;
}

#define DEFINE_NONCONST_SKIPPER(typename)                                       \
inline type_t *skip_ ## typename ## _type_header(type_t *type)                  \
  { return CONST_CAST(type_t *)(skip_ ## typename ## _type_header((const type_t *)type)); }

DEFINE_NONCONST_SKIPPER(ptr)
DEFINE_NONCONST_SKIPPER(array)

inline type_t *typend(const type_t *ptr)  { return (type_t *)strchr((char *)ptr, '\0'); }
inline size_t typlen(const type_t *ptr)  { return strlen((const char *)ptr); }
inline type_t *typncpy(type_t *dst, const type_t *src, size_t size)
        { return (type_t *)::qstrncpy((char *)dst, (const char *)src, size); }
inline type_t *tppncpy(type_t *dst, const type_t *src, size_t size)
        { return (type_t *)::qstpncpy((char *)dst, (const char *)src, size); }
inline int     typcmp(const type_t *dst, const type_t *src)
        { return strcmp((const char *)dst, (const char *)src); }
inline int     typncmp(const type_t *dst, const type_t *src, size_t size)
        { return strncmp((const char *)dst, (const char *)src, size); }
inline type_t *typdup(const type_t *src)
        { return (type_t *)::qstrdup((const char *)src); }

// compare two types for equality (take into account typedefs)
// returns true - types are equal
// if COMP_UNSURE is set then do not use the current memory model and calling
// convention during the comparison.
// For example, BT_PTR|BTMT_DEFPTR won't match BT_PTR_|BTMT_NEAR even
// if the current model is 'small'.
idaman bool ida_export equal_types(const til_t *ti, const type_t *t1, const type_t *t2);

// resolve typedef recursively if is_type_resolvable(p)
// fields will contains the field list if the type is resolved
// namebuf will contain the last type name if resolved.
// empty name means that the type does not need to be resolved
// namebuf must be at least MAXNAMELEN bytes if specified
idaman const type_t *ida_export resolve_typedef2(
        const til_t *ti,
        const type_t *p,
        const p_list **fields=NULL,
        char *namebuf=NULL);

// is the type resolvable? (typedef or name reference)
// namebuf will contain the name of the reference type (if not NULL)
// namebuf must be at least MAXNAMELEN bytes if specified
idaman bool ida_export is_type_resolvable(const type_t *p, char *namebuf=NULL);

idaman bool ida_export is_restype_const  (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_void   (const til_t *til, const type_t *type); // really void?
idaman bool ida_export is_restype_ptr    (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_func   (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_array  (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_complex(const til_t *til, const type_t *type);
idaman bool ida_export is_restype_struct (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_union  (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_struni (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_enum   (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_bitfld (const til_t *til, const type_t *type);

idaman bool ida_export is_castable2(const til_t *til, const type_t *from, const type_t *to);

idaman bool ida_export remove_constness(type_t *type); // remove const and const* modifiers

// Remove pointer of a type, i.e. convert "char *" into "char"
// Optionally remove the "lp" (or similar) prefix of the input name
// If the input type is not a pointer, then fail.
idaman bool ida_export remove_type_pointer(
        const til_t *til,
        const type_t **ptype,
        const char **pname);

idaman bool ida_export build_array_type(
        qtype *outtype,
        const type_t *type,
        int size);

idaman type_t ida_export get_int_type_bit(int size); // size should be 1,2,4,8,16
idaman type_t ida_export get_unk_type_bit(int size); // size should be 1,2,4,8,16

//------------------------------------------------------------------------
// type names (they can be replaced by ida)
struct type_names_t
{
  const char
        *type_void,       // "void",
// int types
        *type_int8,       // "__int8",
        *type_int16,      // "__int16",
        *type_int32,      // "__int32",
        *type_int64,      // "__int64",
        *type_int128,     // "__int128",
// char if special flag set
        *type_char,       // "char",
// natural int
        *type_int,        // "int",
// any bool type
        *type_bool,       // "bool",
// float types
        *type_float,      // "float",
        *type_double,     // "double",
        *type_longdouble, // "long double",
        *type_shortfloat, // "short float",
// segment register
        *type_seg,        // "__seg",
// unknown input
        *type_unknown,    // "_UNKNOWN"
// unknown types (only size is known)
        *type_byte,       // "_BYTE"   1byte
        *type_word,       // "_WORD"   2byte
        *type_dword,      // "_DWORD"  4byte
        *type_qword,      // "_QWORD"  8byte
        *type_oword,      // "_OWORD" 16byte
        *type_tbyte,      // "_TBYTE" 10byte
// prefixes (ATT5: see spaces!)
        *type_signed,     // "signed ",
        *type_unsigned,   // "unsigned ",
// model declarator for function prototypes
        *cc_cdecl,        // "__cdecl"
        *cc_stdcall,      // "__stdcall"
        *cc_pascal,       // "__pascal"
        *cc_fastcall,     // "__fastcall"
        *cc_thiscall,     // "__thiscall"
        *cc_manual,       // "" - compiler specific: __syscall/__fortran/vxdcall/...
// used for CM_CC_SPECIAL{PE}
        *cc_specialp,     // "__userpurge"
        *cc_special;      // "__usercall"
};
extern type_names_t  type_names;

//------------------------------------------------------------------------
// Type Information Library
//------------------------------------------------------------------------

struct til_t
{
  char *name;           // short file name (without path and extension)
  char *desc;           // human readable til description
  int nbases;           // number of base tils
  struct til_t **base;  // tils that our til is based on
  uint32 flags;
#define TIL_ZIP 0x0001  // pack buckets using zip
#define TIL_MAC 0x0002  // til has macro table
#define TIL_ESI 0x0004  // extended sizeof info (short, long, longlong)
#define TIL_UNI 0x0008  // universal til for any compiler
#define TIL_ORD 0x0010  // type ordinal numbers are present
#define TIL_ALI 0x0020  // type aliases are present (this bit is used only on the disk)
#define TIL_MOD 0x0040  // til has been modified, should be saved
#define TIL_STM 0x0080  // til has extra streams
  inline bool is_dirty(void) const { return (flags & TIL_MOD) != 0; }
  inline void set_dirty(void) { flags |= TIL_MOD; }
  compiler_info_t cc;
  struct til_bucket_t *syms;
  struct til_bucket_t *types;
  struct til_bucket_t *macros;
  int nrefs;            // number of references to the til
  int nstreams;         // number of extra streams
  struct til_stream_t **streams;
  til_t(void) { memset(this, 0, sizeof(*this)); }
};


//-------------------------------------------------------------------------
// Symbol from a specific type library
//------------------------------------------------------------------------

struct til_symbol_t
{
  const char *name;         // symbol name
  const til_t *til;         // pointer to til
  til_symbol_t(const char *n = NULL, const til_t *t = NULL): name(n), til(t) {};
};
DECLARE_TYPE_AS_MOVABLE(til_symbol_t);


// Initialize a til
idaman til_t *ida_export new_til(const char *name, const char *desc);

// Add a base til
// bases - comma separated list of til names
// returns: !=0-ok, otherwise the error message is in errbuf
int add_base_tils(til_t *ti, const char *tildir, const char *bases, char *errbuf, size_t bufsize);

#define TIL_ADD_FAILED  0
#define TIL_ADD_OK      1       // some tils were added
#define TIL_ADD_ALREADY 2       // the base til was already added


// Load til from a file
// tildir: directory where to load the til from. NULL means current directory.
// name: filename of the til. If it's an absolute path, tildir is ignored.
// NB: the file extension is forced to .til
// returns: !NULL-ok, otherwise the error message is in errbuf
idaman til_t *ida_export load_til(const char *tildir, const char *name, char *errbuf, size_t bufsize);

// Sort til (use after modifying it)
// returns false - no memory or bad parameter
idaman bool ida_export sort_til(til_t *ti);

// Collect garbage in til. Must be called before storing the til
// Returns true is freed some memory
idaman bool ida_export compact_til(til_t *ti);

// Store til to a file
// If the til contains garbage, it will be collected before storing the til.
// Your plugin should call compact_til() before calling store_til()
// tildir: directory where to store the til. NULL means current directory.
// name: filename of the til. If it's an absolute path, tildir is ignored.
// NB: the file extension is forced to .til
idaman bool ida_export store_til(til_t *ti, const char *tildir, const char *name);

// Free memory allocated by til
idaman void ida_export free_til(til_t *ti);

// Get human-readable til description
idaman til_t *ida_export load_til_header(const char *tildir, const char *name, char *errbuf, size_t bufsize);


// The following 2 functions are for special use only
void til_add_macro(til_t *ti, const char *name, const char *body, int nargs, bool isfunc);
bool til_next_macro(const til_t *ti, const char **current, const char **body, int *nargs, bool *isfunc);

//------------------------------------------------------------------------
// FUNCTIONS TO WORK WITH TYPE STRINGS


// FUNCTION: Get the type size
//      til - pointer to type information library.
//            if NULL, then the current IDA database is used
//      ptr - pointer to type string
//      lp  - pointer to variable which will get the natural alignment
//            for the type
// if this function returns BADSIZE
//   value of ptr is unknown but it is guaranteed
//   that ptr points somewhere within the string
//   (including the final zero byte)
// else
//   ptr points after the full description of the type.

idaman size_t ida_export get_type_size(const til_t *ti, const type_t * &ptr, size_t *lp = NULL);
// return: 0 - unknown, BADSIZE error
// this variant of the function doesn't move the pointer:
inline size_t get_type_size0(const til_t *ti, const type_t *ptr, size_t *lp = NULL)
{
  return get_type_size(ti, ptr, lp);
}


// function skip current subtype. Returns NULL if the type string is bad
// if this function returns NULL
//   value of ptr is unknown but it is guaranteed
//   that ptr points somewhere within the string
//   (including the final zero byte)
// else
//   ptr points after the descriptor of the type

idaman const type_t *ida_export skip_type(const til_t *ti, const type_t *&ptr);

inline bool check_skip_type(const til_t *ti, const type_t *&ptr)
{
  return skip_type(ti, ptr) != NULL;
}

inline bool is_valid_full_type(const til_t *ti, const type_t *&ptr)
{
  return skip_type(ti, ptr) != NULL && *ptr == '\0';
}

// get size of the object pointed by a pointer or an array element size
// the type should be a pointer or an array
// if error, return BADSIZE

idaman ssize_t ida_export get_ptr_object_size(const til_t *til, const type_t *type);


// get number of bytes occupied by a function argument
// this function knows that arrays are converted to pointers
// if error, return BADSIZE

idaman size_t ida_export get_funcarg_size(const til_t *til, const type_t *&type, size_t *lp=NULL);


const size_t BADSIZE = size_t(-1);


//------------------------------------------------------------------------
// FUNCTION: Unpack type string
// This function generates C/C++ representation of the type string
//      til     - pointer to type information library.
//                if NULL, then the current IDA database is used
//      pt      - pointer to type string
//      cb_func - callback to call for each field/argument.
//                it will be also called once for function/complex type
//      cd_data - data to pass to cb_func
//      name    - name of variable of this type
//      cmt     - a comment for the whole type
//      field_names - field/argument names (used for functions are complex types)
//      field_cmts  - field/argument comments (used for functions are complex types)
//
//             names/comments is fully 'synchronized' when it (or one for him)
//             length is 1 (asciz "") - skipped.
//
// The function will return one of the following codes:
#define T_CBBRKDEF  3   // !cb_func return from 'redefine' call
#define T_NONALL    2   // type string doesn't have a final zero byte.
#define T_CBBRK     1   // !cb_func return
#define T_NORMAL    0   // GOOD
#define T_BADDESCR  -1  // bad type string
#define T_SHORTSTR  -2  // buffer too small, or strlen(answer) > MAXSTR
#define T_BADNAMES  -3  // bad fldNames
#define T_BADCMTS   -4  // bad fldCmts
#define T_PARAMERR  -5  // parameter error
#define T_ALREADY   -6  // type already exists
#define T_NOTYPE    -7  // no such type
#define T_UNIMPL    -8  // currently not implemented or bad type string
#define T_INTERNAL  -9  // internal error (need feedback!)

struct descr_t
{
  const   p_list *Names; // names for field/param
  const   p_list *Cmts;  // comment for field/param
};

// callback: if returns false - stop unpack_type()
typedef bool (idaapi*tcbfn)(
        void *cb_data,                   // data from the caller
        int level,                       // structure inclusion level
        const char *str,                 // C representation of type
        const char *cmt);                // possible comment
   // INTERNAL:
   //           if function called for names [re]difiniton
   //           str   = NULL (for normall call this is not allowed)
   //           cmt   = (const char *)Descr (see below)
   //           level = offset in type_t for current element of type_t
   // ATTENTION:
   //           after *Descr->Names = '\0', Descr->Names set to NULL
   //           after *Descr->Cmts  = '\0', Descr->Cmts set to NULL
   //                    can be used for checks

idaman int ida_export unpack_type(
        const til_t *ti,                  // type information library
        const type_t *pt,                 // type descriptor string
        tcbfn cb_func,                    // callback
        void  *cb_data,                   // data for callback
        const char *name = NULL,          // var/func name
        const char *cmt = NULL,           // main comment
        const descr_t *Descr = NULL,      // field/args names & comments
        unsigned int flags=0);            // combination of UNPFL_....
#define UNPFL_REDEFINE    0x00000001      // must call cb_func for
                                          // name definitions too
#define UNPFL_NOPRALGN    0x00000010      // do not print #pragma pack
                                          // before/after structures
#define UNPFL_PARSPACE    0x00000020      // print space after comma
                                          // in function prototypes
#define UNPFL_TYPENAME    0x00000040      // name is type name, not variable name
#define UNPFL_SEMI        0x00000080      // append ; at the end

// print type to one line
// if buf == NULL and bufsize == 0, return the size of the required buffer
//                                         negative numbers denote error codes
// if buf != NULL return an error code (T_...)

idaman int ida_export print_type_to_one_line(     // make one-line description
        char  *buf,                       // output buffer
        size_t bufsize,                   // size of the output buffer
        const til_t *ti,                  // type information library
        const type_t *pt,                 // type descriptor string
        const char *name = NULL,          // var/func name
        const char *cmt = NULL,           // main comment
        const p_list *field_names = NULL, // field names
        const p_list *field_cmts = NULL); // field comments


idaman int ida_export print_type_to_many_lines(   // make manyline description
        bool (idaapi*printer)(void *cbdata, const char *buf),
        void *cbdata,                     // callback data
        const char *prefix,               // prefix of each line
        int indent,                       // structure level indent
        int cmtindent,                    // comment indents
        const til_t *ti,                  // type information library
        const type_t *pt,                 // type descriptor string
        const char *name = NULL,          // var/func name
        const char *cmt = NULL,           // main comment
        const p_list *field_names = NULL, // field names
        const p_list *field_cmts = NULL); // field comments

// the most generic function to print types
idaman ssize_t ida_export print_type_to_qstring(  // returns -1 if error
        qstring *result,                  // or the result size
        const char *prefix,
        int indent,
        int cmtindent,
        int flags,
        const til_t *ti,
        const type_t *pt,
        const char *name=NULL,
        const char *cmt=NULL,
        const p_list *field_names=NULL,
        const p_list *field_cmts=NULL);
// flags is a bitwise combination of the following symbols:
#define PRTYPE_1LINE  0x0000              // print to one line
#define PRTYPE_MULTI  0x0001              // print to many lines
#define PRTYPE_TYPE   0x0002              // print type declaration (not variable declaration)
#define PRTYPE_PRAGMA 0x0004              // print pragmas for alignment
#define PRTYPE_SEMI   0x0008              // append ; to the end

// Get type declaration for the specified address
idaman bool ida_export print_type(ea_t ea, char *buf, size_t bufsize, bool one_line);

// display the type string in its internal form:
void show_type(int (*print_cb)(const char *format, ...),
               const type_t *ptr);
void show_plist(int (*print_cb)(const char *format, ...),
                const char *header,
                const p_list *list);

const p_list *skip_function_arg_names(const til_t *til, const type_t *type, const p_list *fields);
bool perform_funcarg_conversion(const til_t *til, qtype &type);
bool get_argloc_info(
        const til_t *til,
        const type_t *func,
        const type_t *type,
        cm_t cc,
        uint32 *arglocs,
        size_t n);

//=========================================================================
// some examples:
//
// __int8  (*func(void))(__int16 (*)(char*), ...);
//    BT_FUNC | BTMT_DEFCALL, CM_UNKNOWN | CM_M_NN | CM_CC_UNKNOWN,
//      BT_PTR | BTMT_DEFPTR,
//      BT_FUNC | BTMT_DEFCALL, CM_UNKNOWN | CM_M_NN | CM_CC_ELLIPSIS,
//        BT_INT8 | BTMT_UNKSIGN,
//        2,
//        BT_PTR | BTMT_DEFPTR,
//        BT_FUNC | BTMT_DEFCALL, CM_UNKNOWN | CM_M_NN | CM_CC_UNKNOWN,
//          BT_INT16 | BTMT_UNKSIGN,
//          2,
//          BT_PTR | BTMT_DEFPTR,
//          BT_INT8 | BTMT_CHAR,
//      2,
//      BT_VOID,
//    0 // eof

//
//--------------
// __int8 (*funcS[1][2])(__int8(*)[1][2] ,...);
//    BT_FUNC | BTMT_DEFFUNC, CM_UNKNOWN | CM_M_NN | CM_CC_ELLIPSIS,
//      BT_PTR | BTMT_DEFPTR,
//        BT_ARRAY | BTMT_NONBASED,
//          2,
//        BT_ARRAY | BTMT_NONBASED,
//          3,
//        BT_INT8,
//      2,
//        BT_PTR | BTMT_DEFPTR,
//          BT_ARRAY | BTMT_NONBASED,
//            2,
//          BT_ARRAY | BTMT_NONBASED,
//            3,
//          BT_INT8,
//  0 // eof
//------------------------------------------------------------------------
// CM (calling convention & model)

// default pointer size
const cm_t CM_MASK = 0x03;
const cm_t  CM_UNKNOWN   = 0x00;
const cm_t  CM_N8_F16    = 0x01;  // 1: near 1byte,  far 2bytes
const cm_t  CM_N64       = 0x01;  // if sizeof(int)>2 then ptr size is 8bytes
const cm_t  CM_N16_F32   = 0x02;  // 2: near 2bytes, far 4bytes
const cm_t  CM_N32_F48   = 0x03;  // 4: near 4bytes, far 6bytes
// model
const cm_t CM_M_MASK = 0x0C;
const cm_t  CM_M_NN      = 0x00;  // small:   code=near, data=near (or unknown if CM_UNKNOWN)
const cm_t  CM_M_FF      = 0x04;  // large:   code=far, data=far
const cm_t  CM_M_NF      = 0x08;  // compact: code=near, data=far
const cm_t  CM_M_FN      = 0x0C;  // medium:  code=far, data=near

inline bool is_code_far(cm_t cm) { return((cm & 4) != 0); }
inline bool is_data_far(cm_t cm) { return((cm &= CM_M_MASK) && cm != CM_M_FN); }

// calling convention
const cm_t CM_CC_MASK = 0xF0;
const cm_t  CM_CC_INVALID  = 0x00;  // this value is invalid
const cm_t  CM_CC_UNKNOWN  = 0x10;  // unknown calling convention
const cm_t  CM_CC_VOIDARG  = 0x20;  // function without arguments
                                    // ATT7: if has other cc and argnum == 0,
                                    // represent as f() - unknown list
const cm_t  CM_CC_CDECL    = 0x30;  // stack
const cm_t  CM_CC_ELLIPSIS = 0x40;  // cdecl + ellipsis
const cm_t  CM_CC_STDCALL  = 0x50;  // stack, purged
const cm_t  CM_CC_PASCAL   = 0x60;  // stack, purged, reverse order of args
const cm_t  CM_CC_FASTCALL = 0x70;  // stack, purged (x86), first args are in regs (compiler-dependent)
const cm_t  CM_CC_THISCALL = 0x80;  // stack, purged (x86), first arg is in reg (compiler-dependent)
const cm_t  CM_CC_MANUAL   = 0x90;  // special case for compiler specific
const cm_t  CM_CC_SPOILED  = 0xA0;  // This is NOT a cc! Mark of __spoil record
                                    // low tetrade is count and after n {spoilreg_t}
                                    // present real cm_t byte
const cm_t  CM_CC_RESERVE4 = 0xB0;
const cm_t  CM_CC_RESERVE3 = 0xC0;
const cm_t  CM_CC_SPECIALE = 0xD0;  // CM_CC_SPECIAL with ellipsis
const cm_t  CM_CC_SPECIALP = 0xE0;  // Equal to CM_CC_SPECIAL, but with purged stack
const cm_t  CM_CC_SPECIAL  = 0xF0;  // locations of all arguments and the return
                                    // value are present in the function declaration.
                                    // The locations are represented by argloc_t:
                                    // in the type string, it occupies 1 or 2 bytes
                                    // if byte1 == 0x80:
                                    //   the argument is on the stack
                                    // else
                                    //   in register number (byte1 - 1)
                                    //   if the argument occupies 2 registers:
                                    //     byte1 = (hireg+1) | 0x80
                                    //     byte2 = (loreg+1)
                                    // Since the 1/2 byte form is not well suited
                                    // for analysis, we use an external ulong
                                    // form of argument locations.
typedef uint32 argloc_t;            // In the uint32 form we keep first register
                                    // at the LSB and the second register shifted << 8
                                    // The 2 high bits of argloc_t denote the presence
                                    // of the registers; if none is present, it
                                    // is a stack argument and the argloc_t value
                                    // denotes the offset from the stack top (usually
                                    // 0 for the first stack argument)
typedef qvector<argloc_t> arglocvec_t;

#define BAD_ARGLOC      argloc_t(-1) // invalid argloc value
#define ARGLOC_REG      0x80000000L // argument is in a register
#define ARGLOC_REG2     0x40000000L // second register is present
inline bool is_reg_argloc(uint32 argloc) { return (argloc & ARGLOC_REG) != 0; }
inline bool is_stack_argloc(uint32 argloc) { return !is_reg_argloc(argloc); }
inline bool is_reg2_argloc(uint32 reg_argloc) { return (reg_argloc & ARGLOC_REG2) != 0; }
// get the first register
inline int get_argloc_r1(uint32 reg_argloc) { return (reg_argloc & 0x7FFF); }
// get the second register
inline int get_argloc_r2(uint32 reg_argloc) { return (reg_argloc >> 15) & 0x7FFF; }
inline argloc_t make_argloc(int r1, int r2)
{
  argloc_t a = 0;
  if ( r1 != -1 ) a |= ARGLOC_REG | r1;
  if ( r2 != -1 ) a |= ARGLOC_REG2 | (r2 << 15);
  return a;
}
inline void split_argloc(argloc_t al, int *r1, int *r2)
{
  if ( is_reg_argloc(al) )
  {
    *r1 = get_argloc_r1(al);
    *r2 = is_reg2_argloc(al) ? get_argloc_r2(al) : -1;
  }
  else
  {
    *r1 = -1;
    *r2 = -1;
  }
}
inline void extract_argloc(const type_t *&ptr, int *p1, int *p2)
{
  type_t high = *ptr++;
  *p1 = (high & 0x7F) - 1;
  if ( high > 0x80 )
    *p2 = *ptr++ - 1;
  else
    *p2 = -1;
}

inline argloc_t extract_argloc(const type_t *&ptr)
{
  int p1, p2;
  extract_argloc(ptr, &p1, &p2);
  return make_argloc(p1, p2);
}

// returns 0 if a stack argument
inline uint32 extract_and_convert_argloc(const type_t *&tp)
{
  int r1, r2;
  extract_argloc(tp, &r1, &r2);
  if ( r1 == -1 ) // stack argument
    return 0;
  return make_argloc(r1, r2);
}

//----
// extract one spoiled register info
inline void extract_spoiledreg(const type_t *&ptr, uchar *reg, uchar *len)
{
  type_t t = *ptr++;
  if ( !(t & 0x80) ) {
    *len = uchar(1 + (t >> 4));
    *reg = uchar((t & (uchar)0xF) - 1);
  } else {
    *len = *ptr++;
    *reg = uchar(t & 0x7F);
  }
}

// skip all spoiled register info. ptr points just after the calling convention
// if the spoiled register info is absent, return the original pointer
// returns NULL if the type string ends prematurely
idaman const type_t *ida_export skip_spoiled_info(const type_t *ptr);

//----------------------------
//
// standard C-language models for x86
const cm_t C_PC_TINY    = (CM_N16_F32 | CM_M_NN);
const cm_t C_PC_SMALL   = (CM_N16_F32 | CM_M_NN);
const cm_t C_PC_COMPACT = (CM_N16_F32 | CM_M_NF);
const cm_t C_PC_MEDIUM  = (CM_N16_F32 | CM_M_FN);
const cm_t C_PC_LARGE   = (CM_N16_F32 | CM_M_FF);
const cm_t C_PC_HUGE    = (CM_N16_F32 | CM_M_FF);
const cm_t C_PC_FLAT    = (CM_N32_F48 | CM_M_NN);
//
inline cm_t get_cc (cm_t cm) { return(cm & CM_CC_MASK); }

// a calling convention that specifies that argument locations explicitly?
inline bool is_user_cc(cm_t cm)
{
  cm_t cc = get_cc(cm);
  return cc >= CM_CC_SPECIALE;
}

// a calling convention with ellipsis?
inline bool is_vararg_cc(cm_t cm)
{
  cm_t cc = get_cc(cm);
  return cc == CM_CC_ELLIPSIS || cc == CM_CC_SPECIALE;
}

// a calling convention that cleans the stack arguments upon return?
// Note: this function is valid only for x86 code
inline bool is_purging_cc(cm_t cm)
{
  cm_t cc = get_cc(cm);
  return cc == CM_CC_STDCALL || cc == CM_CC_PASCAL || cc == CM_CC_SPECIALP || cc == CM_CC_FASTCALL || cc == CM_CC_THISCALL;
}

/////////////////////////////////////////////////////////////////////////////
// CC (compiler)
const comp_t COMP_MASK   = 0x0F;
const comp_t  COMP_UNK     = 0x00;      // Unknown
const comp_t  COMP_MS      = 0x01;      // Visual C++
const comp_t  COMP_BC      = 0x02;      // Borland C++
const comp_t  COMP_WATCOM  = 0x03;      // Watcom C++
//const comp_t  COMP_         = 0x04
//const comp_t  COMP_         = 0x05
const comp_t  COMP_GNU     = 0x06;      // GNU C++
const comp_t  COMP_VISAGE  = 0x07;      // Visual Age C++
const comp_t  COMP_BP      = 0x08;      // Delphi
//----

const comp_t  COMP_UNSURE  = 0x80;      // uncertain compiler id
//----
inline comp_t get_comp(comp_t comp) { return(comp & COMP_MASK); }
idaman const char *ida_export get_compiler_name(comp_t id);
inline comp_t is_comp_unsure(comp_t comp) { return(comp & COMP_UNSURE); }

inline comp_t default_compiler(void) { return(get_comp(inf.cc.id)); }

// Change current compiler
// Returns: success

idaman bool ida_export set_compiler(const compiler_info_t &cc, int flags);

#define SETCOMP_OVERRIDE 0x0001         // may override old compiler info
#define SETCOMP_ONLY_ID  0x0002         // cc has only 'id' field
                                        // the rest will be set to defaults
                                        // corresponding to the program bitness

inline bool idaapi set_compiler_id(comp_t id)
{
  compiler_info_t cc;
  cc.id = id;
  return set_compiler(cc, SETCOMP_ONLY_ID);
}


// get compiler id from its character code
// returns COMP_UNK - bad character code
comp_t get_compiler_id(char c);
//--------------------------------------------------------------------------
#define MAXFUNCARGCMT 64

#if ( MAXNAMELEN + MAXFUNCARGCMT + 4 ) > MAXSTR
#error  "Illegal MAXFUNCARGCMT"
#endif

// extraction from name/comment string arrays

idaman bool ida_export extract_pstr(const p_list * &pt, char *buff, size_t buff_sz);

inline bool extract_name(const p_list *&pt, char *buff)   { return extract_pstr(pt, buff, MAXNAMELEN); }
inline bool skipName(const p_list *&pt)                   { return extract_name(pt, NULL); }
inline bool extract_comment(const p_list *&pt, char *buff){ return extract_pstr(pt, buff, MAXSTR); }
inline bool skipComment(const p_list *&pt)                { return extract_comment(pt, NULL); }
inline bool extract_fargcmt(const p_list *&pt, char *buff){ return extract_pstr(pt, buff, MAXFUNCARGCMT); }
inline void skip_argloc(const type_t *&ptr)               { if ( *ptr++ > 0x80 ) ptr++; }

//--------------------------------------------------------------------------
// DEFINITIONS FOR C/C++ TYPE DECLARATION PARSER

enum abs_t    { abs_unk, abs_no, abs_yes };     // abstractness of declaration
enum sclass_t                                   // storage class
{
  sc_unk,       // unknown
  sc_type,      // typedef
  sc_ext,       // extern
  sc_stat,      // static
  sc_reg,       // register
  sc_auto,      // auto
  sc_friend,    // friend
  sc_virt       // virtual
};

#define HTI_CPP    0x0001              // C++ mode (not implemented)
#define HTI_INT    0x0002              // debug: print internal representation of types
#define HTI_EXT    0x0004              // debug: print external representation of types
#define HTI_LEX    0x0008              // debug: print tokens
#define HTI_UNP    0x0010              // debug: check the result by unpacking it
#define HTI_TST    0x0020              // test mode: discard the result
#define HTI_FIL    0x0040              // "input" is file name
                                       // otherwise "input" contains a C declaration
#define HTI_MAC    0x0080              // define macros from the base tils
#define HTI_NWR    0x0100              // no warning messages
#define HTI_NER    0x0200              // ignore all errors but display them
#define HTI_DCL    0x0400              // don't complain about redeclarations
#define HTI_NDC    0x0800              // don't decorate names
#define HTI_PAK    0x7000              // explicit structure pack value (#pragma pack)
#define HTI_PAK_SHIFT 12               // shift for HTI_PAK. This field should
                                       // be used if you want to remember explicit
                                       // pack value for each structure/union type
                                       // Some valid pack constants:
#define HTI_PAKDEF 0x0000              //   default pack value
#define HTI_PAK1   0x1000              //   #pragma pack(1)
#define HTI_PAK2   0x2000              //   #pragma pack(2)
#define HTI_PAK4   0x3000              //   #pragma pack(4)
#define HTI_PAK8   0x4000              //   #pragma pack(8)
#define HTI_PAK16  0x5000              //   #pragma pack(16)

#define HTI_ANON   0x8000              // allow anonymous types (don't generate artifical
                                       // names for them but rather store them in-place)

// this callback will be called for each type/variable declaration
// if it returns T_CBBRKDEF, the type declaration won't be saved in the til
typedef int idaapi h2ti_type_cb(
     const char *name,                 // var/func/type name
     const type_t *type,               // type descriptor string
     const char *cmt,                  // main comment
     const p_list *field_names,        // field names
     const p_list *field_cmts,         // field comments
     const uint32 *value,              // symbol value
     void *cb_data);

typedef AS_PRINTF(1, 2) int printer_t(const char *format, ...);

// convert descriptions to type_t*
// returns number of errors (they are displayed using print_cb)
// zero means ok
// This is a low level function - use parse_... functions below
idaman int ida_export h2ti(
         til_t *ti,
         lexer_t *lx,              // input lexer, may be NULL
                                   // always destroyed by h2ti()
         const char *input,        // file name or C declaration
         int flags=0,              // see HTI_... above
         h2ti_type_cb *type_cb=NULL,    // for each type
         h2ti_type_cb *var_cb=NULL,     // for each var
         printer_t *print_cb=NULL,      // may pass 'msg' here
         void *_cb_data=NULL,
         abs_t _isabs=abs_unk);

AS_PRINTF(2, 3) void h2ti_warning(void *parser, const char *format, ...);

// Parse ONE declaration
//      til     - in: type library to store the result
//      decl    - in: C declaration to parse
//      name    - out: declared name
//      type    - out: type string
//      fields  - out: field names
//      flags   - combination of PT_... constants
// NOTE: name & type & fields might be empty after the call!
// Returns true-ok, false-declaration is bad, the error message is displayed
// If the input string contains more than one declaration, the first complete
// type declaration (PT_TYP) or the last variable declaration (PT_VAR) will be used.

idaman bool ida_export parse_decl(
        til_t *til,
        const char *decl,
        qstring *name,
        qtype *type,
        qtype *fields,
        int flags);
#define PT_SIL       0x0001  // silent, no messages
#define PT_NDC       0x0002  // don't decorate names
#define PT_TYP       0x0004  // return declared type information
#define PT_VAR       0x0008  // return declared object information
#define PT_PACKMASK  0x0070  // mask for pack alignment values


// Parse many declarations and store them in 'til'
//    til       - type library to store the result
//    input     - input string or file name (see hti_flags)
//    printer   - function to output error messages (use msg or NULL or your own callback)
//    hti_flags - combination of HTI_... bits
// Returns number of errors, 0 means ok
// If there are any errors, they will be printed using 'printer'.
// This function uses default include path and predefined macros from the
// database settings. It always uses the HTI_DCL bit.

idaman int ida_export parse_decls(
        til_t *til,
        const char *input,
        printer_t *printer,
        int hti_flags);


/////////////////////////////////////////////////////////////////////////////
//              WORK WITH NAMED TYPES
/////////////////////////////////////////////////////////////////////////////

// get named typeinfo
//      til       - pointer to type information library
//      name      - name of type
//      flags     - combination of NTF_... flags
//      type      - ptr to ptr to output buffer for the type info
//      fields    - ptr to ptr to the field/args names. may be NULL
//      cmt       - ptr to ptr to the main comment. may be NULL
//      fieldcmts - ptr to ptr to the field/args comments. may be NULL
//      sclass    - ptr to storage class (sc_...)
//      value     - ptr to symbol value. for types, ptr to the ordinal number
// if name==NULL returns false
// returns: 0 - can't find the named type
//          1  - ok, the buffers are filled with information (if not NULL)
//          2  - ok, found it in a base til
// the returned pointers are pointers to static storage
// they are valid till free_til(), set_named_type(), del_named_type(), rename_named_type(),
// set_numbered_type(), del_numbered_type(), and idb structure/enum manipulation
// (in other words, until til_t is changed)

idaman int ida_export get_named_type(
        const til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t **type=NULL,
        const p_list **fields=NULL,
        const char **cmt=NULL,
        const p_list **fieldcmts=NULL,
        sclass_t *sclass=NULL,
        uint32 *value=NULL);

#define NTF_TYPE     0x0001     // type name
#define NTF_SYMU     0x0008     // symbol, name is unmangled ('func')
#define NTF_SYMM     0x0000     // symbol, name is mangled ('_func')
                                // only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used
#define NTF_NOBASE   0x0002     // don't inspect base tils (for get_named_type)
#define NTF_REPLACE  0x0004     // replace original type (for set_named_type)
#define NTF_UMANGLED 0x0008     // name is unmangled (don't use this flag)
#define NTF_NOCUR    0x0020     // don't inspect current til file (for get_named_type)


// set named typeinfo
//      til       - pointer to til.
//      name      - name of type (any ascii string)
//      flags     - combination of NTF_...
//      ptr       - pointer to typeinfo to save
//      fields    - ptr to the field/args names. may be NULL
//      cmt       - ptr to the main comment. may be NULL
//      fieldcmts - ptr to the field/args comments. may be NULL
//      sclass    - ptr to storage class (sc_...). may be NULL
//      value     - ptr to symbol value. for types, ptr to the ordinal number. may be NULL
// if name==NULL or ptr==NULL returns false
// returns true if successfully saves the typeinfo

idaman bool ida_export set_named_type(
        til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t *ptr,
        const p_list *fields=NULL,
        const char *cmt=NULL,
        const p_list *fieldcmts=NULL,
        const sclass_t *sclass=NULL,
        const uint32 *value=NULL);


// get size of the named type
// returns: -1 - error (unknown name)
//           0 - unknown size
//          otherwise returns the size

idaman size_t ida_export get_named_type_size(
        const til_t *ti,
        const char *name,
        int ntf_flags,
        size_t *lp = NULL);


// del information about a symbol
// returns: success

idaman bool ida_export del_named_type(til_t *ti, const char *name, int ntf_flags);


// rename a type or a symbol
//      ti - type library
//      from - source name
//      to - destination name. NULL denotes anonymous name
//      ntf_flags - combination of NTF_.. constants
// If NTF_TYPE is specifed and numbered types are enabled (idati has them enabled)
// then this function can be used to add or delete type names.
// The ordinals can be specified as specially crafter names: '#' followed by set_de(ordinal)
// return error code (see T_... constants above)

idaman int ida_export rename_named_type(til_t *ti, const char *from, const char *to, int ntf_flags);


// Enumerate types
// These functions return mangled names
// They never return anonymous types. To include them, enumerate types by ordinals.

idaman const char *ida_export first_named_type(const til_t *ti, int ntf_flags);
idaman const char *ida_export next_named_type(const til_t *ti, const char *name, int ntf_flags);


// Mangle/unmangle a C symbol name
//      ti        - pointer to til
//      name      - name of symbol
//      type      - type of symbol. If NULL then it will try to guess.
//      outbuf    - output buffer
//      bufsize   - size of the output buffer
//      mangle    - true-mangle, false-unmangle
//      cc        - real calling convention for VOIDARG functions
// returns true if success

inline bool decorate_name(
        const til_t *ti,
        const char *name,
        const type_t *type,
        char *outbuf,
        size_t bufsize,
        bool mangle,
        cm_t cc=0)
{
  if ( !ph.ti() )
    return false;
  return ph.notify(ph.decorate_name, ti, name,
                        type, outbuf, bufsize, mangle, cc) != 0;
}

// Generic function for that (may be used in IDP modules):
idaman bool ida_export gen_decorate_name(
        const til_t *ti,
        const char *name,
        const type_t *type,
        char *outbuf,
        size_t bufsize,
        bool mangle,
        cm_t cc);

// Get undecorated or demangled name, the smallest possible form
//      name - original (mangled or decorated) name
//      type - name type if known, otherwise NULL
//      buf  - output buffer
//      bufsize - output buffer size
// Returns: true-name has been demangled/undecorated
//          false-name is the same as before

idaman bool ida_export calc_bare_name(
        const char *name,
        const type_t *type,
        char *buf,
        size_t bufsize);


// Choose a type from a type library
//      root_til  - pointer to starting til (the function will inspect the base tils if allowed by flags)
//      title     - title of listbox to display
//      ntf_flags - combination of NTF_... flags
//      func      - predicate to select types to display (maybe NULL)
//      sym       - pointer to be filled with the chosen type
// returns: false-nothing is chosen, otherwise true

typedef bool idaapi predicate_t(const char *name, const type_t *type, const p_list *fields);

idaman bool ida_export choose_named_type2(
                const til_t *root_til,
                const char *title,
                int ntf_flags,
                predicate_t *func,
                til_symbol_t* sym);

idaman const char *ida_export choose_named_type(
                const til_t *root_til,
                const char *title,
                int ntf_flags,
                predicate_t *func);


// Choose a type from the local type library
//      ti        - pointer to til
//      title     - title of listbox to display
//      func      - predicate to select types to display (maybe NULL)
//                   0 - skip type, 1-include, 2-preselect
// returns: <=0-nothing is chosen, otherwise an ordinal number

typedef int idaapi local_predicate_t(uint32 ord, const type_t *type, const p_list *fields, void *ud);

idaman uint32 ida_export choose_local_type(
                const til_t *ti,
                const char *title,
                local_predicate_t *func,
                void *ud);

//--------------------------------------------------------------------------
// NUMBERED TYPES
// These types may be named or anonymous.
// They are referenced by their ordinal number. Access to them is faster because
// there is no need to resolve their names. Also, they can stay anonymous
// and be aliased. They can be used only in the local type library
// created by IDA (in idati).

// Enable the use of numbered types in til
// Currently it is impossible to disable numbered types once they are enabled

bool enable_numbered_types(til_t *ti, bool enable);


// Retrieve a type by its ordinal number

idaman bool ida_export get_numbered_type(
        const til_t *ti,
        uint32 ordinal,
        const type_t **type=NULL,
        const p_list **fields=NULL,
        const char **cmt=NULL,
        const p_list **fieldcmts=NULL,
        sclass_t *sclass=NULL);


// Allocate a range of ordinal numbers for new types.
//      qty - number of ordinals to allocate
// Returns the first ordinal. 0 means failure.

idaman uint32 ida_export alloc_type_ordinals(til_t *ti, int qty);
inline uint32 alloc_type_ordinal(til_t *ti) { return alloc_type_ordinals(ti, 1); }


// Get number of allocated ordinals
// If failed, returns uint32(-1)

idaman uint32 ida_export get_ordinal_qty(const til_t *ti);


// Store a type in the til
// 'name' may be NULL for anonymous types
// The specified ordinal must be free (no other type is using it)

idaman bool ida_export set_numbered_type(
        til_t *ti,
        uint32 ordinal,
        int ntf_flags,              // only NTF_REPLACE is consulted
        const char *name,
        const type_t *type,
        const p_list *fields=NULL,
        const char *cmt=NULL,
        const p_list *fldcmts=NULL,
        const sclass_t *sclass=NULL);


// Delete a numbered type

idaman bool ida_export del_numbered_type(til_t *ti, uint32 ordinal);


// Create a type alias.
// Redirects all references to source type to the destination type.
// This is equivalent to instantaneous replacement all reference to srctype by dsttype.

idaman bool ida_export set_type_alias(til_t *ti, uint32 src_ordinal, uint32 dst_ordinal);


// Find the final alias destination.
// If the ordinal has not been aliased, return the specified ordinal itself
// If failed, returns 0. Might return uint32(-1) to indicate a deleted target.
// (in this case we have a dangling alias)

idaman uint32 ida_export get_alias_target(const til_t *ti, uint32 ordinal);


// Get type ordinal by its name

inline int32 get_type_ordinal(const til_t *ti, const char *name)
{
  uint32 ordinal = 0;
  get_named_type(ti, name, NTF_TYPE|NTF_NOBASE, NULL, NULL, NULL, NULL, NULL, &ordinal);
  return ordinal;
}

// Get type name (if exists) by its ordinal
// If the type is anonymous, returns "". If failed, returns NULL

idaman const char *ida_export get_numbered_type_name(const til_t *ti, uint32 ordinal);


// Create anonymous name for numbered type. This name can be used
// to reference a numbered type by its ordinal
// Ordinal names have the following format: '#' + set_de(ord)
// Returns: 0 if error, otherwise the name length

idaman size_t ida_export create_numbered_type_name(int32 ord, char *buf, size_t bufsize);


// Check if the name is an ordinal name
// Ordinal names have the following format: '#' + set_de(ord)

inline bool is_ordinal_name(const char *name, uint32 *ord)
{
  if ( name[0] != '#' )
    return false;

  const type_t *ptr = (const type_t *)name + 1;
  return get_de(ptr, ord);
}

// Get ordinal number of an idb type (struct/enum)
// The 'type' parameter is used only to determine the kind of the type (struct or enum)
// Use this function to find out the correspondence between idb types and til types

idaman int ida_export get_ordinal_from_idb_type(const char *name, const type_t *type);


// Is the specified idb type automatically synchronized?
inline bool idaapi is_autosync(const char *name, const type_t *type)
{
  return get_ordinal_from_idb_type(name, type) != -1;
}


// Generate a name like $hex_numbers based on the field types and names

idaman void ida_export build_anon_type_name(
        char *buf,
        size_t bufsize,
        const type_t *type,
        const p_list *fields);


//--------------------------------------------------------------------------
// ALIGNMENT

// Get default alignment for structure fields
//      cm - the current calling convention and model
// returns: the default alignment for structure fields
//          (something like 1,2,4,8,...)

inline size_t get_default_align(cm_t) { return inf.cc.defalign; }

inline void align_size(size_t &size, size_t algn)
  { if ( size && (int)--algn > 0) size = (size + algn ) & ~algn; }

// Get alignment delta for a structure field
//      cur_tot_size - the structure size calculated so far
//      elem_size    - size of the current field
//                     the whole structure should be calculated
//      algn         - the structure alignment (1,2,4,8...)
inline void align_size(size_t &cur_tot_size, size_t elem_size, size_t algn)
    { align_size(cur_tot_size, qmin(elem_size, algn)); }

//--------------------------------------------------------------------------
// enums

// Get sizeof(enum)

inline size_t get_default_enum_size(cm_t cm)
  { return ph.ti() ? ph.notify(ph.get_default_enum_size, cm) : 0; }

//--------------------------------------------------------------------------
// POINTERS

// get maximal pointer size

inline int max_ptr_size(void) { return ph.notify(ph.max_ptr_size)-1; }

// get prefix and size of 'segment based' ptr type (something like char _ss *ptr)
//      ptrt  - the type of pointer to get information about
//              it is calculated as "size - max_ptr_size() - 1"
//      size  - the sizeof of the type will be returned here
// returns: NULL - error (unknown type == bad typeinfo string)
//          else - string in form "_ss",
//                 size contains sizeof of the type
// HINT: the returned value may be an empty string ("")

inline const char *idaapi based_ptr_name_and_size(unsigned ptrt, size_t &size)
{
  if ( !ph.ti() )
    return NULL;
  const char *ptrname;
  size = ph.notify(ph.based_ptr, ptrt, &ptrname);
  return ptrname;
}


// Dereference a pointer
//      ti          - type library (usually idati)
//      type        - type of the pointer
//      ptr_ea      - in: address of the pointer
//                    out: the pointed address
//      closure_obj - out: closure object (not used yet)
// Returns: true-success

idaman bool ida_export deref_ptr(
        const til_t *ti,
        const type_t *type,
        ea_t *ptr_ea,
        ea_t *closure_obj=NULL);


// Calculate function argument locations
//      til       - in: type library
//      type      - in: function type string
//      arglocs   - out: argument locations
//                  each entry in the array will contain an offset from the stack pointer
//                  for the first stack argument the offset will be zero
//                  register locations are represented like this:
//                  the register number combined with ARGLOC_REG
//      maxn      - number of elements in arglocs
// returns: number_of_arguments. -1 means error.
//      type is advanced to the function argument types array

idaman int ida_export calc_argloc_info(
        const til_t *til,
        const type_t *type,
        uint32 *arglocs,
        size_t maxn);

#define MAX_FUNC_ARGS   256             // max number of function arguments


// Get offset of the first stack argument

inline int get_stkarg_offset(void)
{
  if ( !ph.ti() )
    return 0;
  return ph.notify(ph.get_stkarg_offset2) - 2;
}


// Visit all subtypes of a type.
//   ptype - ptr to ptr to type string
//           the pointer will be moved by this function.
// Derive your visitor from this class:
struct type_visitor_t
{
  virtual int idaapi visit_type(const type_t *type) = 0;
  DEFINE_VIRTUAL_DTOR(type_visitor_t)
};

idaman int ida_export for_all_types(const type_t **ptype, type_visitor_t &tv);


// Replace subtypes of a type
// The subtypes to replace are specified as pairs. Each pair means: replace reference
// to the first type by a reference to the second type. The collection of types
// to replace is specified as a vector of such type pairs. Example: the following
// type: struct { int x; int32 z; struct aaa *ptr; }; will be transformed into
//       struct { short x; int32 z; struct bbb *ptr; } if the following pairs
// were specified:
//      (int, short)
//      (struct aaa, struct bbb)
// Returns: number of replaced types

struct type_pair_t
{
  qtype type1;
  qtype type2;
  type_pair_t(void) {}
  type_pair_t(const qtype &l) : type1(l) {}
  type_pair_t(const qtype &l, const qtype &g) : type1(l), type2(g) {}
};
struct type_pair_vec_t : qvector<type_pair_t>
{
  void add_names(const qstring &name1, const qstring &name2);
};
idaman int ida_export replace_subtypes(qtype &type, const type_pair_vec_t &type_pairs);


// Copy a named type from til to idb
//      til   - type library
//      idx   - the position of the new type in the list of types (structures or enums)
//              -1 means at the end of the list
//      tname - the type name
//      flags - combination of the following bits:
#define IMPTYPE_VERBOSE  0x0001 // more verbose output (dialog boxes may appear)
#define IMPTYPE_OVERRIDE 0x0002 // override existing type
#define IMPTYPE_LOCAL    0x0004 // the type is local, the struct/enum won't be marked as til type
                                // there is no need to specify this bit if til==idati,
                                // the kernel will set it automatically
// Returns BADNODE - error

idaman tid_t ida_export import_type(const til_t *til, int idx, const char *name, int flags=0);


// Load a til file
// returns one of ADDTIL_... constants

idaman int ida_export add_til2(const char *name, int flags);

// flags argument:
#define ADDTIL_DEFAULT  0x0000  // default behaviour
#define ADDTIL_INCOMP   0x0001  // load incompatible tils
#define ADDTIL_SILENT   0x0002  // do not ask any questions

// return values:
#define ADDTIL_FAILED   0  // something bad, the warning is displayed
#define ADDTIL_OK       1  // ok, til is loaded
#define ADDTIL_COMP     2  // ok, but til is not compatible with the current compiler

// Unload a til file

idaman bool ida_export del_til(const char *name);


// Apply the specified named type to the address
//      ea - linear address
//      name - the type name, e.g. "FILE"
// returns: success

idaman bool ida_export apply_named_type(ea_t ea, const char *name);


// Apply the specified type to the address
//      til - type library
//      ea - linear address
//      type - type string in the internal format
//      fields - field names if required by the type string
//      userti - 1: this is a definitive type, 0: this is a guessed type
// This function sets the type and tries to convert the item at the specified
// address to conform the type.
// returns: success

idaman bool ida_export apply_tinfo(
        const til_t *til,
        ea_t ea,
        const type_t *type,
        const p_list *fields,
        int userti);


// Apply the specified type to the address
//      til - type library
//      ea - linear address
//      decl - type declaration in C form
// This function parses the declaration and calls apply_type()
// returns: success

idaman bool ida_export apply_cdecl2(til_t *til, ea_t ea, const char *decl, int flags=0);


// Apply the type of the called function to the calling instruction
//      til - type library
//      caller - linear address of the calling instruction.
//               must belong to a function.
//      type - type string in the internal format
//      fields - field names if required by the type string
// This function will append parameter comments and rename the local
// variables of the calling function.

idaman void ida_export apply_callee_type(
        ea_t caller,
        const type_t *type,
        const p_list *fields);


// Apply the specified type and name to the address
//      ea - linear address
//      type - type string in the internal format
//      name - new name for the address
// This function checks if the address already has a type. If the old type
// does not exist or the new type is 'better' than the old type, then the
// new type will be applied. A type is considere better if it has more
// information (e.g.e BT_STRUCT is better than BT_INT).
// The same logic is with the name: if the address already have a meaningful
// name, it will be preserved. Only if the old name does not exist or it
// is a dummy name like byte_123, it will be replaced by the new name.
// Returns: success

idaman bool ida_export apply_once_type_and_name(ea_t ea, const type_t *type, const char *name);


// To retrieve the type information attach to an address, use get_tinfo() function
// (see nalt.hpp)

// Generate a type string using information about the function
// from the disassembly. you could use guess_type() function instead of this function

idaman int ida_export guess_func_tinfo(func_t *pfn, qtype *type, qtype *fields);

#define GUESS_FUNC_FAILED   0   // couldn't guess the function type
#define GUESS_FUNC_TRIVIAL  1   // the function type doesnt' have interesting info
#define GUESS_FUNC_OK       2   // ok, some non-trivial information is gathered


// Generate a type string using information about the id from the disassembly
// id can be a structure/union/enum id or an address.

idaman int ida_export guess_tinfo(tid_t id, qtype *type, qtype *fields);


// Various parameters

inline void set_c_header_path(const char *incdir)           { RootNode.supset(RIDX_H_PATH, incdir); }
inline ssize_t get_c_header_path(char *buf, size_t bufsize) { return RootNode.supstr(RIDX_H_PATH, buf, bufsize); }
inline void set_c_macros(const char *macros)                { RootNode.supset(RIDX_C_MACROS, macros); }
inline ssize_t get_c_macros(char *buf, size_t bufsize)      { return RootNode.supstr(RIDX_C_MACROS, buf, bufsize); }

//------------------------------------------------------------------------
// HIGH LEVEL FUNCTIONS TO SUPPORT TILS IN THE IDA KERNEL
// This functions are mainly for the kernel only.

// Pointer to the local type library. This til is private for each
// IDB file.

idaman ida_export_data til_t *idati;

void init_til(bool newfile);
void save_til(void);
void term_til(void);

void determine_til(void);
void sync_from_til(const til_t *ti, const char *oname, const char *name, const type_t *type);

idaman char *ida_export get_tilpath(char *tilbuf, size_t tilbufsize);
void autoload_til(const char *cfgfname, const char *sigfname);

idaman bool ida_export get_idainfo_by_type2(
        const til_t *til,
        const type_t *&rtype,
        const p_list *fields,
        size_t *psize,
        flags_t *pflags,
        opinfo_t *mt,
        size_t *alsize=NULL);

void apply_callee_type(ea_t caller, ea_t callee);

// propagate stack argument information
void propagate_stkargs(void);

// Since it is difficult to directly work with the function type string directly,
// the func_type_info_t object has been introduced.
// It represents the function type information in a better way.
// There are two conversion functions:
//   build_funcarg_info:  typestring -> function object
//   build_func_type:     function object -> typestring

struct funcarg_info_t
{
  argloc_t argloc;      // argument location (stack offset or register if ARGLOC_REG)
  qstring name;         // argument name (might be empty)
  qtype type;           // argument type
  qtype fields;         // argument field names (used for local structure types)
  funcarg_info_t(): argloc(0) {};
};

struct func_type_info_t : public qvector<funcarg_info_t>
{
  int flags;
#define FTI_SPOILED 0x0001 // __spoils information is present
  qtype rettype;        // return type
  qtype retfields;      // return type field names (if structure)
  argloc_t retloc;      // return location
  uval_t stkargs;       // size of stack arguments (not used in build_func_type)
  reginfovec_t spoiled; // spoiled register information
                        // if spoiled register info is present, it overrides
                        // the standard spoil info (eax, edx, ecx for x86)
  cm_t cc;              // calling convention
  type_t basetype;      // function base type (the first byte of the type, not used in build_func_type)
  func_type_info_t(): flags(0), retloc(0), stkargs(0), cc(0), basetype(0) {};
};

// functype string -> func_type_info object
// returns the number of function parameters, -1 if error
idaman int ida_export build_funcarg_info(
        const til_t *til,
        const type_t *type,
        const p_list *fields,
        func_type_info_t *info, // out: argument information
        int bfi_flags);
#define BFI_NOCONST 0x0001      // remove constness from all function argument types

// func_type_info object -> functype string
idaman bool ida_export build_func_type(
        qtype *p_type,                  // out: function type string
        qtype *p_fields,                // out: field names
        const func_type_info_t &fi);    // in: information about function type

idaman bool ida_export build_func_type2(
        const til_t *ti,
        qtype *p_type,
        qtype *p_fields,
        const func_type_info_t &fi);

// Other helper functions to work with function types. They are lighter because
// they do not scan the whole type string.

// returns number of arguments
// *p_type points to the argument part after this call
idaman int ida_export get_func_rettype(
        const til_t *til,
        const type_t **type,
        const p_list **fields,
        qtype *rettype,
        qtype *retfields=NULL,
        argloc_t *p_retloc=NULL,
        cm_t *p_cc=NULL);

// get the calling convention of the function
// *p_type points to the return type after this call
// returns: CM_CC_INVALID is any error occurs
idaman cm_t ida_export get_func_cc(
        const til_t *til,
        const type_t **p_type,
        const p_list **p_fields=NULL);

inline int idaapi calc_func_nargs(const til_t *til, const type_t *type)
{
  return get_func_rettype(til, &type, NULL, NULL);
}

inline int calc_purged_bytes(const type_t *type)
{
  return ph.notify(ph.calc_purged_bytes, type) - 2;
}


// calculate 'names' and 'cmts' lists for a new type
// the caller has to qfree names and cmts
idaman error_t ida_export calc_names_cmts(
        const til_t *ti,
        const type_t *type,
        bool idaapi find_var(
                int level,
                void *ud,
                const char **name,
                const char **cmt),
        void *ud,
        p_list **names,
        p_list **cmts);

// resolve BT_COMPLEX type
idaman bool ida_export resolve_complex_type2(
        const til_t *til,
        const type_t **ptype,         // in/out
        const p_list **fields,        // in/out
        qstring *type_name,           // out: type name
        type_t *bt,                   // out
        int *N);                      // out: nfields and alignment


// process each field of a complex type
idaman int ida_export visit_strmems(
        const til_t *til,
        const type_t *type,           // points to field types
        const p_list *fields,
        int N,                        // nfields and alignment
        bool is_union,
        int idaapi visitor(
                uint32 offset,
                const type_t *type,
                const p_list *fields,
                const char *name,
                void *ud),
        void *ud);

idaman bool ida_export is_type_scalar2(const til_t *til, const type_t *type);

typedef int type_sign_t;
const type_sign_t
  no_sign       = 0,    // or unknown
  type_signed   = 1,    // signed type
  type_unsigned = 2;    // unsigned type

idaman type_sign_t ida_export get_type_sign(const til_t *til, const type_t *type);
inline bool is_type_signed  (const til_t *til, const type_t *type) { return get_type_sign(til, type) == type_signed; }
inline bool is_type_unsigned(const til_t *til, const type_t *type) { return get_type_sign(til, type) == type_unsigned; }

//------------------------------------------------------------------------
// Definitions for packing/unpacking idc objects

struct regobj_t                         // object that represents a register
{
  int regidx;                           // index into dbg->registers
  int relocate;                         // 0-plain num, 1-must relocate
  bytevec_t value;
  size_t size(void) const { return value.size(); }
};
struct regobjs_t : public qvector<regobj_t>
{
};

// Read a typed idc object from the database
idaman error_t ida_export unpack_object_from_idb(
        idc_value_t *obj,
        til_t *ti,
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        const bytevec_t *off0,  // if !NULL: bytevec that represents object at 'ea'
        int pio_flags=0);
#define PIO_NOATTR_FAIL 0x0004  // missing attributes are not ok
#define PIO_IGNORE_PTRS 0x0008  // do not follow pointers

// Read a typed idc object from the byte vector
idaman error_t ida_export unpack_object_from_bv(
        idc_value_t *obj,
        til_t *ti,
        const type_t *type,
        const p_list *fields,
        const bytevec_t &bytes,
        int pio_flags=0);

// Write a typed idc object to the database
idaman error_t ida_export pack_object_to_idb(
        const idc_value_t *obj,
        til_t *ti,
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        int pio_flags=0);

// Write a typed idc object to the byte vector
// Byte vector may be non-empty, this function will append data to it
idaman error_t ida_export pack_object_to_bv(
        const idc_value_t *obj,
        til_t *ti,
        const type_t *type,
        const p_list *fields,
        relobj_t *bytes,
        void *objoff,         // NULL - append object to 'bytes'
                              // if not NULL:
                              //   in: int32*: offset in 'bytes' for the object
                              //       -1 means 'do not store the object itself in bytes
                              //                 store only pointed objects'
                              //   out: data for object (if *(int32*)objoff == -1)
        int pio_flags=0);


struct get_strmem_t
{
  int flags;            // STRMEM_.. flags
#define STRMEM_MASK    0x0007 //   the search type:
#define   STRMEM_OFFSET 0x0000//   get member by offset
                              //   in:  this->offset - is a member offset
#define   STRMEM_INDEX  0x0001//   get member by number
                              //   in:  this->index - is a member number
#define   STRMEM_AUTO   0x0002//   get member by offset if struct
                              //   get member by index if union
                              //     nb: index is stored in the offset field!
#define   STRMEM_NAME   0x0003//   get member by name
                              //   in:  this->name - the desired member name.
#define   STRMEM_TYPE   0x0004//   get member by type.
                              //   in:  this->ftype - the desired member type.
                              //   member types are compared with equal_types()
#define STRMEM_ANON 0x80000000//   can be combined with STRMEM_NAME:
                              //     look inside anonymous members too.
#define STRMEM_CASTABLE_TO 0x40000000
                              //   can be combined with STRMEM_TYPE:
                              //     member type must be castable to the specified type
  int index;            // member index
  asize_t offset;       // member offset
  asize_t delta;        // search by offset: offset from the member start
  qstring name;         // member name
  qtype ftype;          // member type
  qtype fnames;         // member field names
  qstring sname;        // structure type name
};

// get a structure member:
//   - at the specified offset  (STRMEM_OFFSET)
//   - with the specified index (STRMEM_INDEX)
//   - with the specified type  (STRMEM_TYPE)
//   - with the specified name  (STRMEM_NAME)
idaman bool ida_export get_strmem2(
        const til_t *til,
        const type_t *type,   // in: type
        const p_list *fields, // in: fields. for typedefs may be NULL
        get_strmem_t *info);  // in/out


// helper function for the processor modules
// to be called from ph.use_stkarg_type
idaman bool ida_export apply_type_to_stkarg(
        op_t &x,
        uval_t v,
        const type_t *type,
        const char *name);

// helper function for the processor modules
// to be called from ph.use_arg_types() for the delay slots
// returns new value of 'rn'
// please use gen_use_arg_types() which is more high level
idaman int ida_export use_regarg_type_cb(
        ea_t ea,
        const type_t **rtypes,
        const char **rnames,
        uint32 *rlocs,
        int rn,
        void *ud=NULL);

//------------------------------------------------------------------------
// helper function for the processor modules
// to be called from ph.use_arg_types() to do everything
// 3 callbacks should be provided:

// set the operand type as specified

typedef bool idaapi set_op_type_t(op_t &x, const type_t *type, const char *name);


// is the current insn a stkarg load?
// if yes, src - index of the source operand in Cmd.Operands
//         dst - index of the destination operand in Cmd.Operands
//               cmd.Operands[dst].addr is expected to have the stack offset

typedef bool idaapi is_stkarg_load_t(int *src, int *dst);


// the call instruction with a delay slot?

typedef bool idaapi has_delay_slot_t(ea_t caller);


// the main function using these callbacks:

idaman int ida_export gen_use_arg_types(
        ea_t caller,
        const type_t * const *types,
        const char * const *names,
        const uint32 *arglocs,
        int n,
        const type_t **rtypes,
        const char **rnames,
        uint32 *rlocs,
        int rn,
        set_op_type_t *set_op_type,
        is_stkarg_load_t *is_stkarg_load, // may be NULL
        has_delay_slot_t *has_delay_slot=NULL);


enum update_type_t
{
  UTP_ENUM,
  UTP_STRUCT,
};

// If you plan to add or modify types massively then use
// the following functions to mark the beginning and the end
// of the update operation. For example, these functions
// can be used with add_enum_member(), add_struc_member(), etc...
idaman void ida_export begin_type_updating(update_type_t utp);
idaman void ida_export end_type_updating(update_type_t utp);

#ifndef NO_OBSOLETE_FUNCS
idaman int ida_export add_til(const char *name);
inline bool is_type_voiddef(type_t t) { return(get_full_type(t) == BTF_VOID); }
inline bool is_type_void_obsolete(type_t t) { return(get_base_type(t) == BT_VOID); }
inline bool is_type_unk(type_t t)     { return(get_base_type(t) == BT_UNK); }
inline bool is_type_only_size(type_t t){ return get_base_type(t) <= BT_VOID; }

idaman bool ida_export apply_type(ea_t ea, const type_t *type, const p_list *fields);

idaman bool ida_export apply_type2(ea_t ea, const type_t *rtype, const p_list *fields, int userti);
idaman bool ida_export parse_type(const char *decl, char **name, type_t **type, p_list **fields, int flags=0);
idaman int ida_export parse_types(const char *input, bool isfile, printer_t *printer);
idaman int ida_export parse_types2(const char *input, printer_t *printer, int hti_flags);
idaman bool ida_export resolve_complex_type(const type_t **ptype, const p_list **fields, char *fname, size_t fnamesize, type_t *bt, int *N);
idaman int ida_export foreach_strmem(const type_t *type, const p_list *fields, int N, bool is_union, int idaapi func(uint32 offset, const type_t *type, const p_list *fields, const char *name, void *ud), void *ud);
idaman bool ida_export get_struct_member(const type_t *type, const p_list *fields, asize_t offset, asize_t *delta, char *name, size_t namesize, type_t *ftype, size_t typesize, p_list *ffields, size_t ffldsize, char *sname, size_t snamesize);
idaman bool ida_export apply_cdecl(ea_t ea, const char *decl);
idaman tid_t ida_export til2idb(int idx, const char *name);
idaman bool ida_export get_idainfo_by_type(const type_t *&rtype, const p_list *fields, size_t *psize,  flags_t *pflags,  opinfo_t *mt, size_t *alsize=NULL);
idaman bool ida_export remove_pointerness(const type_t **ptype, const char **pname);
idaman int  ida_export get_pointer_object_size(const type_t *t);
idaman bool ida_export is_type_scalar(const type_t *type);
idaman type_sign_t ida_export get_type_signness(const type_t *type);
inline bool is_type_signed  (const type_t *type) { return get_type_sign(idati, type) == type_signed; }
inline bool is_type_unsigned(const type_t *type) { return get_type_sign(idati, type) == type_unsigned; }
idaman bool ida_export is_resolved_type_const  (const type_t *type);
idaman bool ida_export is_resolved_type_void   (const type_t *type); // really void?
idaman bool ida_export is_resolved_type_ptr    (const type_t *type);
idaman bool ida_export is_resolved_type_func   (const type_t *type);
idaman bool ida_export is_resolved_type_array  (const type_t *type);
idaman bool ida_export is_resolved_type_complex(const type_t *type);
idaman bool ida_export is_resolved_type_struct (const type_t *type);
idaman bool ida_export is_resolved_type_union  (const type_t *type);
idaman bool ida_export is_resolved_type_struni (const type_t *type);
idaman bool ida_export is_resolved_type_enum   (const type_t *type);
idaman bool ida_export is_resolved_type_bitfld (const type_t *type);
idaman bool ida_export is_castable(const type_t *from, const type_t *to);
idaman int ida_export guess_func_type(func_t *pfn, type_t *type, size_t tsize, p_list *fields, size_t fsize);
idaman int ida_export guess_type(tid_t id, type_t *type, size_t tsize, p_list *fields, size_t fsize);
idaman bool ida_export make_array_type(type_t *buf, size_t bufsize, const type_t *type, int size);
idaman type_t *ida_export extract_func_ret_type(const type_t *type, type_t *buf, int bufsize);
idaman int ida_export get_func_nargs(const type_t **type);
idaman int ida_export build_funcarg_arrays(const type_t *type, const p_list *fields, uint32 *arglocs, type_t **types, char **names, int maxargs, bool remove_constness);
idaman void ida_export free_funcarg_arrays(type_t **types, char **names, int n);
idaman int ida_export calc_arglocs(const type_t *&type, uint32 *arglocs, int maxn);
idaman const type_t *ida_export resolve_typedef(const til_t *ti, const type_t *p, const p_list **fields);
idaman bool ida_export get_strmem(const til_t *til, const type_t *type, const p_list *fields, asize_t offset, asize_t *delta, qstring *name, qtype *ftype=NULL, qtype *fnames=NULL, qstring *sname=NULL);
idaman bool ida_export get_strmem_by_name(const til_t *til, const type_t *type, const p_list *fields, const char *name, asize_t *offset, qtype *ftype=NULL, qtype *fnames=NULL, qstring *sname=NULL);
#define NTF_NOIDB    0x0010     // ignored
#endif

#pragma pack(pop)
#endif // _TYPEINF_HPP

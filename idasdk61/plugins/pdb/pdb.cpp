
// IDA Pro plugin to load function name information from PDB files
//      26-02-2008 Complete rewrite to use DIA API

#include <set>
#include <map>
#include <algorithm>

#ifndef __NT__
#define REMOTEPDB
#endif

#ifndef REMOTEPDB
#include <windows.h>
#include "cvconst.h"
#include "dia2.h"
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <err.h>
#include <md5.h>
#include <dbg.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>
#include "../../ldr/pe/pe.h"
#include "../../include/intel.hpp"
#include "common.h"

#ifndef REMOTEPDB
#include "oldpdb.h"
#define COMPILE_PDB_PLUGIN
#include "common.cpp"
#else
typedef uint32 DWORD;
#include "../../base/tilstream.cpp"
#endif

static peheader_t pe;
static char download_path[QMAXPATH];
static char full_sympath[QMAXPATH];
static char pdb_remote_server[QMAXPATH];
static int  pdb_remote_port = DEBUGGER_PORT_NUMBER;
static char pdb_remote_passwd[QMAXPATH];
static PDB_CALLCODE call_code;

typedef std::map<ea_t, qstring> namelist_t;
static namelist_t namelist;

#ifndef REMOTEPDB

typedef qvector<funcarg_info_t> argsarray_t;

typedef std::map<qstring, qstring> longnames_t;
static longnames_t longnames;

static DWORD g_dwMachineType = CV_CFL_80386;
static int g_diaVersion = 0;
static bool g_enregistered_bug = false;

enum cvt_code_t
{
  cvt_failed,
  cvt_ok,
  cvt_typedef           // conversion resulted in a typedef to a named type
};

static const char *dstr(const type_t *type, const p_list *fields=NULL)
{
  static qstring res;
  if ( print_type_to_qstring(&res, NULL, 2, 0, PRTYPE_1LINE|PRTYPE_TYPE,
                      idati, type, NULL, NULL, fields) <= 0 )
    res = "#print_failed";
  return res.c_str();
}

struct tpinfo_t
{
  cvt_code_t cvt_code;
  qtype type;
  qtype fields;
  tpinfo_t(void) {}
  tpinfo_t(const qtype &t) : type(t), cvt_code(cvt_ok) {}
  const char *dstr(void) const
  {
    if ( cvt_code == cvt_failed )
      return "#cvt_failed";
    else
      return ::dstr(type.c_str(), fields.c_str());
  }
};

static std::set<uint32> unnamed_types;

typedef std::map<DWORD, tpinfo_t> typemap_t;
static typemap_t typemap;              // id -> type info

typedef std::map<DWORD, uint32> idmap_t;
static idmap_t idmap;                  // id -> type ordinal

typedef std::map<DWORD, qstring> tpdefs_t;
static tpdefs_t tpdefs;                // id -> enum type defined in base til

typedef std::set<DWORD> idset_t;       // set of id's
static idset_t handled;                // set of handled symbols

static bool get_symbol_type(IDiaSymbol *sym, qtype &itp, qtype *fields);
static HRESULT handle_symbol(IDiaSymbol *sym, ea_t base);
static void enum_function_args(IDiaSymbol *sym, func_type_info_t &args);
static cvt_code_t really_convert_type(IDiaSymbol *sym, DWORD tag, qtype &itp, qtype *fields, IDiaSymbol *parentSym = NULL);

#endif // REMOTEPDB

//----------------------------------------------------------------------
bool create_func_if_necessary(ea_t ea, const char *name)
{
  int stype = segtype(ea);
  if ( stype != SEG_NORM && stype != SEG_CODE ) // only for code or normal segments
    return false;

  if ( get_mangled_name_type(name) == MANGLED_DATA )
    return false;

  if ( !decode_insn(ea) )
    return false;

  if ( !ph.notify(ph.is_sane_insn, 1) )
    return false;

  auto_make_proc(ea);
  return true;
}

//----------------------------------------------------------------------
bool looks_like_function_name(const char *name)
{
  // this is not quite correct: the presence of an opening brace
  // in the demangled name indicates a function
  // we can have a pointer to a function and there will be a brace
  // but this logic is not applied to data segments
  if ( strchr(name, '(') != NULL )
    return true;

  // check various function keywords
  static const char *const keywords[] =
  {
    "__cdecl ",
    "public: ",
    "virtual ",
    "operator ",
    "__pascal ",
    "__stdcall ",
    "__thiscall ",
  };
  for ( int i=0; i < qnumber(keywords); i++ )
    if ( strstr(name, keywords[i]) != NULL )
      return true;
  return false;
}

//----------------------------------------------------------------------
bool check_for_ids(ea_t ea, const char *name)
{
  // Seems to be a GUID?
  const char *ptr = name;
  while ( *ptr == '_' )
    ptr++;

  static const char *const guids[] = { "IID", "DIID", "GUID", "CLSID", "LIBID", NULL };
  static const char *const sids[] = { "SID", NULL };

  struct id_info_t
  {
    const char *const *names;
    const char *type;
  };
  static const id_info_t ids[] =
  {
    { guids, "GUID x;" },
    { sids,  "SID x;" },
  };
  for ( int k=0; k < qnumber(ids); k++ )
  {
    for ( const char *const *p2=ids[k].names; *p2; p2++ )
    {
      const char *guid = *p2;
      size_t len = strlen(guid);
      if ( strncmp(ptr, guid, len) == 0
        && (ptr[len] == '_' || ptr[len] == ' ') ) // space can be in demangled names
      {
        apply_cdecl2(idati, ea, ids[k].type);
        return true;
      }
    }
  }
  if ( strncmp(name, "_guid", 5) == 0 )
  {
    apply_cdecl2(idati, ea, ids[0].type);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool is_data_prefix(ea_t ea, const char *name)
{
  static const char *const data_prefixes[] =
  {
    "__IMPORT_DESCRIPTOR",
    //"__imp_",             //imported function pointer
  };
  for ( int i=0; i < qnumber(data_prefixes); i++ )
    if ( strncmp(name, data_prefixes[i], strlen(data_prefixes[i])) == 0 )
      return true;

  // __real@xxxxxxxx            - floating point number, 4 bytes
  // __real@xxxxxxxxxxxxxxxx    - floating point number, 8 bytes
  if ( strncmp(name, "__real@", 7) == 0 )
  {
    const char *ptr = name + 7;
    const char *hex = ptr;
    while ( qisxdigit(*ptr) )
      ptr++;
    size_t len = ptr - hex;
    if ( len == 8 )
    {
      doFloat(ea, 4);
      return true;
    }
    if ( len == 16 )
    {
      doDouble(ea, 8);
      return true;
    }
    if ( len == 20 )
    { // i haven't seen this, but probably it exists too
      doTbyt(ea, 10);
      return true;
    }
  }
  return false;
}

//----------------------------------------------------------------------
// maybe_func: -1:no, 0-maybe, 1-yes
bool apply_name(ea_t ea, const qstring &name, int maybe_func)
{
  showAddr(ea); // so the user doesn't get bored

  char buf[MAXSTR];
  buf[0] = '\0';
  // check for meaningless 'string' names
  if ( strncmp(name.c_str(), "??_C@_", 6) == 0 )
  {
      // ansi:    ??_C@_0<len>@xxx
      // unicode: ??_C@_1<len>@xxx
      // TODO: parse length?
      make_ascii_string(ea, 0, name[6]=='1' ? ASCSTR_UNICODE : ASCSTR_C );
      return true;
  }
  if ( maybe_func <= 0 && demangle(buf, sizeof(buf), name.c_str(), MNG_SHORT_FORM) > 0 )
  {
    if ( strcmp(buf, "`string'") == 0 )
    {
      size_t s1 = get_max_ascii_length(ea, ASCSTR_C);
      size_t s2 = get_max_ascii_length(ea, ASCSTR_UNICODE);
      make_ascii_string(ea, 0, s1 >= s2 ? ASCSTR_C : ASCSTR_UNICODE);
      return true;
    }
  }

  // Renaming things immediately right here can lead to bad things.
  // For example, if the name is a well known function name, then
  // ida will immediately try to create a function. This is a bad idea
  // because IDA does not know exact function boundaries and will try
  // to guess them. Since the database has little information yet, there
  // is a big chance that the function will end up to be way too long.
  // That's why we collect names here and will rename them later.
  namelist[ea] = name;

  if ( check_for_ids(ea, name.c_str()) )
    return true;
  if ( check_for_ids(ea, buf) )
    return true;

  if ( is_data_prefix(ea, name.c_str()) )
    return true;

  // do not automatically create functions in debugger segments
  segment_t *s = getseg(ea);
  if ( s == NULL || !s->is_loader_segm() )
    return true;

  // check for function telltales
  if ( maybe_func == 0
    && segtype(ea) != SEG_DATA
    && demangle(buf, sizeof(buf), name.c_str(), MNG_LONG_FORM) > 0
    && looks_like_function_name(buf) )
  {
    auto_make_proc(ea); // fixme: when we will implement lvars, we have to process these request
                        // before handling lvars
    return true;
  }

  if ( maybe_func == 0 )
    create_func_if_necessary(ea, name.c_str());
  return true;
}

#ifndef REMOTEPDB

//----------------------------------------------------------------------
static qstring get_name(IDiaSymbol *sym)
{
  BSTR name;
  qstring res;
  if ( sym->get_name(&name) == S_OK )
  {
    u2cstr(name, &res);
    SysFreeString(name);
  }
  return res;
}

//----------------------------------------------------------------------
static qstring get_type_name(IDiaSymbol *sym, bool *p_unnamed=NULL)
{
  bool is_unnamed = false;
  qstring res = get_name(sym);
  if ( res.empty() )
  {
    is_unnamed = true;
  }
  else
  {
    //      remove `anonymous-namespace'::
    // also remove `anonymous namespace'::
    char *p = res.begin();
    while ( true )
    {             // 1234567890
      p = strstr(p, "`anonymous");
      if ( p == NULL )
        break;
      const char *q = p + 10;
      if ( *q != '-' && *q != ' ' )
        break;
      if ( strncmp(q+1, "namespace'::", 12) != 0 )
        break;      // 123456789012
      size_t idx = p - res.begin();
      res.remove(idx, 10+1+12);
      p = res.begin() + idx;
    }

    // <unnamed-tag>  => <unnamed_tag>
    p = res.begin();
    while ( true )
    {
      //             1234567890123
      p = strstr(p, "<unnamed-tag>");
      if ( p == NULL )
        break;
      p[8] = '_';
      p += 13;
      is_unnamed = true;
    }
    if ( !is_unnamed && res == "__unnamed" )
      is_unnamed = true;

    // very long type names can be stored in tils but can not be converted to
    // idb structs and enums. Truncate such names and, if necessary, add
    // a numeric suffix to distinguish them.
    // MAXNAMELEN is the maximum length of structname.fieldname.
    // Allocate half of it for structname and the other half for the fieldname
    if ( res.length() >= MAXNAMELEN/2 )
    {
      longnames_t::iterator q = longnames.find(res);
      if ( q != longnames.end() )
      {
        res = q->second;
      }
      else
      {
        qstring lname = res;
        res.resize(MAXNAMELEN/2);
        while ( res.last() == ' ' )
          res.resize(res.length()-1);
        for ( int i=0; longnames.find(res) != longnames.end(); i++ )
        {
          char suffix[8];
          size_t suflen = qsnprintf(suffix, sizeof(suffix), "_%d", i);
          res.resize(MAXNAMELEN/2-suflen);
          res.append(suffix);
        }
        longnames[lname] = res;
      }
    }
  }
  if ( p_unnamed != NULL )
    *p_unnamed = is_unnamed;
  return res;
}

//----------------------------------------------------------------------
static bool isFrameReg(int reg)
{
  if ( g_dwMachineType == CV_CFL_80386 )
    return reg == CV_REG_EBP;
  else if ( g_dwMachineType == CV_CFL_ARM6 )
    return reg == CV_ARM_R11 || reg == CV_ARM_SP;
  return false;
}

//----------------------------------------------------------------------
static void handle_function_type(ea_t base, ea_t ea, IDiaSymbol *sym)
{
  // create the function - normally we know its size
  ea_t end = BADADDR;
  DWORD64 ulLen;
  if ( SUCCEEDED(sym->get_length(&ulLen)) )
    end = ea + asize_t(ulLen);
  if ( !create_insn(ea) )
    return;
  if ( !add_func(ea, end) ) // end is wrong for fragmented functions
    add_func(ea, BADADDR);

  struct local_data_creator_t : children_visitor_t
  {
    ea_t base;
    ea_t ea;
    virtual HRESULT visit_child(IDiaSymbol *sym)
    {
      DWORD tag;
      HRESULT hr = sym->get_symTag(&tag);
      if ( FAILED(hr) )
        return hr;

      switch ( tag )
      {
        case SymTagBlock: // nested blocks
          return for_all_children(sym, SymTagNull, *this);
        case SymTagFuncDebugStart:
        case SymTagFuncDebugEnd:
          return S_OK;    // ignore these for the moment
      }

      DWORD dwLocType, dwReg;
      LONG lOffset;
      if ( sym->get_locationType(&dwLocType) != S_OK )
        return S_OK; // optimized away?
      switch ( dwLocType )
      {
        case LocIsConstant:
          break; // we ignore function level constants

        case LocIsStatic:
          handle_symbol(sym, base);
          break;

        case LocIsEnregistered:
          if ( sym->get_registerId(&dwReg) == S_OK )
          {
            if ( g_enregistered_bug && dwReg > 0 )
              dwReg--;
            func_t *pfn = get_func(ea);
            qstring name = get_name(sym);
            const char *canon = print_pdb_register(g_dwMachineType, dwReg);
            if ( pfn != NULL )
              add_regvar(pfn, pfn->startEA, pfn->endEA, canon, name.c_str(), NULL);
          }
          break;

        case LocIsRegRel:
          if ( sym->get_registerId(&dwReg) == S_OK
            && sym->get_offset(&lOffset) == S_OK
            && dwReg == CV_REG_EBP )     // we can handle only ebp for the moment
          {
            func_t *pfn = get_func(ea);
            if ( pfn != NULL )
            {
              qstring name = get_name(sym);
              qtype type, fields;
              if ( get_symbol_type(sym, type, &fields) )
              {
                const type_t *ptr = type.c_str();
                opinfo_t mt;
                size_t size;
                flags_t flags;
                if ( get_idainfo_by_type2(idati, ptr, fields.c_str(), &size, &flags, &mt, NULL) )
                {
                  // DIA's offset is bp-based, not frame-based like in IDA
                  lOffset -= pfn->fpd;
                  if ( g_dwMachineType == CV_CFL_ARM6 && dwReg == CV_ARM_SP )
                    lOffset -= pfn->frsize;
                  // make sure the new variable is not overwriting the return address
                  // for some reason some PDBs have bogus offsets for some params/locals...
                  if ( g_dwMachineType != CV_CFL_80386 || lOffset > 0 || size <= -lOffset )
                  {
                    add_stkvar2(pfn, name.c_str(), lOffset, flags, &mt, size);
                    cmd.ea = BADADDR;
                    cmd.Op1.type = o_void; // make sure is_sp_based fails
                    member_t *mptr = get_stkvar(cmd.Op1, lOffset, NULL);
                    if ( mptr != NULL )
                    {
                      struc_t *sptr = get_frame(pfn);
                      set_member_tinfo(idati, sptr, mptr, 0, type.c_str(), fields.c_str(), 0);
                      set_userti(mptr->id);
                    }
                  }
                }
              }
              else // no type info...
              {
                msg("%a: stkvar '%s' with no type info\n", ea, name.c_str());
              }
            }
          }
          break;

        default:
          ask_for_feedback("pdb: unsupported location type %d, tag %d at %a", dwLocType, tag, ea);
          break;
      }
      return S_OK; // continue enumeration
    }
    local_data_creator_t(ea_t b, ea_t _ea) :
      base(b), ea(_ea){}
  };
  local_data_creator_t ldc(base, ea);
  for_all_children(sym, SymTagNull, ldc);
}

//----------------------------------------------------------------------
static HRESULT handle_symbol(IDiaSymbol *sym, ea_t base)
{
  DWORD id;
  HRESULT hr = sym->get_symIndexId(&id);
  if ( FAILED(hr) )
    return hr;

  if ( handled.find(id) != handled.end() )
    return S_OK;
  handled.insert(id);

  DWORD tag;
  hr = sym->get_symTag(&tag);
  if ( FAILED(hr) )
    return hr;

  int maybe_func = 0; // maybe
  switch ( tag )
  {
    case SymTagNull:
    case SymTagExe:
    case SymTagCompiland:
    case SymTagCompilandEnv:
    case SymTagAnnotation:
    case SymTagCustom:
    case SymTagCustomType:
    case SymTagManagedType:
    case SymTagUDT:
    case SymTagEnum:
    case SymTagFunctionType:
    case SymTagPointerType:
    case SymTagArrayType:
    case SymTagBaseType:
    case SymTagTypedef:
    case SymTagBaseClass:
    case SymTagFunctionArgType:
    case SymTagUsingNamespace:
    case SymTagVTableShape:
    case SymTagDimension:
      return S_OK;
    case SymTagFunction:
    case SymTagThunk:
      maybe_func = 1;
      break;
    case SymTagBlock:
    case SymTagData:
    case SymTagLabel:
    case SymTagFuncDebugStart:
    case SymTagFuncDebugEnd:
    case SymTagVTable:
      maybe_func = -1;
      break;
    case SymTagPublicSymbol:
      {
        BOOL b;
        if ( sym->get_function(&b) && b )
          maybe_func = 1;
      }
      break;
    case SymTagCompilandDetails:
      {
        DWORD backEndVer;
        if ( g_dwMachineType == CV_CFL_80386 && sym->get_backEndMajor(&backEndVer) == S_OK )
          g_enregistered_bug = backEndVer <= 13;
      }
      return S_OK;
    case SymTagFriend:
    default:
      break;
  }

  DWORD off;
  hr = sym->get_relativeVirtualAddress(&off);
  if ( SUCCEEDED(hr) )
  {
    ea_t ea = base + off;
    if ( ea != 0 )
    {
      qstring name = get_name(sym);
      // symbols starting with __imp__ can not be functions
      if ( strncmp(name.c_str(), "__imp__", 7) == 0 )
      {
        doDwrd(ea, 4);
        maybe_func = -1;
      }
      qtype type, fields;
      if ( get_symbol_type(sym, type, &fields) )
      {
        // Apparently _NAME_ is a wrong symbol generated for file names
        // It has wrong type information, so correct it
        if ( tag == SymTagData && name == "_NAME_" && type == (type_t*)"2" )
        {
          static const type_t array_of_chars[] = { BT_ARRAY|BTMT_NONBASED, 1, BT_INT8|BTMT_CHAR, 0 };
          type = array_of_chars;
        }
        if ( tag == SymTagFunction )
        {
          // convert the type again, this time passing function symbol
          // this allows us to get parameter names and handle static class methods
          IDiaSymbol *funcType = NULL;
          if ( sym->get_type(&funcType) == S_OK )
          {
            qtype itp2, fields2;
            if ( really_convert_type(funcType, SymTagFunctionType, itp2, &fields2, sym) == cvt_ok )
            {
              // successfully retrieved
              type = itp2;
              fields = fields2;
            }
            funcType->Release();
          }
        }
        if ( is_restype_func(idati, type.c_str()) )
        {
          maybe_func = 1;
          handle_function_type(base, ea, sym);
        }
        else
        {
          maybe_func = -1;
        }
        const type_t *t2 = type.c_str();
        qtype ret;
        cm_t cc;
        int n = get_func_rettype(idati, &t2, NULL, &ret, NULL, NULL, &cc);
        // sometimes there are functions with linked FunctionType but no parameter or return type info in it
        // we get better results by not forcing type info on them
        bool no_ti = n == 0 && ret.length() == 1 && is_type_void(ret[0]) && fields.empty();
        if ( !no_ti )
          apply_tinfo(idati, ea, type.c_str(), fields.c_str(), true);
      }
      else if ( maybe_func > 0 )
      {
        auto_make_proc(ea); // certainly a func
      }
      apply_name(ea, name, maybe_func);
    }
  }
  return S_OK;
}

//----------------------------------------------------------------------
static cvt_code_t append_basetype(DWORD baseType, int size, qtype &res)
{
  type_t bt = BTF_TYPEDEF;
  const char *name = NULL;
  switch ( baseType )
  {
    default:
    case 0x12c304:                      // "impdir_entry" (guessed)
    case btNoType:
    case btBCD:
    case btBit:
      return cvt_failed;
    case btVoid:
      bt = BTF_VOID;
      break;
    case btChar:
      bt = BT_INT8|BTMT_CHAR;
      break;
    case btBool:
      bt = BT_BOOL;
      if ( size != inf.cc.size_b )
      {
        switch ( size )
        {
          case 1: bt |= BTMT_BOOL1; break;
          case 2: bt |= BTMT_BOOL2; break;
          case 4: bt |= BTMT_BOOL4; break;
          default:
            // can't make this bool size; make an int
            goto MAKE_INT;
        }
      }
      break;
MAKE_INT:
    case btInt:
    case btLong:     bt = get_int_type_bit(size);              break;
    case btUInt:
    case btULong:    bt = get_int_type_bit(size)|BTMT_USIGNED; break;
    case btFloat:
      if ( size == sizeof_ldbl() )
      {
        bt = BTMT_LNGDBL;
      }
      else
      {
        switch( size )
        {
          case 4:  bt = BTMT_FLOAT;   break;
          default:
          case 8:  bt = BTMT_DOUBLE;  break;
          case 10: bt = BTMT_SPECFLT; break;
        }
      }
      bt |= BT_FLOAT;
      break;
    case btWChar:    name = "wchar_t";                         break;
    case btBSTR:     name = "BSTR";                            break;
    case btHresult:  name = "HRESULT";                         break;
    case btCurrency: name = "CURRENCY";                        break;
    case btVariant:  name = "VARIANT";                         break;
    case btComplex:  name = "complex";                         break;
    case btDate:     name = "DATE";                            break;
  }
  res.append(bt);
  if ( name != NULL )
  {
    append_name(&res, name);
    return cvt_typedef;
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
static cm_t convert_cc(DWORD cc0)
{
  switch ( cc0 )
  {
    case CV_CALL_GENERIC    :
    case CV_CALL_NEAR_C     :
    case CV_CALL_FAR_C      : return CM_CC_CDECL;
    case CV_CALL_NEAR_PASCAL:
    case CV_CALL_FAR_PASCAL : return CM_CC_PASCAL;
    case CV_CALL_NEAR_FAST  :
    case CV_CALL_FAR_FAST   : return CM_CC_FASTCALL;
//    case CV_CALL_SKIPPED    :
    case CV_CALL_NEAR_STD   :
    case CV_CALL_FAR_STD    :
    case CV_CALL_ARMCALL    : return CM_CC_STDCALL;
    case CV_CALL_THISCALL   : return CM_CC_THISCALL;
//    case CV_CALL_NEAR_SYS   :
//    case CV_CALL_FAR_SYS    :
//    case CV_CALL_MIPSCALL   :
//    case CV_CALL_ALPHACALL  :
//    case CV_CALL_PPCCALL    :
//    case CV_CALL_SHCALL     :
//    case CV_CALL_ARMCALL    :
//    case CV_CALL_AM33CALL   :
//    case CV_CALL_TRICALL    :
//    case CV_CALL_SH5CALL    :
//    case CV_CALL_M32RCALL   :
  }
  return CM_CC_UNKNOWN;
}

//----------------------------------------------------------------------
static bool retrieve_type(IDiaSymbol *sym, qtype &itp, qtype *fields);

struct chtype_t
{
  qstring name;
  qtype type;
  qtype fields;
};
typedef qvector<chtype_t> chtypes_t;


//----------------------------------------------------------------------
static bool retrieve_children_types_names(IDiaSymbol *sym, func_type_info_t &fi, IDiaSymbol *funcSym)
{
  struct type_name_collector_t : public children_visitor_t
  {
    func_type_info_t &fi;
    HRESULT visit_child(IDiaSymbol *sym)
    {
      // check that it's a parameter
      DWORD dwDataKind;
      if ( sym->get_dataKind(&dwDataKind) == S_OK
        && !(dwDataKind == DataIsParam || dwDataKind == DataIsObjectPtr) )
        return S_OK;
      qtype type, fields;
      if ( retrieve_type(sym, type, &fields) )
      {
        funcarg_info_t &arg = fi.push_back();
        arg.type = type;
        arg.fields = fields;
        arg.name = get_name(sym);
        arg.argloc = 0;
      }
      return S_OK;
    }
    type_name_collector_t(func_type_info_t &_fi) : fi(_fi) {}
  };
  fi.clear();
  type_name_collector_t pp(fi);
  HRESULT hr = for_all_children(sym, SymTagNull, pp);
  if ( SUCCEEDED(hr) && funcSym != NULL )
  {
    // get parameter names from the function symbol
    func_type_info_t args;
    args.flags = 0;
    enum_function_args(funcSym, args);
//    QASSERT(30162,  args.empty() || args.size() == fi.size() );
    bool custom_cc = false;
    for ( int i = 0; i < args.size() && i < fi.size(); i++ )
    {
      if ( fi[i].name.empty() )
        fi[i].name = args[i].name;
      uint32 cur_argloc = args[i].argloc;
      fi[i].argloc = cur_argloc;
      if ( !custom_cc && is_reg_argloc(cur_argloc) )
      {
        if ( g_dwMachineType == CV_CFL_80386 )
        {
          if ( fi.cc == CM_CC_FASTCALL
            && (get_argloc_r1(cur_argloc) == R_cx && i==0 || get_argloc_r1(cur_argloc) == R_dx && i==1) )
          {
            // ignore ecx and edx for fastcall
          }
          else if ( fi.cc == CM_CC_THISCALL && get_argloc_r1(cur_argloc) == R_cx && i==0 )
          {
            // ignore ecx for thiscall
          }
          else
          {
            custom_cc = true;
          }
        }
        //ask_for_feedback("pdb: register arguments are not supported for machine type %d", g_dwMachineType);
      }
    }
    if ( custom_cc )
    {
      // we have some register params; need to convert function to custom cc
      fi.cc = (is_purging_cc(fi.cc) || fi.cc == CM_CC_THISCALL || fi.cc == CM_CC_FASTCALL) ? CM_CC_SPECIALP : CM_CC_SPECIAL;
    }
    return S_OK;
  }
  return S_FALSE;
}

//----------------------------------------------------------------------
static uint32 get_long_value(IDiaSymbol *sym)
{
  uint32 v = 0;
  VARIANT value;
  VariantInit(&value);
  if ( sym->get_value(&value) == S_OK )
  {
    VARIANT vlong;
    VariantInit(&vlong);
    HRESULT hr = VariantChangeType(&vlong, &value, 0, VT_UI4);
    if ( hr != S_OK )
      hr = VariantChangeType(&vlong, &value, 0, VT_I4);
    if ( hr == S_OK )
      v = vlong.ulVal;
    VariantClear(&vlong);
  }
  VariantClear(&value);
  return v;
}

//----------------------------------------------------------------------
// funcSym is Function, typeSym is FunctionType
static bool is_member_func(IDiaSymbol *typeSym, qtype &owner, qtype *fields, IDiaSymbol *funcSym)
{
  // make sure we retrieve class type first
  IDiaSymbol *pParent = NULL;
  if ( typeSym->get_classParent(&pParent) != S_OK || pParent == NULL )
    return false;

  bool has_parent = retrieve_type(pParent, owner, fields);
  pParent->Release();

  // then check if it's static
  BOOL bIsStatic = FALSE;
  if ( funcSym != NULL && g_diaVersion >= 800 && funcSym->get_isStatic(&bIsStatic) == S_OK )
    return !bIsStatic;
  else
    return has_parent;
}

//----------------------------------------------------------------------
static void enum_function_args(IDiaSymbol *sym, func_type_info_t &args)
{
  // enumerate all function parameters and gather their names
  struct param_enumerator_t : children_visitor_t
  {
    func_type_info_t& args;
    int stack_off;
    virtual HRESULT visit_child(IDiaSymbol *sym)
    {
      DWORD tag;
      HRESULT hr = sym->get_symTag(&tag);
      if ( FAILED(hr) )
        return hr;

      switch ( tag )
      {
        case SymTagBlock: // nested blocks
          return for_all_children(sym, SymTagNull, *this);
        case SymTagFuncDebugStart:
        case SymTagFuncDebugEnd:
          return S_OK;    // ignore these for the moment
      }

      DWORD dwDataKind, locType;
      if ( sym->get_dataKind(&dwDataKind) == S_OK && dwDataKind == DataIsParam
        && sym->get_locationType(&locType) == S_OK )
      {
        funcarg_info_t &fi = args.push_back();
        fi.name = get_name(sym);
        get_symbol_type(sym, fi.type, &fi.fields);
        if ( locType == LocIsEnregistered )
        {
          DWORD dwReg;
          if ( sym->get_registerId(&dwReg) == S_OK )
          {
            if ( g_enregistered_bug && dwReg > 0 )
              dwReg--;
            const char *regname = print_pdb_register(g_dwMachineType, dwReg);
            fi.argloc = make_argloc(str2reg(regname), -1);
          }
        }
        else if ( locType == LocIsRegRel )
        {
          DWORD dwReg;
          LONG lOffset;
          if ( sym->get_registerId(&dwReg) == S_OK
            && sym->get_offset(&lOffset) == S_OK
            && isFrameReg(dwReg) )
          {
            fi.argloc = stack_off;
            size_t align;
            size_t argsz = get_type_size0(idati, fi.type.c_str(), &align);
            if ( align > argsz )
              argsz = align;
            stack_off += argsz;
          }
        }
        else
        {
          ask_for_feedback("pdb: unsupported location type %d", locType);
        }
      }
      return S_OK; // continue enumeration
    }
    param_enumerator_t(func_type_info_t &_args): args(_args), stack_off(0) {}
  };
  param_enumerator_t pen(args);
  for_all_children(sym, SymTagData , pen);
}

//----------------------------------------------------------------------
static bool get_symbol_type(IDiaSymbol *sym, qtype &itp, qtype *fields)
{
  IDiaSymbol *pType;
  if ( sym->get_type(&pType) != S_OK )
    return false;
  bool ok = retrieve_type(pType, itp, fields);
  pType->Release();
  return ok;
}

//----------------------------------------------------------------------
struct sdacl_info_t
{
  size_t offset;
  int alignment;
};

// >0 - member alignment, <0 - gap filler array
static int handle_gap(size_t saved, size_t off)
{
  // what if we introduce a sdacl byte?
  for ( int align=0; align <= MAX_DECL_ALIGN; align++ )
  {
    size_t copy = saved;
    align_size(copy, 1<<align);
    if ( copy == off )
      return align+1;      // found good member alignment
  }
  return int(saved - off);
}

//----------------------------------------------------------------------
struct meminfo_t : public chtype_t
{
  uval_t offset;
  uint32 size;
  int bitnum;           // for bitfields: starting bit number. otherwise 0
  uint64 width;         // in bits
  bool is_bf(void) const { return width < size*8; }
  bool operator<(const meminfo_t &r) const
  {
    return offset  < r.offset
        || offset == r.offset && bitnum < r.bitnum;
  }
  uint64 begin(void) const { return uint64(offset)*8+bitnum; }
  uint64 end(void) const { return begin()+width; }
};
typedef qvector<meminfo_t> members_t;
static cvt_code_t create_udt(members_t &mems, int udtKind, uint64 size, qtype &itp, qtype *fields);

// check if the specified alignment yields the same structure size and member
// offsets as in 'mems'. If maymodify is true, try to fix 'mems' by adding
// gap-members
static bool verify_alignment(
        members_t &mems,
        size_t total_size,
        int align,
        bool maymodify,
        intvec_t &fillers)
{
  size_t cur = 0;
  fillers.qclear();
  uval_t bf_off = BADADDR;
  int maxal = 0;
  for ( members_t::iterator p=mems.begin(); p != mems.end(); ++p )
  {
    int gap = 0;
    meminfo_t &mem = *p;
    uval_t off = mem.offset;
    if ( !mem.is_bf() || bf_off != off )  // skip bitfields
    {
      size_t alsize = 0;
      const type_t *ptr = mem.type.c_str();
      size_t size = get_type_size(idati, ptr, &alsize);
      if ( size == BADSIZE ) // get_type_size() will fails on self-pointers
        size = mem.size;
      if ( alsize == 0 )
        alsize = size;
      if ( maxal < alsize )
        maxal = alsize;
      size_t saved = cur;
      align_size(cur, alsize, align);
      if ( off > cur )
      {
        if ( !maymodify )
          return false; // there is a gap but we may not fill it
        gap = handle_gap(saved, off);
        cur = off;
      }
      if ( off != cur )
        return false;
      cur += size;
    }
    fillers.push_back(gap);
    bf_off = mem.is_bf() ? mem.offset : BADADDR;
  }
  // align up the whole structure
  int gap = 0;
  size_t saved = cur;
  align_size(cur, maxal, align);
  if ( cur < total_size )
  {
    if ( !maymodify )
      return false;
    gap = handle_gap(saved, total_size);
    cur = total_size;
  }
  fillers.push_back(gap);
  return total_size == 0 || cur == total_size;
}

//----------------------------------------------------------------------
static bool create_gap_filler(qtype &itp, qtype *fields, size_t off, int size)
{
  if ( size > 0 )
  {
    static const type_t t_byte[] = { BT_UNK_BYTE, 0 };
    qtype a2;
    if ( !build_array_type(&a2, t_byte, size) )
      return false;
    itp.append(a2);
    char name[32];
    qsnprintf(name, sizeof(name), "gap%x", off-size);
    append_name(fields, name);
  }
  return true;
}

//----------------------------------------------------------------------
static cvt_code_t create_udt_ref(members_t &mems, int udtKind, qtype &itp)
{
  qtype type, fields;
  cvt_code_t code = create_udt(mems, udtKind, 0, type, &fields);
  if ( code != cvt_ok )
    return code;

  char name[MAXNAMELEN];
  build_anon_type_name(name, sizeof(name), type.c_str(), fields.c_str());
  uint32 id = get_type_ordinal(idati, name);
  if ( id == 0 )
  {
    id = alloc_type_ordinal(idati);
    if ( !set_numbered_type(idati, id, NTF_NOBASE, name, type.c_str(), fields.c_str()) )
      return cvt_failed;
  }

  char buf[32];
  create_numbered_type_name(id, buf, sizeof(buf));
  itp.append(BTF_TYPEDEF);
  append_name(&itp, buf);
  return cvt_ok;
}

//----------------------------------------------------------------------
static bool is_unnnamed_tag_typedef(const type_t *ptr)
{
  char name[MAXNAMELEN];
  if ( !is_type_resolvable(ptr, name) )
    return false;

  if ( name[0] != '#' )
    return false;

  uint32 id;
  ptr = (const type_t *)name + 1;
  if ( !get_de(ptr, &id) )
    return false;

  return unnamed_types.find(id) != unnamed_types.end();
}

//----------------------------------------------------------------------
// verify unions that would be created out of [p1, p2) members.
// The [p1, p2) members are spoiled by the function.
// Create substructures if necessary. Returns the result in out (can be the same
// vector as [p1, p2)
static cvt_code_t verify_union(members_t::iterator p1,  members_t::iterator p2, members_t &out)
{
  QASSERT(30163, p2 > p1);
  int off = p1->offset;
  typedef qvector<members_t> stems_t;
  stems_t stems; // each stem is a member of the future union
  for ( members_t::iterator q=p1; q != p2; ++q )
  {
    members_t *best = NULL;
    q->offset -= off;
    if ( q->offset != 0 )
    { // find best suited stem: the one with end() closest to our offset
      uint64 bestend = uint64(-1);
      for ( stems_t::iterator s=stems.begin(); s != stems.end(); ++s )
      {
        members_t &sm = *s;
        uint64 smend = sm[sm.size()-1].end();
        if ( smend <= q->begin() && (best == NULL || bestend < smend) )
        {
          best = &sm;
          bestend = smend;
        }
      }
    }
    if ( best == NULL )
      best = &stems.push_back();
    qswap(best->push_back(), *q);
  }

  // all non-trivial stems must be converted to structures
  for ( stems_t::iterator s=stems.begin(); s != stems.end(); ++s )
  {
    if ( s->size() == 1 && s->begin()->offset == 0 )
      continue;
    qtype type;
    cvt_code_t code = create_udt_ref(*s, UdtStruct, type);
    if ( code != cvt_ok )
      return code;
    s->resize(1);
    meminfo_t &sm = *s->begin();
    sm.offset = 0;
    sm.size = get_type_size0(idati, type.c_str());
    sm.width = sm.size*8;
    sm.bitnum = 0;
    sm.name.sprnt("_s%d", s-stems.begin());
    sm.type.swap(type);
    sm.fields.clear();
  }

  // collect the results
  out.resize(stems.size());
  for ( int i=0; i < stems.size(); i++ )
  {
    QASSERT(30164, stems[i].size() == 1);
    qswap(out[i], *stems[i].begin());
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
// create a union out of [p1, p2) members. they are spoiled by the function.
// returns type of the new union and its fields
// this function also creates substructures if necessary
static cvt_code_t create_union(members_t::iterator p1,  members_t::iterator p2, qtype &itp)
{
  members_t unimems;
  cvt_code_t code = verify_union(p1, p2, unimems);
  if ( code != cvt_ok )
    return code;
  return create_udt_ref(unimems, UdtUnion, itp);
}

//----------------------------------------------------------------------
// Since the kernel does not support bitfields, we have to replace them
// by simple data types
static void remove_bitfields(members_t &mems)
{
  uval_t bfoff = BADADDR;
  int bfsize = 0;
  for ( members_t::iterator p=mems.begin(); ; )
  {
    if ( p != mems.end() )
    {
      if ( p->is_bf() )
      {
        bfoff = p->offset;
        bfsize = p->size;
        int idx = p - mems.begin();
        mems.erase(p);
        p = mems.begin() + idx;
        continue;
      }
    }
    if ( bfoff != BADADDR )
    {
      // do we have another element of this offset/size?
      bool found = false;
      for ( members_t::iterator q=mems.begin(); q != mems.end(); ++q )
      {
        if ( q->offset == bfoff && q->size == bfsize )
        {
          found = true;
          break;
        }
      }
      if ( !found )
      { // add a member to represent the bitfield
        meminfo_t mi;
        mi.offset = bfoff;
        mi.size = bfsize;
        mi.width = mi.size*8;
        mi.bitnum = 0;
        mi.name.sprnt("_bf%d", bfoff);
        mi.type.resize(1);
        mi.type[0] =  get_int_type_bit(mi.size);
        int idx = p - mems.begin();
        mems.insert(p, mi);
        p = mems.begin() + idx;
      }
      bfoff = BADADDR;
      continue;
    }
    if ( p == mems.end() )
      break;
    p++;
  }
  // array must stil be sorted
  int n = mems.size();
  QASSERT(30165, n>0);
  for ( int i=1; i < n; i++ )
    QASSERT(30166, mems[i-1].offset <= mems[i].offset);
}

//----------------------------------------------------------------------
// find overlapping members and convert into subunions
static cvt_code_t handle_overlapping_members(members_t &mems)
{
  qstack<qstring> union_names;
  members_t::iterator end = mems.end();
  members_t::iterator first = end; // !=end => collecting union members
  members_t::iterator last = end;  // member with highest ending offset so far
  for ( members_t::iterator p=mems.begin(); ; ++p )
  {
    if ( p != mems.end() )
    {
      if ( is_unnnamed_tag_typedef(p->type.c_str()) )
        union_names.push(p->name);
      if ( last == end )
      {
        last = p;
        continue;
      }
      if ( last->end() > p->begin() )
      {
        if ( first == end )
          first = last;
        goto NEXT;
      }
    }
    if ( first != end )
    {
      int fidx = first - mems.begin();
      uval_t off = first->offset;
      // range [first, p) is overlapping, create a new type for it
      qtype unimem;
      cvt_code_t code = create_union(first, p, unimem);
      if ( code != cvt_ok )
        return code;
      mems.erase(first+1, p);
      end = mems.end();
      first = end;
      last = end;
      p = mems.begin() + fidx;
      p->offset = off;
      p->size = get_type_size0(idati, unimem.c_str());
      p->width = p->size*8;
      p->bitnum = 0;
      if ( union_names.empty() )
        p->name.sprnt("___u%d", fidx);
      else
        p->name = union_names.pop();
      p->type.swap(unimem);
      p->fields.clear();
    }
    if ( p == end )
      break;
NEXT:
    if ( last->end() < p->end() )
      last = p;
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
// enumerate virtual functions of class sym and create a vtable structure
// with function pointers
static cvt_code_t make_vtable_struct(IDiaSymbol *sym, qtype &itp, qtype *fields)
{
  struct virtual_func_visitor_t : public children_visitor_t
  {
    members_t &mems;
    qstring &classprefix;
    virtual HRESULT visit_child(IDiaSymbol *sym)
    {
      BOOL b;
      // skip non-virtual functions
      if ( sym->get_virtual(&b) != S_OK || !b )
        return S_OK;
      DWORD offset = -1;
      if ( sym->get_virtualBaseOffset(&offset) != S_OK )
        return S_OK; // skip

      // TODO: add RVA as a comment?
      // ULONGLONG dwRVA = -1;
      // sym->get_virtualAddress(&dwRVA);

      // if this offset was used before, replace the member
      // this often happens when virtual class::~class
      // is later redefined as __vecDelDtor()
      size_t memidx = -1;
      for ( size_t i = 0; memidx == -1 && i < mems.size(); ++i )
      {
        if ( mems[i].offset == offset )
          memidx = i;
      }

      qstring name = get_name(sym);
      // remove 'class_name::'
      if ( !classprefix.empty() )
      {
        size_t pos = name.find(classprefix);
        if ( pos != qstring::npos )
          name.remove(pos, classprefix.length());
      }

      qtype type, fields;
      // the field is a pointer to function
      type.append(BT_PTR);
      if ( retrieve_type(sym, type, &fields) )
      {
        asize_t size = get_type_size0(idati, type.c_str());
        DWORD64 ulLen = DWORD64(size)*8;
        meminfo_t &mem = memidx == -1 ? mems.push_back() : mems[memidx];
        mem.bitnum = 0;
        mem.width = ulLen;
        mem.offset = offset;
        mem.type.swap(type);
        mem.fields.swap(fields);
        mem.name.swap(name);
        mem.size = size;
      }
      return S_OK;
    }
    virtual_func_visitor_t(members_t &m, qstring &cp) : mems(m), classprefix(cp) {}
  };

  members_t mems;
  qstring classprefix = get_name(sym);
  if ( !classprefix.empty() )
    classprefix+="::";
  virtual_func_visitor_t pp(mems, classprefix);
  for_all_children(sym, SymTagFunction, pp);
  if ( mems.empty() )
  {
    return cvt_failed;
  }
  std::sort(mems.begin(), mems.end());
  return create_udt(mems, UdtStruct, 0, itp, fields);
}

//----------------------------------------------------------------------
static const type_t fake_vtable_type[] = "$vt";
static cvt_code_t convert_udt(IDiaSymbol *sym, DWORD64 size, qtype &itp, qtype *fields)
{
  DWORD udtKind;
  if ( sym->get_udtKind(&udtKind) != S_OK )
    return cvt_failed;

  // retrieve member names, types, offsets
  struct type_name_collector_t : public children_visitor_t
  {
    members_t &mems;
    HRESULT visit_child(IDiaSymbol *sym)
    {
      DWORD dwLocType = LocIsNull;
      sym->get_locationType(&dwLocType); // may fail, must ignore

      LONG offset = 0;
      if ( sym->get_offset(&offset) != S_OK )
        return S_OK;

      qtype type, fields;
      asize_t size = get_symbol_length(sym);
      if ( retrieve_type(sym, type, &fields) )
      {
        qstring name;
        DWORD tag = SymTagNull;
        sym->get_symTag(&tag);
        if ( tag == SymTagBaseClass )
        {
          name.sprnt("baseclass_%x", offset);
        }
        else
        {
          name = get_name(sym);
          if ( tag == SymTagVTable )
          {
            if ( type == fake_vtable_type )
            {
              static const type_t t_pvoid[] = { BT_PTR, BTF_VOID, 0 };
              type = t_pvoid;
            }
            else
            {
              // type is a structure, while the field is a pointer to it
              type.insert(0, BT_PTR);
            }
            if ( name.empty() )
            {
              if ( offset == 0 )
                name = "vfptr";
              else
                name.sprnt("vfptr%x", offset);
            }
            size = get_type_size0(idati, type.c_str());
          }
        }
        DWORD64 ulLen = DWORD64(size)*8;
        DWORD dwBitPos = 0;
        if ( dwLocType == LocIsBitField )
        {
          sym->get_bitPosition(&dwBitPos);
          sym->get_length(&ulLen);
        }
        meminfo_t &mem = mems.push_back();
        mem.bitnum = dwBitPos;
        mem.width = ulLen;
        mem.offset = offset;
        mem.type.swap(type);
        mem.fields.swap(fields);
        mem.name.swap(name);
        mem.size = size;
      }
      return S_OK;
    }
    type_name_collector_t(members_t &m) : mems(m) {}
  };

  members_t mems;
  type_name_collector_t pp(mems);
  for_all_children(sym, SymTagNull, pp);
  if ( mems.empty() && size > 0 ) // add a dummy character array
  {
    static const type_t t_char[] = { BT_INT8|BTMT_CHAR, 0 };
    meminfo_t &m = mems.push_back();
    m.name = "dummy";
    build_array_type(&m.type, t_char, size);
    m.offset = 0;
    m.size = size;
    m.bitnum = 0;
    m.width = 8 * size;
  }
  if ( mems.empty() )
  {
    itp.append(udtKind == UdtUnion ? BTF_UNION : BTF_STRUCT);
    append_dt(&itp, 0);
    append_name(&itp, get_type_name(sym).c_str());
    return cvt_typedef;
  }

  std::stable_sort(mems.begin(), mems.end());
  remove_bitfields(mems);
  return create_udt(mems, udtKind, size, itp, fields);
}

//----------------------------------------------------------------------
static void append_member_type(qtype *itp, const meminfo_t &mem)
{
  type_t typebuf[8];
  const type_t *mt;
  if ( mem.is_bf() )
  {
    int bit;
    switch ( mem.size )
    {
      default: ask_for_feedback("Unsupported bitfield size %d", mem.size);
      case 1: bit = BTMT_BFLDI8;  break;
      case 2: bit = BTMT_BFLDI16; break;
      case 4: bit = BTMT_BFLDI32; break;
      case 8: bit = BTMT_BFLDI64; break;
    }
    type_t *p = typebuf;
    *p++ = BT_BITFIELD|bit;
    p = set_dt(p, (mem.width<<1) | (is_type_unsigned(idati, mem.type.c_str()) ? 1 : 0) );
    *p = '\0';
    mt = typebuf;
  }
  else
  {
    mt = mem.type.c_str();
    // can not check it here because not all types are saved to the database
    // some referenced types are being built...
    //int size = get_type_size0(idati, mt);
    //QASSERT(30167, size > 0 || size == 0 && is_restype_array(idati, mt));
  }
  itp->append(mt);
}

//----------------------------------------------------------------------
static cvt_code_t create_udt(members_t &mems, int udtKind, uint64 size, qtype &itp, qtype *fields)
{
  cvt_code_t code;
  if ( udtKind == UdtUnion )
  {
    code = verify_union(mems.begin(), mems.end(), mems);
    if ( code == cvt_ok )
    {
      itp.append(BTF_UNION);
      append_dt(&itp, mems.size() << 3);
      for ( members_t::iterator p=mems.begin(); p != mems.end(); ++p )
      {
        append_member_type(&itp, *p);
        if ( fields != NULL )
        {
          append_name(fields, p->name.c_str());
          fields->append(p->fields);
        }
      }
    }
    return code;
  }

  // find overlapping members and convert into subunions (anonymous union would be great)
  code = handle_overlapping_members(mems);
  if ( code != cvt_ok )
    return code;

  // verify gaps and add padding of alignment directives if necessary
  bool gaps_ok;
  intvec_t fillers; // >0:alignment:1<<(x-1); <0:gap size; 0-no filler
  int pragma_align = 0;
  for ( bool maymodify=false; ; maymodify=true )
  {
    int defal = (int)get_default_align(0);
    gaps_ok = verify_alignment(mems, (size_t)size, defal, maymodify, fillers);
    if ( !gaps_ok )
    {
      for ( int align=0; align < 7; align++ )
      {
        gaps_ok = verify_alignment(mems, (size_t)size, 1<<align, maymodify, fillers);
        if ( gaps_ok )
        {
          pragma_align = align + 1;
          break;
        }
      }
    }
    if ( gaps_ok || maymodify )
      break;
  }
  if ( !gaps_ok )
    return cvt_failed;

  // count number of filler arrays we will introduce
  int gaps = 0;
  for ( int i=0; i < fillers.size(); i++ )
    if ( fillers[i] < 0 )
      gaps++;

  itp.append(BTF_STRUCT);
  append_dt(&itp, int(((gaps+mems.size()) << 3) | pragma_align));

  // add sdacl byte for the whole structure
  int align = fillers.back();
  if ( align > 0 )
  {
    char sdacl = (char)sdacl_pack(align-1);
    itp.append(sdacl);
  }

  intvec_t::iterator q = fillers.begin();
  for ( members_t::iterator p=mems.begin(); p != mems.end(); ++p,++q )
  {
    meminfo_t &mem = *p;
    uint32 off = mem.offset;
    int align = *q;
    if ( align < 0 )  // we need a gap filler
    {
      if ( !create_gap_filler(itp, fields, off, -align) )
        return cvt_failed;
    }
    append_member_type(&itp, mem);
    if ( align > 0 )  // we need an alignment sdacl byte
    {
      char sdacl = (char)sdacl_pack(align-1);
      itp.append(sdacl);
    }
    if ( fields != NULL )
    {
      append_name(fields, mem.name.c_str());
      fields->append(mem.fields);
    }
  }
  // add final gap filler if necessary
  align = fillers.back();
  if ( align < 0 )
  {
    if ( !create_gap_filler(itp, fields, (size_t)size, -align) )
      return cvt_failed;
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
// is the return type complex?
// if so, a pointer to return value will be passed as a hidden parameter
static bool is_complex_return(IDiaSymbol *sym)
{
  IDiaSymbol *pType;
  bool complex = false;
  if ( SUCCEEDED(sym->get_type(&pType)) )
  {
    DWORD tag;
    complex = SUCCEEDED(pType->get_symTag(&tag)) && tag == SymTagUDT;
    if ( complex )
    {
      BSTR Name;
      pType->get_name(&Name);
      ULONGLONG size;
      complex = SUCCEEDED(pType->get_length(&size)) && size > 8;
      SysFreeString(Name);
    }
    if ( !complex && tag == SymTagUDT )
    {
      // we've got a small UDT which possibly fits into a register (or two)
      // but it has to be a POD for that, i.e. should have no constructor or assignment operators
      BOOL b;
      if ( SUCCEEDED(pType->get_constructor(&b)) && b
        || SUCCEEDED(pType->get_hasAssignmentOperator(&b)) && b
        || SUCCEEDED(pType->get_hasCastOperator(&b)) && b )
        complex = true;
    }
    pType->Release();
  }
  return complex;
}

//----------------------------------------------------------------------
static cvt_code_t really_convert_type(IDiaSymbol *sym, DWORD tag, qtype &itp, qtype *fields, IDiaSymbol *parentSym)
{
  // retrieve type modifiers
  size_t modidx = itp.length();
  type_t mods = 0;
  BOOL bSet;
  if ( sym->get_constType(&bSet) == S_OK && bSet )
    mods |= BTM_CONST;

  if ( sym->get_volatileType(&bSet) == S_OK && bSet )
    mods |= BTM_VOLATILE;

//  bool unaligned = sym->get_unalignedType(&bSet) == S_OK && bSet;

  DWORD64 size = 0;
  sym->get_length(&size);
  DWORD bt, count;
  cvt_code_t code = cvt_ok;
  switch ( tag )
  {
    default:
    case SymTagNull:
      deb(IDA_DEBUG_PLUGIN, "unsupported tag %s\n", print_symtag(tag));
      return cvt_failed;

    case SymTagBaseType:
      if ( sym->get_baseType(&bt) != S_OK )
        return cvt_failed;
      code = append_basetype(bt, int(size), itp);
      if ( code == cvt_failed )
        return cvt_failed;
      break;

    case SymTagPointerType:
      {
        int init = itp.length();
        itp.append(BT_PTR);
        if ( !get_symbol_type(sym, itp, fields) )
        {
          itp.resize(init);
          return cvt_failed;
        }
      }
      break;

    case SymTagArrayType:
      {
        qtype a2, t2;
        if ( !get_symbol_type(sym, t2, NULL) )
          return cvt_failed;
        t2[0] |= mods;  // propagate type modifiers to the element type

        if ( sym->get_count(&count) != S_OK )
          return cvt_failed;
        if ( !build_array_type(&a2, t2.c_str(), count) )
          return cvt_failed;
        itp.append(a2);
      }
      break;

    case SymTagFunctionType:
      {
        func_type_info_t fi;
        DWORD cc0;
        fi.cc = CM_CC_UNKNOWN;
        if ( sym->get_callingConvention(&cc0) == S_OK )
          fi.cc = convert_cc(cc0);
        if ( !get_symbol_type(sym, fi.rettype, &fi.retfields) ) // return type
          return cvt_failed;

        if ( get_cc(fi.cc) != CM_CC_VOIDARG )
        {
          retrieve_children_types_names(sym, fi, parentSym);
          // last arg unknown/invalid argument => convert to ellipsis
          if ( get_cc(fi.cc) == CM_CC_CDECL && !fi.empty() && fi.back().type.empty() )
          {
            fi.pop_back();
            fi.cc = CM_CC_ELLIPSIS;
          }
          // is there an implicit "result" pointer passed?
          if ( is_complex_return(sym) )
          {
            // complex return type: what's returned is actually a pointer
            fi.rettype.insert(0, BT_PTR);
            funcarg_info_t retarg;
            retarg.type = fi.rettype;
            retarg.fields = fi.retfields;
            retarg.name = "result";
            fi.insert(fi.begin(), retarg);
          }
          // is there an implicit "this" passed?
          // N.B.: 'this' is passed before the implicit result, if both are present
          qtype owner, ofields;
          if ( is_member_func(sym, owner, &ofields, parentSym) )
          {
            owner.insert(0, BT_PTR);
            funcarg_info_t thisarg;
            thisarg.type = owner;
            thisarg.fields = ofields;
            thisarg.name = "this";
            fi.insert(fi.begin(), thisarg);
          }
          if ( is_user_cc(fi.cc) )
          {
            // specify argloc for the return value
            size_t size = get_type_size0(idati, fi.rettype.c_str());
            if ( size <= 1 )
                fi.retloc = make_argloc(R_al, -1);
            else if ( size <= 4 )
                fi.retloc = make_argloc(R_ax, -1);
            else
                fi.retloc = make_argloc(R_ax, R_dx);
          }
          qtype ftype, ffields;
          if ( build_func_type(&ftype, &ffields, fi) )
          {
            itp.append(ftype);
            if ( fields != NULL )
              fields->append(ffields);
          }
          else
          {
            return cvt_failed;
          }
        }
      }
      break;

    case SymTagUDT:
    case SymTagBaseClass:
      code = convert_udt(sym, size, itp, fields);
      break;
    case SymTagEnum:
      {
        struct name_value_collector_t : public children_visitor_t
        {
          const type_t *idatype;
          qstrvec_t names;
          qvector<uval_t> values;
          HRESULT visit_child(IDiaSymbol *sym)
          {
            qstring &name = names.push_back();
            name = get_name(sym);
            uint32 value = get_long_value(sym);
            values.push_back(value);
            if ( get_named_type(idati, name.c_str(), NTF_SYMM, &idatype) )
              return E_FAIL;
            return S_OK;
          }
        };
        name_value_collector_t nvc;
        HRESULT hr = for_all_children(sym, SymTagNull, nvc);
        if ( FAILED(hr) )               // symbol already exists?
        {                               // just reuse the existing enum
          itp.append(nvc.idatype);      // this is not totally correct
          const type_t *p = nvc.idatype;// but ok for the current version
          if ( is_type_typedef(*p++) && get_dt(p) > 0 && get_type_name(sym) == (char*)p )
            return cvt_typedef;         // avoid circular dependencies
          return cvt_ok;
        }
        if ( nvc.values.empty() )
        { // ida does not support enum declarations without any members
          // create a dummy member
          qstring &name = nvc.names.push_back();
          name = get_name(sym);
          name.append("_dummy");
          nvc.values.push_back(0);
        }
        itp.append(BTF_ENUM);
        append_dt(&itp, (int)nvc.values.size());
        itp.append(BTE_ALWAYS);
        uint32 v = 0;
        for ( int i=0; i < nvc.values.size(); i++ )
        {
          uint32 v2 = (uint32)nvc.values[i];
          append_de(&itp, v2-v);
          v = v2;
          if ( fields != NULL )
            append_name(fields, nvc.names[i].c_str());
        }
      }
      break;

    case SymTagTypedef:
    case SymTagFunctionArgType:
    case SymTagFunction:
    case SymTagData:
      {
        int idx = itp.length();
        if ( !get_symbol_type(sym, itp, fields) )
          return cvt_failed;
        if ( is_type_typedef(itp[idx]) )
          code = cvt_typedef; // signal that this is a typedef
      }
      break;
    case SymTagVTable:
      {
        int idx = itp.length();
        IDiaSymbol *pClass;
        if ( sym->get_classParent(&pClass) != S_OK
          || make_vtable_struct(pClass, itp, fields) != cvt_ok )
        {
          itp.resize(idx);
          itp.append(fake_vtable_type);
        }
        pClass->Release();
      }
      break;
  }
  if ( mods != 0 )
    itp[modidx] |= mods;
  // todo: check that the type has the expected size
  return code;
}

//----------------------------------------------------------------------
static cvt_code_t convert_type(IDiaSymbol *sym, DWORD type, DWORD tag, qtype &itp, qtype *fields)
{
  typemap_t::iterator p = typemap.find(type);
  if ( p == typemap.end() )
  {
    tpinfo_t ti;
    ti.cvt_code = really_convert_type(sym, tag, ti.type, &ti.fields);
//    msg("cvt_type %d code %d: %s\n", type, ti.cvt_code, ti.dstr());
    p = typemap.insert(std::make_pair(type, ti)).first;
  }
  tpinfo_t &ti = p->second;
  itp.append(ti.type);
  if ( fields != NULL )
    fields->append(ti.fields);
  return ti.cvt_code;
}

//----------------------------------------------------------------------
typedef std::map<qstring, int> creating_t;
static creating_t creating;
static int unnamed_idx;

static uint32 begin_creation(DWORD tag, const qstring &name)
{
  if ( tag != SymTagFunction )
  {
    creating_t::iterator c = creating.find(name);
    if ( c != creating.end() ) // recursive call
    {
      if ( !c->second )        // allocated?
      {
        c->second = alloc_type_ordinal(idati); // have to create the type id immediately
//        msg("%d %s: prematurely mapped to %d\n", type, name.c_str(), c->second);
      }
      return c->second;
    }
    creating.insert(std::make_pair(name, 0)); // add to the 'creating' list
  }
  return 0;
}

static uint32 end_creation(const qstring &name)
{
  uint32 id = 0;
  creating_t::iterator c = creating.find(name);
  if ( c != creating.end() )
  {
    id = c->second;
    creating.erase(c);
  }
  if ( id == 0 )
  {
    id = alloc_type_ordinal(idati); // have to create the type id immediately
//    msg("%d %s: mapped to %d\n", type, name.c_str(), id);
  }
  return id;
}

//----------------------------------------------------------------------
static bool retrieve_type(IDiaSymbol *sym, qtype &itp, qtype *fields)
{
  DWORD type;
  HRESULT hr = sym->get_symIndexId(&type);
  if ( FAILED(hr) )
    return false;

  // id -> unknown typedef?
  tpdefs_t::iterator q = tpdefs.find(type);
  if ( q != tpdefs.end() )
  {
    itp.append(BTF_TYPEDEF);
    append_name(&itp, q->second.c_str());
    return true;
  }

  uint32 id = idmap[type];
  if ( id == 0 )
  {
    DWORD tag;
    hr = sym->get_symTag(&tag);
    if ( FAILED(hr) )
      return false;

    bool is_unnamed;
    qstring ns = get_type_name(sym, &is_unnamed);

    if ( tag == SymTagVTable && ns.empty() )
    {
      // use '<classname>Vtbl', as in OLE defs (DECLARE_INTERFACE_)
      IDiaSymbol *pClass;
      if ( sym->get_classParent(&pClass) == S_OK )
        ns = get_type_name(pClass);

      if ( ns.empty() )
        ns.sprnt("vtable-%d", unnamed_idx++);
      else
        ns.append("Vtbl");

      pClass->Release();
      is_unnamed = false;
    }

    // udt fields and simple types are converted without allocating
    // an ordinal number
    if ( tag == SymTagData || ns.empty() )
      return convert_type(sym, type, tag, itp, fields) != cvt_failed;

    // give a unique name to unnamed types so they can be told apart
    // this is a temporary name, it will be replaced by $hex..
    if ( is_unnamed )
      ns.sprnt("unnamed-%d", unnamed_idx++);

    // some types can be defined multiple times. check if the name is already defined
    id = get_type_ordinal(idati, ns.c_str());
    if ( id == 0 )
    {
      id = begin_creation(tag, ns);
      if ( id == 0 )
      {
        // now convert the type information, recursive types won't bomb
        qtype t2, f2;
        cvt_code_t cc = convert_type(sym, type, tag, t2, &f2);
        if ( cc != cvt_ok ) // failed or typedef
        {
          creating.erase(ns);
          if ( cc == cvt_failed )
            return false;
          // cvt_typedef
          tpdefs[type] = ns; // reference to unknown typedef
RETT2:
          itp.append(t2);
          if ( fields != NULL )
            fields->append(f2);
          return true;
        }

        // Function types are saved as symbols
        if ( tag == SymTagFunction )
        {
          // the following may fail because of c++ overloaded functions
          // do not check the error code - we can not help it
          set_named_type(idati, ns.c_str(), NTF_SYMM, t2.c_str(), f2.c_str());
          goto RETT2;
        }

        if ( is_unnamed ) // this type will be referenced, so create a name for it
        {
          ns.resize(MAXNAMELEN-1);
          build_anon_type_name(&ns[0], ns.size(), t2.c_str(), f2.c_str());
          id = get_type_ordinal(idati, ns.c_str());
          if ( id != 0 ) // this type already exists, just reuse it
            creating.erase(ns);
        }
        if ( id == 0 )
        {
          id = end_creation(ns);
          if ( !set_numbered_type(idati, id, NTF_NOBASE,
                                  ns.empty() ? NULL : ns.c_str(),
                                  t2.c_str(),
                                  f2.c_str()) )
          {
            return 0;
          }
        }
        if ( is_unnamed )
          unnamed_types.insert(id);
      }
    }
  }
  char buf[32];
  create_numbered_type_name(id, buf, sizeof(buf));
  itp.append(BTF_TYPEDEF);
  append_name(&itp, buf);
  return true;
}

//----------------------------------------------------------------------
static HRESULT handle_types(IDiaSymbol *pGlobal)
{
  static int counter;
  struct type_importer_t : children_visitor_t
  {
    virtual HRESULT visit_child(IDiaSymbol *sym)
    {
      qtype type, fields;
      if ( retrieve_type(sym, type, &fields) )
        counter++;
      return S_OK;
    }
  };
  counter = 0;
  type_importer_t ti;
  HRESULT              hr = for_all_children(pGlobal, SymTagEnum, ti);
  if ( SUCCEEDED(hr) ) hr = for_all_children(pGlobal, SymTagUDT, ti);
  if ( SUCCEEDED(hr) ) hr = for_all_children(pGlobal, SymTagTypedef, ti);
  msg("PDB: loaded %d type%s\n", counter, counter!=1 ? "s" : "");
  return hr;
}

//----------------------------------------------------------------------
struct symbol_handler_t : children_visitor_t
{
  ea_t base;
  virtual HRESULT visit_child(IDiaSymbol *sym)
  {
    return handle_symbol(sym, base);
  }
  symbol_handler_t(ea_t b) : base(b) {}
};

static HRESULT handle_symbols(IDiaSymbol *pGlobal, ea_t base)
{
  symbol_handler_t cp(base);
  return for_all_subtags(pGlobal, SymTagNull, cp);
}

//----------------------------------------------------------------------
static HRESULT handle_publics(IDiaSymbol *pGlobal, ea_t base)
{
  symbol_handler_t cp(base);
  return for_all_children(pGlobal, SymTagPublicSymbol, cp);
}

//----------------------------------------------------------------------
static HRESULT handler(
        IDiaDataSource * /*pSource*/,
        IDiaSession *pSession,
        IDiaSymbol *pGlobal,
        int machine_type,
        int dia_version,
        void *)
{
  g_dwMachineType = machine_type;
  g_diaVersion = dia_version;

  load_vc_til();

  DWORD64 load_addr;
  pSession->get_loadAddress(&load_addr);
  ea_t loaded_base = ea_t(load_addr);

  HRESULT hr = handle_types(pGlobal);
  if ( SUCCEEDED(hr) )
    hr = handle_symbols(pGlobal, loaded_base);
  if ( SUCCEEDED(hr) )
    hr = handle_publics(pGlobal, loaded_base);

  typemap.clear();
  idmap.clear();
  tpdefs.clear();
  handled.clear();
  creating.clear();

  return hr;
}

#endif

//----------------------------------------------------------------------
void load_vc_til(void)
{
  // We managed to load the PDB file.
  // It is very probably that the file comes from VC
  // Load the corresponding type library immediately
  if ( ph.id == PLFM_386 && pe.signature == PEEXE_ID )
  {
    if ( pe.is_userland() )
      add_til2(pe.is_pe_plus() ? "vc8amd64" : "mssdk", ADDTIL_INCOMP);
    else
      add_til2(pe.is_pe_plus() ? "ntddk64" : "ntddk",  ADDTIL_INCOMP);
  }
}

/*//////////////////////////////////////////////////////////////////////
                      IDA PRO INTERFACE START HERE
//////////////////////////////////////////////////////////////////////*/

//--------------------------------------------------------------------------
// terminate
void idaapi term(void)
{
  namelist.clear();
#ifndef REMOTEPDB
  longnames.clear();
#endif
}

//--------------------------------------------------------------------------
// callback for parsing config file
const char *idaapi parse_options(
        const char *keyword,
        int value_type,
        const void *value)
{
  if ( strcmp(keyword, "PDB_REMOTE_PORT") == 0 )
  {
    if ( value_type != IDPOPT_NUM )
      return IDPOPT_BADTYPE;
    uval_t val = *(uval_t*)value;
    if ( val == 0 || val > 65535 )
      return IDPOPT_BADVALUE;
    pdb_remote_port = int(val);
    return IDPOPT_OK;
  }

  if ( value_type != IDPOPT_STR )
    return IDPOPT_BADTYPE;

  if ( strcmp(keyword, "PDBSYM_DOWNLOAD_PATH") == 0 )
  {
    qstrncpy(download_path, (const char *)value, sizeof(download_path));
    // empty string used for ida program directory
    if ( download_path[0] != '\0' && !qisdir(download_path) )
      return IDPOPT_BADVALUE;
  }
  else if ( strcmp(keyword, "PDBSYM_SYMPATH") == 0 )
  {
    qstrncpy(full_sympath, (const char *)value, sizeof(full_sympath));
    return IDPOPT_OK;
  }
  else if ( strcmp(keyword, "PDB_REMOTE_SERVER") == 0 )
  {
    qstrncpy(pdb_remote_server, (const char *)value, sizeof(pdb_remote_server));
    // empty string used for ida program directory
    if ( pdb_remote_server[0] == '\0' )
      return IDPOPT_BADVALUE;
  }
  else if ( strcmp(keyword, "PDB_REMOTE_PASSWD") == 0 )
  {
    qstrncpy(pdb_remote_passwd, (const char *)value, sizeof(pdb_remote_passwd));
    // empty string used for ida program directory
    if ( pdb_remote_server[0] == '\0' )
      return IDPOPT_BADVALUE;
  }
  else
  {
    return IDPOPT_BADKEY;
  }


  return IDPOPT_OK;
}

#ifdef REMOTEPDB
//----------------------------------------------------------------------
static void apply_symbol(til_t *ti, ea_t ea, const char *name, int ord)// const type_t *type, const p_list *fields)
{
  int maybe_func = 0; // maybe

  // symbols starting with __imp__ can not be functions
  if ( name != NULL && strncmp(name, "__imp__", 7) == 0 )
  {
    doDwrd(ea, 4);
    maybe_func = -1;
  }
  if ( ord != -1 )
  {
    const type_t *type = NULL;
    const p_list *fields = NULL;
    get_numbered_type(ti, ord, &type, &fields);
    if ( type != NULL && is_restype_func(ti, type) )
    {
      maybe_func = 1;
    }
    else
    {
      maybe_func = -1;
    }
    bool no_ti = false;
    if ( maybe_func == 1 )
    {
      const type_t *t2 = type;
      qtype ret;
      cm_t cc;
      int n = get_func_rettype(ti, &t2, NULL, &ret, NULL, NULL, &cc);
      // sometimes there are functions with linked FunctionType but no parameter or return type info in it
      // we get better results by not forcing type info on them
      no_ti = n == 0 && ret.length() == 1 && is_type_void(ret[0]);
    }
    if ( !no_ti )
    {
      if ( maybe_func != 1 )
      {
        // use typedef for global items
        qtype itp;
        char buf[32];
        create_numbered_type_name(ord, buf, sizeof(buf));
        itp.append(BTF_TYPEDEF);
        append_name(&itp, buf);
        apply_tinfo(ti, ea, itp.c_str(), NULL, true);
      }
      else
      {
        apply_tinfo(ti, ea, type, fields, true);
      }
    }
  }
  if ( maybe_func > 0 )
    auto_make_proc(ea); // certainly a func
  if ( name != NULL )
    apply_name(ea, name, maybe_func);
}

//----------------------------------------------------------------------
static void import_til(til_t *to, const char *tilfilename, ea_t baseea, bool do_symbols)
{
  char errbuf[MAXSTR];
  til_t *from = load_til(NULL, tilfilename, errbuf, sizeof(errbuf));
  if ( from == NULL )
  {
    warning("Error loading '%s': %s", tilfilename, errbuf);
    return;
  }
  symbol_stream_t syms;
  if ( merge_til(to, from, NTF_SYMM|NTF_TYPE, do_symbols ? &syms : NULL) == 0 )
  {
    warning("Error importing symbols from '%s'", tilfilename);
    return;
  }
  free_til(from);
  if ( do_symbols )
  {
    const char *name;
    for ( til_gen_symbols_t::const_iterator i = syms.symbols.begin(); i != syms.symbols.end(); ++i )
    {
      const til_gen_symbol_t &sym = *i;
      if ( sym.addr == 0 )
        continue;
      if ( sym.name.empty() && sym.type_ord == -1 )
        continue;
      name = sym.name.c_str();
      if ( sym.type_ord != -1 && name[0] == '\0' )
        name = get_numbered_type_name(to, sym.type_ord);
      apply_symbol(to, sym.addr + baseea, name, sym.type_ord);
    }
  }
}

//----------------------------------------------------------------------
// load and connect to a remote win32 debugger, if necessary
static bool load_win32_debugger(bool *was_connected)
{
  *was_connected = false;
  if ( dbg != NULL && (!dbg->is_remote() || strcmp(dbg->name, "win32") != 0) )
  {
    // a debugger is loaded, but it's not a remote win32
    warning("Loading PDB symbols requires a remote win32 debugger. Please stop the current debugging session and try again.");
    return false;
  }
  if ( get_process_state() != DSTATE_NOTASK )
  {
    // the debugger is already connected
    *was_connected = true;
    return true;
  }
  if ( !load_debugger("win32", true) || dbg == NULL )
  {
    warning("Could not load remote Win32 debugger.");
    return false;
  }

  if ( pdb_remote_server[0] == '\0' )
  {
    qstrncpy(pdb_remote_server, "localhost", sizeof(pdb_remote_server));
  }
  while ( !dbg->init_debugger(pdb_remote_server, pdb_remote_port, pdb_remote_passwd) )
  {
    if ( batch ) // avoid endless (and useless) loop in batch mode
      return false;
    // hrw
    static const char formstr[] =
      "Remote PDB server\n"
      "Could not connect to the Win32 remote debugger at the specified address.\n"
      "Please make sure that win32_remote.exe is running there.\n\n"
      "<#Name of the remote host#~H~ostname :A:1023:30::> <#Remote port number#Po~r~t:D:256:8::>\n"
      "<#Password for the remote host#Pass~w~ord :A:1023:30::>\n"
      "Hint: to change this permanently, edit pdb.cfg.\n\n";
    sval_t port = pdb_remote_port;
    int r = AskUsingForm_c(formstr, pdb_remote_server, &port, pdb_remote_passwd);
    if ( r != 1 )
      return false;
    pdb_remote_port = port;
  }
  return true;
}
#endif

//----------------------------------------------------------------------
// Main function: do the real job here
void idaapi run(int _call_code)
{
  ea_t loaded_base;
  char input_path[QMAXPATH];
  sval_t types_only = inf.filetype != f_PE && !is_miniidb();
  bool was_load_error = false;
  bool verbose = false;

  netnode pdbnode;
  pdbnode.create(PDB_NODE_NAME);

  netnode penode(PE_NODE);
  penode.valobj(&pe, sizeof(pe));

  bool ok = true;

  call_code = (PDB_CALLCODE)_call_code;
  // loading additional dll?
  if ( call_code == PDB_CC_ADDITIONAL )
  {
    loaded_base = pdbnode.altval(PDB_DLLBASE_NODE_IDX);
    pdbnode.supstr(PDB_DLLNAME_NODE_IDX, input_path, sizeof(input_path));
    QASSERT(30168, loaded_base != 0);
    PLUGIN.flags &= ~PLUGIN_UNL;
  }
  else
  {
    loaded_base = penode.altval(PE_ALT_IMAGEBASE);
    get_input_file_path(input_path, sizeof(input_path));

    if ( pdbnode.alt1st() != BADNODE ) // pdb plugin has been run at least once
    {
      // user explicitly invoked the plugin?
      if ( call_code == PDB_CC_USER )
        verbose = true;
    }
    if ( verbose || !qfileexist(input_path) )
    {
      verbose = true;
INTERACTIVE:
      static const char form[] =
        "Load PDB file\n"
        "<#Specify the path to the file to load symbols for#Input file:f:0:64::>\n"
        "<#Specify the loading address of the exe/dll file#Address:N:64:64::>\n"
        "<#Load only types, do not rename program locations#Types only:C::::>>\n"
        "\n";
      if ( !AskUsingForm_c(form, input_path, &loaded_base, &types_only) )
        return;
    }

    static const char question[] = "AUTOHIDE REGISTRY\nHIDECANCEL\n"
      "IDA Pro has determined that the input file was linked with debug information.\n"
      "Do you want to look for the corresponding PDB file at the local symbol store\n"
      "and the Microsoft Symbol Server?\n";
    if ( call_code == PDB_CC_IDA && askyn_c(1, question) <= 0 )
      return;
  }

  // user specified symbol path?
  download_path[0] = '\0';
  full_sympath[0] = '\0';
  read_user_config_file("pdb", parse_options);

  const char *spath = NULL;
  // if download path is set, then let us format the path
  if ( full_sympath[0] == '\0' && download_path[0] != '\0' )
    qsnprintf(full_sympath, sizeof(full_sympath), "%s%s%s", spath_prefix, download_path, spath_suffix);

  if ( full_sympath[0] != '\0' )
    spath = full_sympath;

#ifndef REMOTEPDB
  HRESULT hr = handle_pdb_file(
    input_path,
    spath,
    handler,
    loaded_base);

  if ( FAILED(hr) )
  {
    msg("PDB: could not process file %s with DIA: %s\n", input_path, pdberr(hr));

    // DIA interface failed, try the old methods
    ok = old_pdb_plugin(loaded_base, input_path, spath);
    if ( ok )
      msg("Old method of loading PDB files (dbghelp) was successful\n");
    else if ( !was_load_error && verbose )
    {
      was_load_error = true;
      goto INTERACTIVE;
    }
  }
#else
  bool was_connected;
  if ( load_win32_debugger(&was_connected) )
  {
    char errbuf[MAXSTR];
    char tilfname[MAXSTR];
    qtmpnam(tilfname, sizeof(tilfname));
    set_file_ext(tilfname, sizeof(tilfname), tilfname, "til");
    errbuf[0] = '\0';
    int rc = ph.notify(processor_t::til_for_file, loaded_base, input_path, tilfname, download_path, spath, errbuf, sizeof(errbuf));
    if ( !was_connected )
      dbg->term_debugger();
    if ( rc < 2 )
    {
      warning("Symbol fetching is not supported by the remote Win32 debugger.");
      ok = false;
    }
    else if ( rc != 2 )
    {
      warning("Error fetching symbols from remote server: %s", errbuf);
      ok = false;
      if ( !was_load_error && verbose )
      {
        was_load_error = true;
        goto INTERACTIVE;
      }
    }
    else
    {
      msg("Successfully retrieved symbols from remote server\n");
      import_til(idati, tilfname, loaded_base, !types_only);
      unlink(tilfname);
      ok = true;
    }
  }
#endif
  if ( ok && !types_only )
  {
    // Now all information is loaded into the database (except names)
    // We are ready to use names.
    int counter = 0;
    for ( namelist_t::iterator p=namelist.begin(); p != namelist.end(); ++p )
    {
      if ( call_code == PDB_CC_ADDITIONAL )
        counter += set_debug_name(p->first, p->second.c_str());
      else
        counter += do_name_anyway(p->first, p->second.c_str());
    }
    namelist.clear();
    msg("PDB: total %d symbol%s loaded for %s\n", counter, counter!=1 ? "s" : "", input_path);
  }

  pdbnode.altset(PDB_DLLBASE_NODE_IDX, ok);
}

//--------------------------------------------------------------------------
// initialize plugin
int idaapi init(void)
{
  const char *opts = get_plugin_options("pdb");
  if ( opts != NULL && strcmp(opts, "off") == 0 )
    return PLUGIN_SKIP;

  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_HIDE, // plugin flags:
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,          // invoke plugin

  // long comment about the plugin
  // it could appear in the status line
  // or as a hint
  "Load debug information from a PDB file",

  // multiline help about the plugin
  "PDB file loader\n"
  "\n"
  "This module allows you to load debug information about function names\n"
  "from a PDB file.\n"
  "\n"
  "The PDB file should be in the same directory as the input file\n",

  // the preferred short name of the plugin
  "Load PDB file (dbghelp 4.1+)",
  // the preferred hotkey to run the plugin
  ""
};

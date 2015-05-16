/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Structure type management
 *
 */

#ifndef _STRUCT_HPP
#define _STRUCT_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

#include <stdio.h>

#include <bytes.hpp>

#define STRUC_SEPARATOR '.'     // structname.fieldname

struct til_t;

//--------------------------------------------------------------------------
// struct, union

void            init_structs(void);
inline void     save_structs(void) {}
void            term_structs(void);

class member_t
{
public:
  tid_t id;             // name(), cmt, rptcmt
  ea_t soff;            // start offset (for unions - number of the member 0..n)
  ea_t eoff;            // end offset
  flags_t flag;         // type, representation, look strid(id)
//private:
  uint32 props;         // properties:
#define MF_OK     0x00000001    // is the member ok? (always yes)
#define MF_UNIMEM 0x00000002    // is a member of a union?
#define MF_HASUNI 0x00000004    // has members of type "union"?
#define MF_BYTIL  0x00000008    // the member was created due to the type system
#define MF_HASTI  0x00000010    // has type information?
  bool unimem(void)    const { return (props & MF_UNIMEM) != 0; }
  bool has_union(void) const { return (props & MF_HASUNI) != 0; }
  bool by_til(void)    const { return (props & MF_BYTIL)  != 0; }
  bool has_ti(void)    const { return (props & MF_HASTI)  != 0; }
  ea_t get_soff(void) const { return unimem() ? 0 : soff; }
};

class struc_t           // kept as a blob
{
public:
  tid_t id;             // name(), cmt, rptcmt
  size_t memqty;
  member_t *members;    // only defined members are kept
                        // there may be holes in the structure
                        // the displayer must show the holes too
  ushort age;
  uint32 props;         // properties:
#define SF_VAR    0x00000001    // is variable size structure (varstruct)?
                                // a variable size structure is one with
                                // the zero size last member
                                // If the last member is a varstruct, then the current
                                // structure is a varstruct too.
#define SF_UNION  0x00000002    // is a union?
                                // varunions are prohibited!
#define SF_HASUNI 0x00000004    // has members of type "union"?
#define SF_NOLIST 0x00000008    // don't include in the chooser list
#define SF_TYPLIB 0x00000010    // the structure comes from type library
#define SF_HIDDEN 0x00000020    // the structure is collapsed
#define SF_FRAME  0x00000040    // the structure is a function frame
  bool is_varstr(void)    const { return (props & SF_VAR)    != 0; }
  bool is_union(void)     const { return (props & SF_UNION)  != 0; }
  bool has_union(void)    const { return (props & SF_HASUNI) != 0; }
  bool is_choosable(void) const { return (props & SF_NOLIST) == 0; }
  bool from_til(void)     const { return (props & SF_TYPLIB) != 0; }
  bool is_hidden(void)    const { return (props & SF_HIDDEN) != 0; }
  mutable int32 ordinal;        // corresponding local type ordinal number
};

// queries

idaman size_t ida_export get_struc_qty(void);
idaman uval_t ida_export get_first_struc_idx(void);
idaman uval_t ida_export get_last_struc_idx(void);
inline uval_t            get_prev_struc_idx(uval_t idx) { return (idx==BADNODE) ? idx : idx - 1; }
idaman uval_t ida_export get_next_struc_idx(uval_t idx);
idaman uval_t ida_export get_struc_idx(tid_t id);        // get internal number of the structure
idaman tid_t  ida_export get_struc_by_idx(uval_t idx);   // get struct id by struct number
idaman struc_t *ida_export get_struc(tid_t id);

inline tid_t get_struc_id(const char *name)              // get struct id by name
{
  tid_t id = netnode(name);
  return get_struc(id) == NULL ? BADADDR : id;
}

inline ssize_t get_struc_name(tid_t id, char *buf, size_t bufsize) { return netnode(id).name(buf, bufsize); }
inline ssize_t get_struc_cmt(tid_t id, bool repeatable, char *buf, size_t bufsize) { return netnode(id).supstr(repeatable != 0, buf, bufsize); }
idaman asize_t ida_export get_struc_size(const struc_t *sptr);
inline asize_t get_struc_size(tid_t id) { return get_struc_size(get_struc(id)); }

// for unions soff == number of the current member
idaman ea_t ida_export get_struc_prev_offset(const struc_t *sptr, ea_t offset); // BADADDR if no prev offset
idaman ea_t ida_export get_struc_next_offset(const struc_t *sptr, ea_t offset); // BADADDR if no next offset
idaman ea_t ida_export get_struc_last_offset(const struc_t *sptr);              // BADADDR if memqty == 0
idaman ea_t ida_export get_struc_first_offset(const struc_t *sptr);             // BADADDR if memqty == 0

inline ea_t get_max_offset(struc_t *sptr)
{
  if ( sptr == NULL ) return 0; // just to avoid GPF
  return sptr->is_union()
                ? sptr->memqty
                : get_struc_size(sptr);
}

inline bool is_varstr(tid_t id)
{
  struc_t *sptr = get_struc(id);
  return sptr != NULL && sptr->is_varstr();
}

inline bool is_union(tid_t id)
{
  struc_t *sptr = get_struc(id);
  return sptr != NULL && sptr->is_union();
}

idaman struc_t  *ida_export get_member_struc(const char *fullname);
idaman struc_t  *ida_export get_sptr(const member_t *mptr);   // get child struct if member is a struct
idaman member_t *ida_export get_member(const struc_t *sptr, asize_t offset); // sptr may==0
// get a member by its name like "field44"
idaman member_t *ida_export get_member_by_name(const struc_t *sptr,const char *membername); // sptr may==0
// get a member by its fully qualified name "struct.field"
idaman member_t *ida_export get_member_by_fullname(const char *fullname,struc_t **sptr_place);
inline ssize_t idaapi get_member_fullname(tid_t mid, char *buf, size_t bufsize) { return netnode(mid).name(buf, bufsize); }
idaman ssize_t ida_export get_member_name(tid_t mid, char *buf, size_t bufsize);
inline ssize_t idaapi get_member_cmt(tid_t mid, bool repeatable, char *buf, size_t bufsize) { return netnode(mid).supstr(repeatable != 0, buf, bufsize); }
// may return 0 for the last member of varstruct
inline asize_t get_member_size(const member_t *mptr)     { return mptr->unimem() ? mptr->eoff : (mptr->eoff - mptr->soff); }

idaman bool ida_export is_varmember(const member_t *mptr);

// get member that is most likely referenced by the specified offset
// useful for offsets > sizeof(struct)
idaman member_t *ida_export get_best_fit_member(const struc_t *sptr, asize_t offset);

// get the next member idx, if it does not exist, return -1
idaman ssize_t ida_export get_next_member_idx(const struc_t *sptr, asize_t off);

// get the prev member idx, if it does not exist, return -1
idaman ssize_t ida_export get_prev_member_idx(const struc_t *sptr, asize_t off);


//--------------------------------------------------------------------------
// manipulation

// create a structure type
// if idx==BADADDR then add as the last idx
// if name==NULL then a name will be generated "struct_%d"
idaman tid_t ida_export add_struc(uval_t idx, const char *name, bool is_union=false);

idaman void ida_export del_struc(struc_t *sptr);
idaman bool ida_export set_struc_idx(const struc_t *sptr, uval_t idx);

idaman bool ida_export set_struc_name(tid_t id, const char *name);
idaman bool ida_export set_struc_cmt(tid_t id, const char *cmt, bool repeatable);

// this function returns error code (0 is ok)
idaman int ida_export add_struc_member(
                  struc_t *sptr,
                  const char *fieldname,// if NULL, then "anonymous_#" name will be generated
                  ea_t offset,          // BADADDR means add to the end of structure
                  flags_t flag,
                  const opinfo_t *mt,   // additional info about member type
                                        // must be present for:
                                        // structs, offsets, enums, strings,
                                        // struct offsets
                  asize_t nbytes);      // if nbytes == 0 then the structure
                                        // will be a varstruct.
                                        // in this case the member should be
                                        // the last member in the structure

#define STRUC_ERROR_MEMBER_OK      0    // success
#define STRUC_ERROR_MEMBER_NAME    (-1) // already has member with this name (bad name)
#define STRUC_ERROR_MEMBER_OFFSET  (-2) // already has member at this offset
#define STRUC_ERROR_MEMBER_SIZE    (-3) // bad number of bytes or bad sizeof(type)
#define STRUC_ERROR_MEMBER_TINFO   (-4) // bad typeid parameter
#define STRUC_ERROR_MEMBER_STRUCT  (-5) // bad struct id (the 1st argument)
#define STRUC_ERROR_MEMBER_UNIVAR  (-6) // unions can't have variable sized members
#define STRUC_ERROR_MEMBER_VARLAST (-7) // variable sized member should be the last member in the structure
#define STRUC_ERROR_MEMBER_NESTED  (-8) // recursive structure nesting is forbidden

idaman bool ida_export del_struc_member(struc_t *sptr, ea_t offset);

// delete members which occupy range of offsets (off1..off2)
// returns number of deleted members or -1 on error
idaman int ida_export del_struc_members(struc_t *sptr, ea_t off1, ea_t off2);

idaman bool ida_export set_member_name(struc_t *sptr, ea_t offset,const char *name);
idaman bool ida_export set_member_type(struc_t *sptr, ea_t offset, flags_t flag,const opinfo_t *mt, asize_t nbytes);
idaman bool ida_export set_member_cmt(member_t* mptr,const char *cmt,bool repeatable);
idaman bool ida_export expand_struc(struc_t *sptr, ea_t offset, adiff_t delta, bool recalc=true);
idaman void ida_export save_struc2(const struc_t *sptr, bool may_update_ltypes=true); // update struct information in the database (internal function)


// member type information

idaman bool ida_export get_member_tinfo(const member_t *mptr, qtype *buf, qtype *fields);
idaman bool ida_export del_member_tinfo(const struc_t *sptr, member_t *mptr);
idaman bool ida_export set_member_tinfo(
        const til_t *til,
        struc_t *sptr,
        member_t *mptr,
        uval_t memoff,          // offset within member
        const type_t *type,
        const p_list *fields,
        int flags);
#define SET_MEMTI_MAY_DESTROY 0x0001 // may destroy other members
#define SET_MEMTI_COMPATIBLE  0x0002 // new type must be compatible with the old
#define SET_MEMTI_FUNCARG     0x0004 // mptr is function argument (can not create arrays)
idaman bool ida_export get_or_guess_member_tinfo(const member_t *mptr, qtype *type, qtype *fields);

inline opinfo_t *retrieve_member_info(const member_t *mptr, opinfo_t *buf)
{
  if ( mptr == NULL )
    return NULL;
  return get_opinfo(mptr->id, 0, mptr->flag, buf);
}

#ifdef __BORLANDC__
#pragma option push -vi
#endif
inline bool is_anonymous_member_name(const char *name)
{
  return name == NULL
      || strncmp(name, "anonymous", 9) == 0;
}

inline bool is_dummy_member_name(const char *name)
{
  return name == NULL
      || strncmp(name, "arg_", 4) == 0
      || strncmp(name, "var_", 4) == 0
      || is_anonymous_member_name(name);
}
#ifdef __BORLANDC__
#pragma option pop
#endif

// Is a member id?
inline bool is_member_id(tid_t mid)
{
  char buf[MAXSTR];
  return get_member_fullname(mid, buf, sizeof(buf)) > 0  // member name exists
      && get_member_by_fullname(buf, NULL) != NULL;      // we can get ptr to member
}

// Is a special member with the name beginning with ' '?
idaman bool ida_export is_special_member(tid_t id);

//--------------------------------------------------------------------------
// should display a structure offset expression as the structure size?
inline bool stroff_as_size(int plen, const struc_t *sptr, asize_t value)
{
  return plen == 1
      && value > 0
      && sptr != NULL
      && !sptr->is_varstr()
      && value == get_struc_size(sptr);
}

void sync_from_struc(const struc_t *sptr); // sync structure to idati (local til)

#ifndef NO_OBSOLETE_FUNCS
idaman void ida_export save_struc(const struc_t *sptr); // update struct information in the database (internal function)
idaman bool ida_export get_or_guess_member_type(const member_t *mptr, type_t *type, size_t tsize);
idaman bool ida_export get_member_ti(const member_t *mptr, type_t *buf, size_t bufsize);
idaman bool ida_export set_member_ti(struc_t *sptr, member_t *mptr, const type_t *type, int flags);
inline bool del_ti(struc_t *sptr, member_t *mptr) { return set_member_ti(sptr, mptr, (type_t*)"", 0); }
#endif

#pragma pack(pop)
#endif // _STRUCT_HPP

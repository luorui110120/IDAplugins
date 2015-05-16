/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __MOVES_HPP
#define __MOVES_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

#include <sistack.hpp>

struct graph_location_info_t
{
  double zoom;          // zoom level, 1.0 == 100%, 0 means auto position
  double orgx;          // graph origin, x coord
  double orgy;          // graph origin, y coord
  graph_location_info_t(void) : zoom(0), orgx(0), orgy(0) {}
  bool operator == (const graph_location_info_t &r)
    { return zoom == r.zoom && orgx == r.orgx && orgy == r.orgy; }
  bool operator != (const graph_location_info_t &r)
    { return !(*this == r); }
};

#ifndef SWIG
// Helper functions. Should not be called directly!
class curloc;
class location_t;
#define DEFINE_CURLOC_HELPERS(decl) \
decl void ida_export curloc_linkTo   (curloc *, const char *stackName);\
decl void ida_export curloc_jump_push(curloc *, bool try_to_unhide, ea_t ea, int lnnum, int x, int y);\
decl bool ida_export curloc_pop      (curloc *, bool try_tohide);\
decl bool ida_export curloc_get      (curloc *, size_t depth);\
decl int  ida_export curloc_mark     (curloc *, int marker,const char *title, const char *desc);\
decl ea_t ida_export curloc_markedpos(curloc *, int *marker);\
decl bool ida_export curloc_jump     (curloc *, int marker);\
decl ssize_t ida_export curloc_markdesc(curloc *, int marker, char *buf, size_t bufsize);

#define DEFINE_LOCATION_HELPERS(decl) \
decl void ida_export location_linkTo   (location_t *, const char *name);\
decl void ida_export location_push_and_jump(location_t *, bool try_to_unhide, ea_t ea, int lnnum, int x, int y, const graph_location_info_t *gi);\
decl bool ida_export location_pop    (location_t *, bool try_tohide);\
decl bool ida_export location_get    (location_t *, size_t depth);\
decl int  ida_export location_mark   (location_t *, int marker, const char *title, const char *desc);\
decl bool ida_export location_jump   (location_t *, int marker);\

DEFINE_CURLOC_HELPERS(idaman)
DEFINE_LOCATION_HELPERS(idaman)
#else
#define DEFINE_CURLOC_HELPERS(decl)
#define DEFINE_LOCATION_HELPERS(decl)
#endif // SWIG

#define CURLOC_SISTACK_ITEMS 4

class curloc : public sistack_t
{
  void push(void);
  DEFINE_CURLOC_HELPERS(friend)
  void unhide_if_necessary(ea_t ea);
  void hide_if_necessary(void);
protected:
  void toup(ea_t _ea) { ea = _ea; lnnum = 0; x = 0; y = 0; flags = 0; target = BADADDR; };
public:
  ea_t ea;                // Address
  ushort x,y;             // coords on the screen
  ushort lnnum;           // number of line for the current address
#define DEFAULT_LNNUM 0xFFFF
  ushort flags;           // unhid something?
#define UNHID_SEGM 0x0001 // unhid a segment at 'target'
#define UNHID_FUNC 0x0002 // unhid a function at 'target'
#define UNHID_AREA 0x0004 // unhid an area at 'target'
  ea_t target;

  curloc(void)                   { ea = target = BADADDR; flags = 0; x = 0; y = 0; }
  curloc(const char *stackName)  { linkTo(stackName); }
  void linkTo(const char *stackName)
        { curloc_linkTo(this, stackName); }
  void setx(int xx)              { x  = ushort(xx); }
  void jump_push(bool try_to_unhide, ea_t ea=BADADDR, int lnnum=0, int x=0, int y=0)
        { curloc_jump_push(this, try_to_unhide, ea, lnnum, x, y); }
  bool pop(bool try_tohide)
        { return curloc_pop(this, try_tohide); }
  bool get(size_t depth)
        { return curloc_get(this, depth); }
  size_t size(void)               { return sistack_t::size()/CURLOC_SISTACK_ITEMS; }
  void copy_current_location(const curloc &loc)
  {
    ea    = loc.ea;
    lnnum = loc.lnnum;
    x     = loc.x;
    y     = loc.y;
  }

  // Mark/unmark position
  // marker - the marked position number (1..MAX_MARK_SLOT)
  //          if specified as <=0: ask the user to select the mark slot.
  // title  - if marker<=0, then the window caption of the dialog which
  //          will appear on the screen. title==NULL will lead to the default
  //          caption: "please select a mark slot"
  // desc   - description of the marked position. If NULL, IDA will show a dialog
  //          box asking the user to enter the description.
  //          If desc is specified as "", then the specified marked position
  //          will be deleted and the remaining positions will be shifted.
  // returns used marker number (<=0 - none)
  int mark(int marker, const char *title, const char *desc)
        { return curloc_mark(this, marker, title, desc); }

  ea_t markedpos(int *marker)           // get address of marked location
        { return curloc_markedpos(this, marker); }
  bool jump(int marker)                 // Jump to marker
        { return curloc_jump(this, marker); }
  ssize_t markdesc(int marker, char *buf, size_t bufsize)
        { return curloc_markdesc(this, marker, buf, bufsize); }
};

#define MAX_MARK_SLOT   1024     // Max number of marked locations

// Since we can not modify the curloc class (for compatibility reasons)
// we create a derived class and will exclusively use it in IDA GUI
class location_t : public curloc
{
  typedef curloc inherited;
  DEFINE_LOCATION_HELPERS(friend)
public:
  graph_location_info_t gli;
  location_t(void) {}
  location_t(const char *name) { linkTo(name); }
  void linkTo(const char *name) { location_linkTo(this, name); }

  void push_and_jump(bool try_to_unhide, ea_t ea=BADADDR, int lnnum=0,
                int x=0, int y=0,  graph_location_info_t *gli=NULL)
    { location_push_and_jump(this, try_to_unhide, ea, lnnum, x, y, gli); }
  bool pop(bool try_tohide)
    { return location_pop(this, try_tohide); }
  bool get(size_t depth)
    { return location_get(this, depth); }
  void copy_current_location(const location_t &loc)
  {
    inherited::copy_current_location(loc);
    gli = loc.gli;
  }

  int mark(int marker, const char *title, const char *desc)
    { return location_mark(this, marker, title, desc); }
  bool jump(int marker)
    { return location_jump(this, marker); }
};

//----------------------------------------------------------------------
// functions for the kernel only:
void init_marks(void);
void term_marks(void);
void change_jumps_stack_format(void);
void move_marks(ea_t from, ea_t to, asize_t size);

static const char loc_gtag = 'G'; // graph location information tag

#pragma pack(pop)
#endif // __MOVES_HPP


/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Virtual Array of Longs
 *
 */

#ifndef VARRAY_HPP
#define VARRAY_HPP
#pragma pack(push, 1)   // IDA uses 1 byte alignments!

#include <pro.h>
#include <vm.hpp>

// internal classes
struct vaptr_t          // Chunk definition
{
  ea_t start;           // Start address of the chunk
  ea_t end;             // End address of the chunk (not included)
  uval_t offset;        // Offset in the file
                        // Offsets should be in increasing order
  void correct_offset(size_t pagesize)
  {
    size_t psize = pagesize / sizeof(uint32);
    offset = offset - offset%pagesize + (start%psize)*sizeof(uint32);
  }
  asize_t size(void) const { return end - start; }
};

#define VA_MAGIC "Va0"

struct vaheader_t                       // First bytes of VA file (header)
{
  char magic[4];                        // Must be VA_MAGIC
  ushort nchunks;                       // Number of chunks
  ushort eof;                           // Number of last used page + 1
};

// Callback function to Varray:scan, test functions

typedef bool idaapi va_test(uint32, void *ud);

// Main class declared in the file:
class Varray
{
public:

        Varray(void)    { Pages = NULL; }
        ~Varray(void)   { vclose(); }

        //lint -sem(Varray::linkTo, initializer)
        int     linkTo  (const char *file, uint Psize, uint PoolSize);
                                        // Psize - how many longs
                                        // PoolSize - how many pages in the cache
                                        // if file doesn't exist, it will be
                                        // created
        void    vclose   (void);
//
//      Address space functions
//
        error_t enable  (ea_t start,ea_t end);        // 0-ok,else error
        error_t disable (ea_t start,ea_t end);        // 0-ok,else error
        bool    enabled (ea_t addr)                   // is enabled ?
                                { return getoff(addr) != 0; }

        bool in_fast_cache(ea_t addr)
        {
          return lastvp != NULL && lastvp->start <= addr && lastvp->end > addr;
        }

        ea_t nextaddr  (ea_t addr); // get next enabled addr
                                    // if not exist, returns -1
        ea_t prevaddr  (ea_t addr); // get prev enabled addr
                                    // if not exist, returns -1
        ea_t prevchunk (ea_t addr); // return prev chunk last addr
                                    // if not exist, returns -1
        ea_t nextchunk (ea_t addr); // return next chunk first addr
                                    // if not exist, returns -1
        asize_t chunksize(ea_t addr)
        {
          if ( getoff(addr) == 0 )
            return 0;
          return lastvp->end - lastvp->start;
        }

        ea_t get_chunk_start(ea_t addr)
        {
          if ( getoff(addr) == 0 )
            return BADADDR;
          return lastvp->start;
        }

        ea_t get_chunk_end(ea_t addr)
        {
          if ( getoff(addr) == 0 )
            return 0;
          return lastvp->end;
        }

        ea_t first_enabled_addr(ea_t ea1, ea_t ea2) const; // get first enabled addr in [ea1, ea2)
        int movechunk  (ea_t from, ea_t to, asize_t size);
                             // move information from one address to another. returns VAMOVE_...
#define VAMOVE_OK        0   // all ok
#define VAMOVE_BADFROM   -1  // the from address is not enabled
#define VAMOVE_TOOBIG    -2  // the range to move is too big
#define VAMOVE_OVERLAP   -3  // the target address range is already occupied
#define VAMOVE_TOOMANY   -4  // too many chunks are defined, can't move
        int check_move_args(ea_t from, ea_t to, asize_t size); // returns VAMOVE_...

//
//      Read/Write functions
//
        uint32   vread  (ea_t ea)             { return *Raddr(ea); }
        void    vwrite  (ea_t ea, uint32 val) { *Waddr(ea)  =  val; }
        void    setbits (ea_t ea, uint32 bit) { *Waddr(ea) |=  bit; }
        void    clrbits (ea_t ea, uint32 bit) { *Waddr(ea) &= ~bit; }
        uint32*  Waddr  (ea_t ea);       // return &flags for ea, mark page as dirty
        uint32*  Raddr  (ea_t ea);       // return &flags for ea
        void    vflush  (void)          { Pages->vflush(); }

        void memset(ea_t start, asize_t size, uint32 x);
        void memcpy(ea_t start, asize_t size, Varray &src, ea_t srcstart);
        ea_t memcmp(ea_t start, asize_t size, Varray &v2, ea_t v2start);
                                                // returns -1 - if equal
                                                // else address where mismatches
        ea_t memscn (ea_t start, asize_t size, uint32 x);
        ea_t memtst (ea_t start, asize_t size, va_test *test, void *ud);
        ea_t memtstr(ea_t start, asize_t size, va_test *test, void *ud);

        uint32  *vread  (ea_t start,      uint32 *buffer, size_t size);
        void    vwrite  (ea_t start,const uint32 *buffer, size_t size);

        void    shright (ea_t from);    // Shift right tail of array
        void    shleft  (ea_t from);    // Shift left  tail of array

//
//      Sorted array functions (obsolete for 64-bit ea_t)!!!
//
#ifndef __EA64__
        ea_t bsearch(ea_t ea);          // Binary search
                                        // Returns index to >= ea
                                        // Attention: this func may return
                                        // pointer past array !
        bool addsorted(ea_t ea);        // Add an element to a sorted array.
                                        // If element exists, return 0
                                        // else 1
        bool delsorted(ea_t ea);        // Del element from a sorted array
                                        // If doesn't exist, return 0
                                        // else return 1
#endif

        void vadump(const char *msg, bool ea_sort_order); // debugging
        const char *check(bool ea_sort_order); // check internal consistency

        // iterate chunks
        typedef vaptr_t *iterator;
        typedef const vaptr_t *const_iterator;
        const_iterator begin(void) const { return const_iterator(header+1); }
        const_iterator end(void) const { return begin() + header->nchunks; }
        iterator begin(void) { return iterator(header+1); }
        iterator end(void) { return begin() + header->nchunks; }

//
// scan the Varray forward. call 'perform' for each page. If perform()
// returns >=0, then this is an index in the page, return address with this index.
// if perform() < 0, continue the scan
// Returns the address calculated by the index returned by perform().
//      perform() args: page - pointer to the page
//                      s    - size of the page
// 'change' - will perform() change the pages
//
  ea_t vascan(
        ea_t _start,
        asize_t size,
        ssize_t (idaapi*perform)(uint32 *page, ssize_t s, void *ud),
        bool change,
        void *ud);
  ea_t vascanr(
        ea_t _start,
        asize_t size,
        ssize_t (idaapi*perform)(uint32 *page, ssize_t s, void *ud),
        bool change,
        void *ud);

private:
  vmclass<uint32> *Pages;
  vaheader_t *header;                   // Header page
  ea_t lastea;                          // Last accessed address
  vaptr_t *lastvp;                      //  vptr of it
  uint32 lastoff;                       //  offset of it
  ushort lastPage;
  uint32 *lPage;
  size_t psize;                         // how many items can be put into a page
  size_t pagesize;                      // page size in bytes

  uint32 getoff(ea_t addr);
  int shiftPages(uval_t offset, int op, int np, bool changecur);
  void move_vm_chunk(size_t p1, size_t p2, ssize_t n);
  void swap(size_t x1, size_t x2, ssize_t n);
  vaptr_t *split(vaptr_t *cvp, ea_t from, ea_t end);
  void split_page(size_t kp, ea_t from);
  void merge_if_necessary(vaptr_t *vp);

  // 0-ok, -1-error, eof overflow
  int add_pages(uval_t offset, int npages, bool changecur)
    { return shiftPages(offset, 0, npages, changecur); }
  int del_pages(uval_t offset, int npages, bool changecur)
    { return shiftPages(offset, npages, 0, changecur); }

  size_t getidx(const vaptr_t *vp) const { return size_t(vp - begin()); }
  bool is_first(const vaptr_t *vp) const { return getidx(vp) == 0; }
  bool is_last(const vaptr_t *vp) const;
};

// Structure types used internally by Varray
struct vaidx_info_t
{
  Varray *source;
  ea_t index;
};

struct vascan_info_t
{
  va_test *test;
  void *ud;
  vascan_info_t(va_test *_test, void *_ud) : test(_test), ud(_ud) {}
};

#pragma pack(pop)
#endif // VARRAY_HPP

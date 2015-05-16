#ifndef _PE_LDR_COMMON_H_
#define _PE_LDR_COMMON_H_

#define PAGE_SIZE 0x1000
//------------------------------------------------------------------------
struct pe_section_visitor_t
{
  virtual int idaapi visit_section(const pesection_t &, off_t /*file_offset*/) { return 0; }
  virtual int idaapi load_all() { return 0; }
  virtual idaapi ~pe_section_visitor_t(void) {}
};

//------------------------------------------------------------------------
struct pe_import_visitor_t
{
  bool withbase;
  int elsize;  // initialized by process_import_table()
  peimpdir_t id;
  dimpdir_t did;

  pe_import_visitor_t(void) : withbase(false) {}
  virtual int idaapi visit_module(const char * /*dll*/, ea_t /*iat_start*/, ea_t /*int_rva*/) { return 0; }
  virtual int idaapi leave_module(int /*nprocessed_imports*/) { return 0; }
  // buf==NULL:by ordinal
  virtual int idaapi visit_import(ea_t impea, uint64 ordinal, const char *buf) = 0;
  virtual int idaapi impdesc_error(off_t /*file_offset*/) { return 0; }
  virtual idaapi ~pe_import_visitor_t(void) {}
};

//------------------------------------------------------------------------
struct pe_export_visitor_t
{
  // this function will be called once at the start.
  // it must return 0 to continue
  virtual int idaapi visit_expdir(const peexpdir_t & /*ed*/, const char * /*modname*/) { return 0; }
  // this function is called for each export. name is never NULL, forwarder may point to the forwarder function
  // it must return 0 to continue
  virtual int idaapi visit_export(uint32 rva, uint32 ord, const char *name, const char *forwarder) = 0;
  virtual idaapi ~pe_export_visitor_t(void) {}
};

//------------------------------------------------------------------------
class pe_loader_t
{
private:
  int process_import_table(
        linput_t *li,
        const peheader_t &pe,
        ea_t atable,
        ea_t ltable,
        pe_import_visitor_t &piv);
  template <class T>
  T varead(linput_t *li, uint32 rva, bool *ok)
  {
    T x = 0;
    if ( vseek(li, rva) )
    {
      lread(li, &x, sizeof(x));
    }
    else
    {
      if ( ok != NULL )
        *ok = false;
    }
    return x;
  }
public:
  struct transl_t
  {
    ea_t start;
    ea_t end;
    off_t pos;
    size_t psize;
  };
  typedef qvector<transl_t> transvec_t;
  transvec_t transvec;
  exehdr exe;
  peheader_t pe;
  peheader64_t pe64;    // original 64bit header, should not be used
                        // because all fields are copied to pe
                        // nb: imagebase is truncated during the copy!
  ea_t load_imagebase;  // imagebase used during loading; initialized from the PE header but can be changed by the user
  off_t peoff;          // offset to pe header
  bool link_ulink;      // linked with unilink?

  // low level functions
  ea_t map_ea(ea_t rva, const transl_t **tr = NULL);
  ea_t get_imagebase(void) const { return load_imagebase; }
  void set_imagebase(ea_t newimagebase) { load_imagebase=newimagebase; }
  virtual bool vseek(linput_t *li, uint32 rva);
  inline uint16 vashort(linput_t *li, uint32 addr, bool *ok) { return varead<uint16>(li, addr, ok); }
  inline uint32 valong(linput_t *li, uint32 addr, bool *ok) { return varead<uint32>(li, addr, ok); }
  inline uint64 vaint64(linput_t *li, uint32 addr, bool *ok) { return varead<uint64>(li, addr, ok); }
  char *asciiz(linput_t *li, uint32 rva, char *buf, size_t bufsize, bool *ok);
  int process_sections(linput_t *li, off_t fist_sec_pos, int nojbs, pe_section_visitor_t &psv);
  int process_sections(linput_t *li, pe_section_visitor_t &psv);
  bool read_header(linput_t *li, off_t _peoff, bool silent);

  // high level functions
  bool read_header(linput_t *li, bool silent=false);
  int process_sections(linput_t *li);

  int process_delayed_imports(linput_t *li, pe_import_visitor_t &il);
  int process_imports(linput_t *li, pe_import_visitor_t &piv);
  int process_exports(linput_t *li, pe_export_visitor_t &pev);
  bool vmread(linput_t *li, uint32 rva, void *buf, size_t sz);

  virtual ~pe_loader_t(void) {}
};

#endif

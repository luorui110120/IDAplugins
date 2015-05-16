/*

  This file contains functions common to many processor modules
  to manage configuration files. The following functions can be called:

  bool apply_config_file(int _respect_info);
        Read and parse the config file

  void set_device_name(const char *dname, int respect_info);
        Set a new device name and reread the config file

  bool display_infotype_dialog(int *respect_info, const char *cfgname);
        Display a form and allow the user to clear some IORESP_ bits

*/

#include <entry.hpp>

char deviceparams[MAXSTR];
static int respect_info;

#define IORESP_PORT     1       // rename port names in memory
#define IORESP_AREA     2       // respect "area" directives
#define IORESP_INT      4       // respect interrupt information

#define IORESP_ALL     (IORESP_PORT|IORESP_AREA|IORESP_INT)
#define IORESP_NONE     0

#define NONEPROC        "NONE"

// Option: complain about missing config files
// Default: yes, complain
// Change: define SILENT
//#define SILENT        - don't complain about missing config files

// Option: additional segment class to appear in the device description
// Default: EEPROC
// Change: define CUSTOM1 for the name you want
#ifndef CUSTOM1
#define CUSTOM1 "EEPROM"
#endif

// Option: respect configuration information for different file types?
// Default: only binary-like files use IORESP_PORT, AREA, INT
// Change: define CHECK_IORESP as a condition
#ifndef CHECK_IORESP
#define CHECK_IORESP inf.like_binary()
#endif

// Option: a callback function to parse additional configuration file lines
// Default: "interrupt" and "entry" keywords are recognized
// Change: define callback to point to a local callback function
#ifndef callback
#define callback standard_callback
#endif

// Option: function to handle entry points
// Default: create an entry point
// Change: define ENTRY_PROCESSING to point to a local function

// Option: function to handle areas
// Default: create a segment
// Change: define AREA_PROCESSING to point to a local function

// Option: define function get_cfg_path()
// Default: yes, it returns a file name using the current processor name
// Change: define NO_GET_CFG_PATH and write your own get_cfg_path()

//------------------------------------------------------------------
static const char *idaapi parse_area_line(const char *line, char *buf, size_t bufsize)
{
  char word[MAXSTR];
  char aclass[MAXSTR];
  ea_t ea1, ea2;
  if ( sscanf(line, "area %s %s %" FMT_EA "i:%" FMT_EA "i", aclass, word, &ea1, &ea2) == 4 )
  {
    size_t ram = 0;
    size_t rom = 0;
    size_t eprom = 0;
    size_t eeprom = 0;
    static const char format[] = "RAM=%lu ROM=%lu EPROM=%lu " CUSTOM1 "=%lu";
    sscanf(buf, format, &ram, &rom, &eprom, &eeprom);
    size_t size = size_t(ea2 - ea1);
         if ( stristr(word, "RAM")    != NULL ) ram    += size;
    else if ( stristr(word, CUSTOM1)  != NULL ) eeprom += size;
    else if ( stristr(word, "EPROM")  != NULL ) eprom  += size;
    else if ( stristr(word, "ROM")    != NULL ) rom    += size;
    if ( ram || rom || eeprom || eeprom )
      qsnprintf(buf, bufsize, format, ram, rom, eprom, eeprom);
    else
      buf[0] = '\0';
    if ( (respect_info & IORESP_AREA) != 0 && get_first_seg() != NULL )
    {
#ifdef AREA_PROCESSING
      if ( !AREA_PROCESSING(ea1, ea2, word, aclass) )
#endif
      {
#ifdef I8051
        if ( ( stristr(word, "FSR") != NULL ) ||( stristr(word, "RAM") != NULL ))
        {
          AdditionalSegment( size_t(ea2-ea1), (size_t)ea1, word );
        }
        else
#endif // I8051
        {
          sel_t sel = allocate_selector(0);
          add_segm(sel, ea1, ea2, word, aclass);
        }
        if ( ea2-ea1 > 0xFFFF )
          set_segm_addressing(getseg(ea1), true);
      }
    }
    return NULL;
  }
  return "syntax error";
}

//------------------------------------------------------------------
const char *idaapi parse_area_line0(const char *line, char *buf, size_t bufsize)
{
  respect_info = 0;
  parse_area_line(line, buf, bufsize);
  return NULL;
}

//------------------------------------------------------------------
static const char *idaapi standard_callback(const ioport_t *, size_t, const char *line)
{
  char word[MAXSTR];
  ea_t ea1;
  int len;
  if ( sscanf(line, "interrupt %s %" FMT_EA "i%n", word, &ea1, &len) == 2 )
  {
    if ( (respect_info & IORESP_INT) != 0 )
    {
      ea_t proc, wrong;
      segment_t *s = getseg(ea1);
      if ( s != NULL && s->use32() )
      {
        doDwrd(ea1, 4);
        proc = get_long(ea1);
        wrong = 0xFFFFFFFF;
      }
      else
      {
        doWord(ea1, 2);
        proc = get_word(ea1);
        wrong = 0xFFFF;
      }
      if ( proc != wrong && isEnabled(proc) )
      {
        set_offset(ea1, 0, 0);
        add_entry(proc, proc, word, true);
      }
      else
      {
        set_name(ea1, word);
      }
      const char *ptr = &line[len];
      ptr = skipSpaces(ptr);
      if ( ptr[0] != '\0' )
        set_cmt(ea1, ptr, true);
    }
    return NULL;
  }
  if ( sscanf(line, "entry %s %" FMT_EA "i%n", word, &ea1, &len) == 2 )
  {
    if ( (respect_info & IORESP_INT) != 0 )
    {
      if ( isEnabled(ea1) )
      {
        const char *ptr = &line[len];
        ptr = skipSpaces(ptr);
#ifdef ENTRY_PROCESSING
        if ( !ENTRY_PROCESSING(ea1, word, ptr) )
#endif
        {
          add_entry(ea1, ea1, word, true);
          if ( ptr[0] != '\0' )
            set_cmt(ea1, ptr, true);
        }
      }
    }
    return NULL;
  }
  return parse_area_line(line, deviceparams, sizeof(deviceparams));
}

//------------------------------------------------------------------
#ifndef NO_GET_CFG_PATH
inline void get_cfg_filename(char *buf, size_t bufsize)
{
  inf.get_proc_name(buf);
  strlwr(buf);
  qstrncat(buf, ".cfg", bufsize);
}
#endif

//------------------------------------------------------------------
static bool apply_config_file(int _respect_info)
{
  if ( strcmp(device, NONEPROC) == 0 )  // processor not selected
    return true;

  char cfgfile[QMAXFILE];
  char cfgpath[QMAXPATH];
  get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( getsysfile(cfgpath, sizeof(cfgpath), cfgfile, CFG_SUBDIR) == NULL )
  {
#ifndef SILENT
    warning("ICON ERROR\n"
            "Can not open %s, I/O port definitions are not loaded", cfgfile);
#endif
    return false;
  }
  deviceparams[0] = '\0';
  if ( !CHECK_IORESP ) _respect_info = 0;
  respect_info = _respect_info;
  free_ioports(ports, numports);
  ports = read_ioports(&numports, cfgpath, device, sizeof(device), callback);
  if ( respect_info & IORESP_PORT )
  {
    for ( int i=0; i < numports; i++ )
    {
      ioport_t *p = ports + i;
      ea_t ea = p->address;
#ifdef I8051
      if ( ea >= 0x80 && ea < 0x100 )
      { // specail mapping alg for i51 FSR regs
        segment_t *s = get_segm_by_name("FSR");
        if ( s != NULL )
        {
          ea_t map = ea + s->startEA - 0x80;
          if ( isEnabled(map) )
            ea = map;
        }
      }
#endif
      set_name(ea, p->name);
      set_cmt(ea, p->cmt, true);
    }
  }
  return true;
}

//------------------------------------------------------------------
void set_device_name(const char *dname, int respect_info)
{
  if ( dname != NULL )
  {
    qstrncpy(device, dname, sizeof(device));
    helper.supset(-1, device);
    apply_config_file(respect_info);
  }
}

//------------------------------------------------------------------
// Display a dialog form with the information types
// Let the user to clear some checkboxes if he wants so
// Returns: true - the user clicked OK
bool display_infotype_dialog(int display_info, int *respect_info, const char *cfgname)
{
  if ( display_info == 0 )
    return false;
  static const char form[] =
    "Loaded information type\n"
    "\n"
    "Please specify what information should be loaded from\n"
    "the configuration file %s to the database.\n"
    "\n"
    "If the input file does not contain parts corresponding to\n"
    "the segmentation defined in the config file, you might want\n"
    "to clear the 'memory layout' checkbox or even cancel this\n"
    "dialog box.\n";
  char buf[MAXSTR];
  char *ptr = buf + qsnprintf(buf, sizeof(buf), form, cfgname);
  char *const end = buf + sizeof(buf);
  int B = 1;
  ushort b = 0;
  ushort r = (ushort)*respect_info;
#define ADD_FIELD(bit, desc) \
  if ( display_info & bit )  \
  {                          \
    if ( r & bit )           \
      b |= B;                \
    B <<= 1;                 \
    APPEND(ptr, end, desc);  \
  }
  ADD_FIELD(IORESP_PORT, "\n<#Rename port and I/O registers#I/O ports:C>")
  ADD_FIELD(IORESP_AREA, "\n<#Adjust the program segmentation#Memory layout:C>")
  ADD_FIELD(IORESP_INT,  "\n<#Create interrupt vectors and/or entry points#Interrupts:C>")
#undef ADD_FIELD
  qnotused(B);
  APPEND(ptr, end, ">\n\n");
  if ( !AskUsingForm_c(buf, &b) )
    return false;
  B = 1;
  if ( display_info & IORESP_PORT ) { setflag(r, IORESP_PORT, B & b); B <<= 1; }
  if ( display_info & IORESP_AREA ) { setflag(r, IORESP_AREA, B & b); B <<= 1; }
  if ( display_info & IORESP_INT  ) { setflag(r, IORESP_INT , B & b);          }
  *respect_info = r;
  return true;
}

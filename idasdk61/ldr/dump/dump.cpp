/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov (ig@datarescue.com)
 *                                              http://www.datarescue.com
 *      ALL RIGHTS RESERVED.
 *
 */

#include "../idaldr.h"

//--------------------------------------------------------------------------
static int make_words(char *line, char **words, int maxwords)
{
  while ( qisspace(*line) )
    line++;
  int i;
  for ( i=0; *line && i < maxwords; i++ )
  {
    words[i] = line;
    while ( !qisspace(*line) && *line != '\0' )
      line++;
    if ( *line != '\0' )
      *line++ = '\0';
    while ( qisspace(*line) )
      line++;
  }
  return i;
}

//--------------------------------------------------------------------------
inline uint32 hex(char *&word)
{
  return strtoul(word, &word, 16);
}

//--------------------------------------------------------------------------
inline uint32 oct(char *&word)
{
  return strtoul(word, &word, 8);
}

//#define FAILED  do { msg(            "failed at %d (input file line %d)\n", __LINE__, nl); return 0; } while ( 0 )
#define FAILED  return deb(IDA_DEBUG_LDR,"failed at %d (input file line %d)\n", __LINE__, nl), 0

//--------------------------------------------------------------------------
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  char line[MAXSTR];
  char *words[MAXSTR];

  if ( n )
    return 0;

  // We try to interpret the input file as a text
  // file with a dump format, i.e. all lines should look like

//00000020:  59 69 74 54-55 B6 3E F7-D6 B9 C9 B9-45 E6 A4 52  YitTU¦>?O?E?E??R
//0020: 59 69 74 54 55 B6 3E F7 D6 B9 C9 B9 45 E6 A4 52  "YitTU¦>?O?E?E??R"
//1000: 12 23 34 56 78
//0100: 31 C7 1D AF 32 04 1E 32 05 1E 3C 32 07 1E 21 D9
//12 23 34 56 78

  // and similar lines
  // We allow non-ascii characters at the end of the line
  // We skip empty lines

  ssize_t p0len = -1;    // length of the first word's hex part
  char w0sep[10];        // separator after the first word
  w0sep[0] = '\0';
  int nl = 0;
  int nontrivial_line_count = 0;
  bool no_more_lines = false;
  uint32 adr, oldadr=0;
  while ( qlgets(line, sizeof(line), li) )
  {
    nl++;
    strrpl(line, '-', ' ');
    int nw = make_words(line, words, qnumber(words));
    if ( line[0] == ';' || line[0] == '#' )
      continue;
    if ( nw == 0 )
      continue;
    nontrivial_line_count++;
    if ( no_more_lines )
      FAILED;
    // od -x format may contain '*' lines which mean repetition
    if ( strcmp(words[0], "*") == 0 && nw == 1 )
      continue;
    // the first word must be a number (more than one digit)
    char *ptr = words[0];
    adr = hex(ptr);
    ssize_t p0 = ptr - words[0];
    if ( p0 <= 1 )
      FAILED;
    if ( nontrivial_line_count > 1 && p0 < p0len )
      FAILED;
    p0len = p0;
    // take the separator from the first line
    if ( nontrivial_line_count == 1 )
    {
      qstrncpy(w0sep, ptr, sizeof(w0sep));
      while ( *ptr )
        if ( strchr(":>-.", *ptr++) == NULL )
          FAILED;
    }
    else
    {
      if ( strcmp(w0sep, ptr) != 0 )
        FAILED;
    }
    bool haspref = p0len >= 4 || w0sep[0] != '\0';
    if ( haspref )
    {
      // if the line contains only the address, then don't accept lines anymore
      if ( nw == 1 )
      {
        if ( nontrivial_line_count == 1 )
          FAILED;
        no_more_lines = true;
        if ( adr <= oldadr )
          FAILED;
      }
      else
      {
        // the remaining words should be numbers with at least 1 position
        // (at least the second word should be so)
        ptr = words[1];
        hex(ptr);
        if ( ptr == words[1] )
          FAILED;
      }
    }
    oldadr = adr;
  }
  if ( nontrivial_line_count == 0 )
    FAILED;

  qstrncpy(fileformatname, "Dump file", MAX_FILE_FORMAT_NAME);
  return 1;
}

//--------------------------------------------------------------------------
static uchar bytes[MAXSTR/2];
static bool iscode;
static sel_t sel;
static ea_t sea;
static ea_t eea;
static ushort neflag;

static void copy(ea_t &ea, ea_t &top)
{
  if ( sea == BADADDR )
  {
    if ( neflag & NEF_SEGS )
    {
      const char *sname = iscode ? "CODE" : "DATA";
      sel = setup_selector(0);
      add_segm(sel, ea, top, sname, sname);
    }
    sea = ea;
    eea = top;
  }
  else
  {
    if ( eea < top )
    {
      eea = top;
      set_segm_end(sea, eea, SEGMOD_KILL);
    }
  }
  mem2base(bytes, ea, top, -1);
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort _neflag, const char * /*fileformatname*/)
{
  char line[MAXSTR];
  char *words[MAXSTR];

  neflag = _neflag;
  iscode = (neflag & NEF_CODE) != 0;
  sel = BADSEL;
  sea = BADADDR;
  ea_t ea = 0;
  ea_t top= 0;
  bool use32   = false;
  bool octpref = false;
  bool octnum  = false;
  size_t fill = 0;

  // Since we made all the checks in accept_file,
  // here we don't repeat them

  ssize_t p0len = -1;    // length of the first word's hex part
  char w0sep[10];        // separator after the first word
  w0sep[0] = '\0';
  int nontrivial_line_count = 0;
  while ( qlgets(line, sizeof(line), li) )
  {
    strrpl(line, '-', ' ');
    if ( line[0] == ';' || line[0] == '#' )
      continue;
    int n = make_words(line, words, qnumber(words));
    if ( n == 0 )
      continue;
    nontrivial_line_count++;
    ssize_t bi;
    // od -x format may contain '*' lines which mean repetition
    if ( strcmp(words[0], "*") == 0 && n == 1 )
    {
      fill  = size_t(top - ea);
      octpref = true;             // od -x have octal prefixes
      continue;
    }
    // the first word must be a number (more than one digit)
    char *ptr = words[0];
    uint32 w0 = octpref ? oct(ptr) : hex(ptr);
    p0len = ptr - words[0];
    // take the separator from the first line
    if ( nontrivial_line_count == 1 )
      qstrncpy(w0sep, ptr, sizeof(w0sep));

    // process '*' and fill the gap
    if ( fill > 0 )
    {
      while ( top < w0 )
      {
        ea = top;
        top = ea + fill;
        copy(ea, top);
      }
    }

    int idx = 0;
    if ( w0sep[0] != '\0' || p0len >= 4 )
    {
      if ( nontrivial_line_count > 1 && !octpref && top != w0 )
      {
        // strange, the sequence is not contiguous
        // check if the prefixes are octal (od -x)
        ptr = words[0];
        if ( oct(ptr) == top )
        {
          octpref = true;
          ptr = words[0];
          w0 = oct(ptr);
        }
      }
      ea = w0;
      idx = 1;
    }
    else
    {
      ea = top;
    }
    for ( bi=0; idx < n; idx++ ) //lint !e443
    {
      ptr = words[idx];
      if ( nontrivial_line_count == 1 && !octnum && strlen(ptr) == 6 )
      {
        oct(ptr);
        if ( ptr-words[idx] == 6 )
          octnum = true;
        ptr = words[idx];
//        msg("ptr=%s octnum=%d\n", ptr, octnum);
      }
      uint32 b = octnum ? oct(ptr) : hex(ptr);
      ssize_t nc = ptr - words[idx];
      if ( nc < 2 )
      {
        // we tolerate one-letter separators between numbers
        if ( words[idx][1] == '\0' && strchr("\xA6|-:", words[idx][0]) != NULL )
          continue;
        break;
      }
      nc /= octnum ? 3 : 2;             // number of bytes
      *(uint32 *)&bytes[bi] = b;
      bi += nc;
    }
    top = ea + bi;
    copy(ea, top);
  }

  if ( eea >= 0x10000 || p0len > 4 )
    use32 = true;
  if ( neflag & NEF_SEGS )
  {
    if ( use32 )
    {
      set_segm_addressing(getseg(sea), 1);
      if ( ph.id == PLFM_386 ) inf.lflags |= LFLG_PC_FLAT;
    }
    set_default_dataseg(sel);
  }
  if ( (neflag & NEF_RELOAD) == 0 )
    create_filename_cmt();
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  LDRF_RELOAD,               // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  NULL,
  NULL,
  NULL,
};

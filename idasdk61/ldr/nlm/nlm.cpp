/*
 *  This Loader Module is written by Ilfak Guilfanov and
 *                        rewriten by Yury Haron
 *
 */
/*
  L O A D E R  for Netware Loadable Module (NLM)
*/

#include <stddef.h>
#include "../idaldr.h"
#include "nlm.h"
#include <typeinf.hpp>

#pragma pack(push, 1)   // IDA uses 1 byte alignments!

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  char magic[NLM_MAGIC_SIZE];

  if ( n) return(0 );

  if ( qlread(li, magic, sizeof(magic)) != sizeof(magic ) ||
     memcmp(magic, NLM_MAGIC, sizeof(magic)))                 return(0);

  qstrncpy(fileformatname,
           "Netware Loadable Module (NLM)",
           MAX_FILE_FORMAT_NAME);
  return(f_NLM);
}

//--------------------------------------------------------------------------
static void _errstruct(int lnnum)
{
  loader_failure("Bad file structure or read error (line %d)", lnnum);
}
#define errstruct()  _errstruct(__LINE__)

//--------------------------------------------------------------------------
// Меня уже достал этот кривой Ватком!
//Из-за него пришость делать внешнее определение
struct unp_data {
  FILE    *fo;
  uint32  pos, size;
  uchar   *buff;
  ushort  b_pos, b_val;
};
static struct local_data {
  linput_t      *li;
  nlmexe_t  nlm;
  union {
    char      buf[MAXSTR];
    unp_data unp;
  };
  ea_t start, cbase, csize, dbase, dsize;
  netnode impnode;
}lc;
//--------------------------------------------------------------------------
static int mread(void *buf, size_t size)
{
  if ( qlread(lc.li, buf, size) == size) return(0 );
  if ( askyn_c(0, "HIDECANCEL\nRead error or bad file structure. Continue loading?") <= 0 )
    loader_failure();
  return(1);
}

//--------------------------------------------------------------------------
static int getstr(void)
{
  uchar len;
#if MAXSTR < 256
#error
#endif

  if ( mread(&len, sizeof(len)) || (len && mread(lc.buf, len))) return(1 );
  lc.buf[len] = '\0';
  return(0);
}

//----------------------------------------------------------------------
static void set_reloc(ushort sel, ea_t fixaddr, ea_t toea, bool self_flag)
{
  fixup_data_t fdt;
  sval_t displ = int32(get_long(fixaddr));

  fdt.off          = toea;
  fdt.sel          = sel;
  fdt.type         = FIXUP_OFF32;
  fdt.displacement = 0;
  if ( sel == 3 ) {
    fdt.type |= FIXUP_EXTDEF;
    fdt.displacement = displ;
  }
  if ( self_flag ){
    fdt.type |=  FIXUP_SELFREL;
    toea -= fixaddr;
  }
  put_long(fixaddr, toea + displ);
  set_fixup(fixaddr, &fdt);
}

//----------------------------------------------------------------------
static void addImps(void)
{
  uint32 i, fnum, ent;
  ea_t ea, sz, ebase, eend;
  int   self, sff;

  if ( lc.nlm.impoff == 0 || (i = lc.nlm.impnum) == 0 ) return;
  msg("Creating imported names and relocate it...\n");
  lc.impnode.create(LDR_NODE);
  qlseek(lc.li, lc.nlm.impoff, SEEK_SET);
  eend = (ebase = lc.start) + (i * sizeof(int32));
  set_selector(3, 0);
  if ( !add_segm(3, ebase, eend, NAME_EXTERN, NULL)) loader_failure( );
  {
    register segment_t *ps = getseg(ebase);
    ps->type = SEG_XTRN;
    ps->update();
  }

  for( ; i; i--, ebase += sizeof(int32)) {
    if ( getstr() ) break;
    showAddr(ebase);
    set_name(ebase, lc.buf, SN_NOCHECK | SN_PUBLIC);
    put_long(ebase, 0);
    if ( lc.impnode) netnode(lc.impnode).supset(ebase, lc.buf );
    if ( mread(&fnum, sizeof(uint32)) ) {
forcend:
      if ( (ebase += sizeof(int32)) < eend )
        set_segm_end(ebase, ebase, SEGMOD_KILL);
      return;
    }
    sff = 0;
    while ( fnum-- ) {
      if ( mread(&ent, sizeof(uint32)) ) goto forcend;
      self = (ent & 0x80000000l) ? 0 : 1;
      if ( ent & 0x40000000l ) {
        ea = lc.cbase;
        sz = lc.csize;
      } else {
        ea = lc.dbase;
        sz = lc.dsize;
      }
      ent &= ~0xC0000000L;
      if ( ent >= sz )
        msg("Skip reference to extern '%s' with illegal offset 0x%X\n",
                                                                lc.buf, ent);
      else {
        set_reloc(3, ea + ent, ebase, self);
        if ( !sff && self ) {
          ++sff;
          add_func(ebase, ebase+3);
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
static void addFixups(void)
{
  uint32  i, ent;
  ea_t base, toea;
  asize_t size;
  ushort sel;

  if ( lc.nlm.fixupoff == 0 || (i = lc.nlm.fixupnum) == 0 ) return;
  msg("Applying internal fixup records...\n");
  qlseek(lc.li, lc.nlm.fixupoff, SEEK_SET);

  while ( i-- ) {
    if ( mread(&ent, sizeof(uint32)) ) break;
    if ( ent & 0x40000000l ) {
      base = lc.cbase;
      size = lc.csize;
    } else {
      base = lc.dbase;
      size = lc.dsize;
    }
    if ( ent & 0x80000000l ) {
      toea = lc.cbase;
      sel = 1;
    } else {
      toea = lc.dbase;
      sel = 2;
    }
    ent &= ~0xC0000000L;
    if ( ent >= size || !toea ) {
      msg("Skip invalid relocation for offset 0x%X (to base %a)\n", ent, toea);
    } else set_reloc(sel, ent + base, toea, 0);
  }
}

//--------------------------------------------------------------------------
static void addExpPub(void)
{
  char  flag;
  uint32 i, foff;
  ea_t base, ea;
  asize_t size;
  int pfl;

  for(pfl = 0, foff = lc.nlm.expoff, i = lc.nlm.expnum; pfl < 2;
                      pfl++, foff = lc.nlm.puboff, i = lc.nlm.pubnum) {
    if ( !foff || !i ) continue;
    msg("Applying %s names...\n", pfl ? "public" : "exported");
    qlseek(lc.li, foff, SEEK_SET);
    while ( i-- ) {
      if ( !pfl ) {
        if ( getstr() || mread(&ea, sizeof(uint32)) ) break;
        flag = (ea & 0x80000000l) ? 1 : 0;
      } else if ( mread(&flag, sizeof(flag) ) ||
                mread(&ea, sizeof(uint32)) || getstr())  break;
      ea &= ~0xC0000000L;
      if ( flag ) {
        base = lc.cbase;
        size = lc.csize;
      } else {
        base = lc.dbase;
        size = lc.dsize;
      }
      if ( ea >= size )
        msg("Skip name '%s' with illegal offset (0x%a)\n", lc.buf, ea);
      else {
        ea += base;
        add_entry(ea, ea, lc.buf, flag);
      }
    }
  }
}

//--------------------------------------------------------------------------
static int LoadMsgString(void)
{
  register int c, i;
  for(i = 0; i < sizeof(lc.buf)-1; i++) {
    if ( (c = qlgetc(lc.li)) == EOF) return(0 );
    if ( !c ) break;
    if ( c == 0xFF ) c = '.';
    else if ( c < ' ' ) {
      static const char rpts[] = "\t\n\r\a\v\f",
                        rptc[] = "tnravf";
      register const char *p = strchr(rpts, c);
      if ( p ) {
        if ( i == sizeof(lc.buf)-2 ) break;
        lc.buf[i++] = '\\';
        c = (int)(uchar)rptc[(int)(p-rpts)];
      }
    }
    lc.buf[i] = (char)c;
  }
  lc.buf[i] = '\0';
  return(1);
}

//--------------------------------------------------------------------------
static uint32 addSpecialComment(void)
{
  uchar vp = 0, cp = 0;
  uint32 mp = 0, pos = qltell(lc.li);
  ea_t loadbase = lc.nlm.codeoff;
  if ( lc.nlm.datalen && loadbase > lc.nlm.dataoff ) loadbase = lc.nlm.dataoff;
  if ( loadbase > 0x1000 ) loadbase = 0x1000;

  while ( pos + 12 < loadbase ) {
    if ( mread(lc.buf, 12) ) break;
    if ( !mp && !memcmp(lc.buf, "MeSsAgEs", 8) ) {
      mp = pos + 8;
      pos += 0x7C;
      goto repos;
    }
    if ( !vp && !memcmp(lc.buf, "VeRsIoN#", 8) ) {
      if ( mread(&lc.buf[12], 32-12) ) break;
      ++vp;
      pos += 32 - 1;
      qsnprintf(&lc.buf[32], sizeof(lc.buf)-32, "%u.%02u%c (%02u.%02u.%04u)",
              *(uint32 *)&lc.buf[8], (uchar)lc.buf[8+4],
              *(uint32 *)&lc.buf[8+8] ? (char)(lc.buf[8+8] + ('A'-1)) : ' ',
              (uchar)lc.buf[8+20], (uchar)lc.buf[8+16],
              *(ushort *)&lc.buf[8+12]);
      add_pgm_cmt("Version                : %s", &lc.buf[32]);
      goto check;
    }
    if ( !cp && !memcmp(lc.buf, "CoPyRiGhT=", 10) ) {
      pos += 10;
      pos += (uchar)lc.buf[10];
      qlseek(lc.li, -2L, SEEK_CUR);
      if ( getstr() ) break;
      add_pgm_cmt("Copyright              : %s", lc.buf);
      ++cp;
      goto check;
    }
    if ( !memcmp(lc.buf, "CuStHeAd", 8) ) {
      pos += 8;
      pos += *(uint32 *)&lc.buf[8];
      goto repos;
    }
check:
    if ( mp && vp && cp ) break;
    ++pos;
repos:
    qlseek(lc.li, pos, SEEK_SET);
  }
  return(mp);
}

//--------------------------------------------------------------------------
static void addComments(int flg)
{
  uint32 i;
  uint32 clst = (uint32)-1, msgpos = 0;
  char  *cl1 = NULL, *cl2 = NULL;

  create_filename_cmt();
  qlseek(lc.li, NLM_MODNAMOFF, SEEK_SET);
  if ( lc.nlm.fname[0] )
    add_pgm_cmt(  "Module Name            : %.12s", lc.nlm.fname);
  if ( !getstr() ) {
    add_pgm_cmt(  "Description            : %s", lc.buf);
    qlseek(lc.li, 1, SEEK_CUR);
    if ( mread(&clst, sizeof(clst))) clst = (uint32 )-1;
    else {
      qlseek(lc.li, 0xD-sizeof(clst), SEEK_CUR);
      if ( !getstr() ) {
        cl1 = qstrdup(lc.buf);
        qlseek(lc.li, 1, SEEK_CUR);
        if ( !getstr() ) {
          cl2 = qstrdup(lc.buf);
          msgpos = addSpecialComment();
        }
      }
    }
  }
  add_pgm_cmt(  "File Format Version    : %08Xh%s", lc.nlm.version,
              (lc.nlm.version & NLM_COMPRESSED) ? " (compressed)" : "");
  {
    static const char *const tt[15] =
    {
      "Generic",
      "LAN Driver",
      "Disk Driver",
      "Name Space",
      "Patch/Utility",
      "Mirrored Server Link",
      "OS",
      "High OS",
      "Host Adapter",
      "Custom Device",
      "FS Engine",
      "Real Mode",
      "OS",                //duplicate 6
      "Platform Support",
      "Unknown"
    };
    register int type = (int)lc.nlm.modType;
    if ( lc.nlm.modType > 14 ) type = 14;
    add_pgm_cmt(  "Module type            : %s (%u)", tt[type], type);
  }
  if ( lc.nlm.bssSize )
    add_pgm_cmt(  "Unitialized data size  : %08Xh", lc.nlm.bssSize);
  if ( lc.nlm.custoff && lc.nlm.custlen )
    add_pgm_cmt(  "Custom data            : off=%08Xh len=%08Xh",
                                            lc.nlm.custoff, lc.nlm.custlen);
  lc.buf[0]= '\0';
  if ( lc.nlm.flags ) {
    static const char *const ff[4] =
    {
      "reentrant",
      "multiply loadable",
      "synchronize",
      "pseudo-preemptable"
    };
    register char *ptr = lc.buf;
    register char *end = lc.buf + sizeof(lc.buf);
    register int cn = 0;
    APPCHAR(ptr, end, ' ');
    APPCHAR(ptr, end, '(');
    for(int i = 0; i < 4; i++) if ( lc.nlm.flags & (1 << i) ) {
      if ( cn ) {
         APPCHAR(ptr, end, ',');
         APPCHAR(ptr, end, ' ');
      }
      ++cn;
      APPEND(ptr, end, ff[i]);
    }
    if ( cn) APPCHAR(ptr, end, ')' );
    else   ptr = lc.buf;
    APPZERO(ptr, end);
  }
  add_pgm_cmt(    "Flags                  : %08Xh%s", lc.nlm.flags, lc.buf);
  if ( clst != (uint32)-1 )
    add_pgm_cmt(  "CLIB Stack Size        : %08Xh", clst);
  if ( cl1 ) {
    if ( *cl1 )
      add_pgm_cmt("CLIB Screen Name       : %s", cl1);
    qfree(cl1);
  }
  if ( cl2 ) {
    if ( *cl2 )
      add_pgm_cmt("CLIB Thread Name       : %s", cl2);
        qfree(cl2);
  }
  if ( lc.nlm.autoliboff && lc.nlm.autolibnum ) {
    qlseek(lc.li, lc.nlm.autoliboff, SEEK_SET);
    for(i = 0; i < lc.nlm.autolibnum; i++) {
      if ( getstr() ) break;
      add_pgm_cmt("Referenced Modules     : '%s'", lc.buf);
      if ( lc.impnode ) {
        char *p1, *p2;
        for(p1 = lc.buf; p1 && *trim(p1); p1 = p2) {
          if ( (p2 = strchr(p1, '|')) != NULL ) {
            *p2++ = '\0';
            if ( !*trim(p1) ) continue;
          }
          import_module(p1, NULL, lc.impnode, NULL, "netware");
        }
      }
    }
  }

  if ( !msgpos ) return;

  qlseek(lc.li, msgpos, SEEK_SET);
  if ( mread(lc.buf, 0x7C-8) ) return;

  register uint32 id = *(uint32 *)&lc.buf[0x60-8];
  if ( id )
    add_pgm_cmt(  "Product ID             : %08Xh", id);
  id = *(uint32 *)&lc.buf[0];
  if ( id )
    add_pgm_cmt(  "Language ID            : %u", id);
  id = *(uint32 *)&lc.buf[0x34-8];
  if ( id )
    add_pgm_cmt(  "Shared Data            : off=%08Xh, size=%08Xh",
                                              *(uint32 *)&lc.buf[0x30-8], id);
  id = *(uint32 *)&lc.buf[0x2C-8];
  if ( id ) {
    add_pgm_cmt(  "Shared Code            : off=%08Xh, size=%08Xh",
                                            *(uint32 *)&lc.buf[0x28-8], id);
    add_pgm_cmt(  "Shared Start Procedure : off=%08Xh",
                                              *(uint32 *)&lc.buf[0x58-8]);
    add_pgm_cmt(  "Shared Exit Procedure  : off=%08Xh",
                                              *(uint32 *)&lc.buf[0x5C-8]);
  }
  id = *(uint32 *)&lc.buf[0x1C-8];
  if ( id )
    add_pgm_cmt(  "Help                   : off=%08Xh, size=%08Xh",
                                              *(uint32 *)&lc.buf[0x18-8], id);
  id = *(uint32 *)&lc.buf[0x24-8];
  if ( id )
    add_pgm_cmt(  "RPC & BAG              : off=%08Xh, size=%08Xh",
                                            *(uint32 *)&lc.buf[0x20-8], id);
  id = *(uint32 *)&lc.buf[0x10-8];

  if ( id ) {
    add_pgm_cmt(  "Message                : off=%08Xh, size=%08Xh",
                                    msgpos = *(uint32 *)&lc.buf[0xC-8], id);

    if ( !flg ) return;

    uint32 mlng, mcnt;
    qlseek(lc.li, msgpos + 0x6A, SEEK_SET);
    if ( mread(&mlng, sizeof(mlng)) || mread(&mcnt, sizeof(mcnt)) ) return;

    add_pgm_cmt(  "Message Language       : %08Xh", mlng);
    msgpos += 0x76;
    for(clst = 0; clst < mcnt; clst++) {
      qlseek(lc.li, msgpos + clst*4, SEEK_SET);
      if ( mread(&mlng, sizeof(mlng)) ) break;
      qlseek(lc.li, msgpos + mlng, SEEK_SET);
      if ( !LoadMsgString() ) break;
      add_pgm_cmt("   %08X : %s", clst, lc.buf);
    }
//4C - Shared Exported Symbols
//44 - Shared Imported Symbols
//3C - Shared Fixups
//54 - Shared Debug Records
  }
}

//--------------------------------------------------------------------------
static void load_image(void)
{
  uint32     off, lend = 0, addbss = 0;

  if ( (off = lc.nlm.codeoff) != 0 && (lend = lc.nlm.codelen) != 0 ) {
    lc.csize = lend;
    lc.cbase = lc.start;
  }
  for(int i = 1; ; ) {
    const char *pn, *pc;
    segment_t s;
    s.endEA   = s.startEA = lc.start;
    s.align   = saRel4K;
    s.bitness = 1;
    s.comb    = scPub;
    s.sel     = i;
    if ( i == 1 ) {
      s.type  = SEG_CODE;
      pn      = NAME_BSS;
      pc      = CLASS_CODE;
    } else {
      if ( !lend ) {
        pn = NAME_BSS;
        pc = CLASS_BSS;
      } else {
        pn     = NAME_DATA;
        pc     = CLASS_DATA;
      }
      if ( lend || addbss ) {
        s.type = SEG_DATA;
        lc.dbase = lc.start;
        lc.dsize = lend;
      }
    }
    if ( !lend && !addbss ) {
      s.type  = SEG_NULL;
      lc.start += 0x1000;
    } else {
      if ( lend )
        file2base(lc.li, off, s.startEA, s.endEA += lend, FILEREG_PATCHABLE);
      lc.start = ((s.endEA += addbss) + 0xFFF) & ~0xFFF;
    }
    set_selector(s.sel, 0);
    if ( !add_segm_ex(&s, pn, pc, ADDSEG_NOSREG)) loader_failure( );
//-
    if ( ++i > 2 ) break;
    addbss = lc.nlm.bssSize;
    lend = ((off = lc.nlm.dataoff) == 0) ? 0 : lc.nlm.datalen;
  }
}

//--------------------------------------------------------------------------
static void Unpack(void);
//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort neflag, const char * /*fileformatname*/)
{
  add_til2("nlm", ADDTIL_DEFAULT);
  if ( ph.id != PLFM_386 )
    set_processor_type("80386r", SETPROC_ALL|SETPROC_FATAL);
  inf.lflags |= LFLG_PC_FLAT;

  if ( qlread(lc.li = li, &lc.nlm, sizeof(lc.nlm)) != sizeof(lc.nlm) )
                                                            errstruct();
  if ( lc.nlm.version & NLM_COMPRESSED) Unpack( );

  lc.start = toEA(inf.baseaddr, 0);
  memset(&lc.cbase, 0, sizeof(local_data) - qoffsetof(local_data, cbase));

  load_image();
  set_default_dataseg(2);

  if ( lc.nlm.startIP < lc.csize ) {
    uval_t bip = lc.cbase + lc.nlm.startIP;
    inf.start_cs = 1;
    inf.startIP = bip;
    add_entry(bip, bip, "nlm_start", 1);
  }
  if ( (lc.nlm.endIP || lc.nlm.startIP) && lc.nlm.endIP < lc.csize ) {
    uval_t eip = lc.cbase + lc.nlm.endIP;
    add_entry(eip, eip, "nlm_terminate", 1);
  }
  if ( lc.nlm.auxIP && lc.nlm.auxIP < lc.csize ) {
    uval_t aip = lc.cbase + lc.nlm.auxIP;
    add_entry(aip, aip, "nlm_check_unload", 1);
  }

//  inf.nametype   =  NM_EA;
//  inf.s_prefflag &= ~PREF_SEGADR;
//  inf.start_ss = BADSEL;
//  inf.startSP = BADADDR;
  inf.specsegs = 1; //4-byte format of extrn/abs/common

  addImps();
  addExpPub();
  addFixups();
  addComments(neflag & NEF_RSCS);
  if ( lc.impnode )
    import_module("nlm_root", NULL, lc.impnode, NULL, "netware");
  inf.lowoff = inf.minEA;

  if ( lc.li != li) close_linput(lc.li);  // close & delete tmp (unpack ) file

  splitSRarea1(inf.beginEA, ph.regDataSreg, 2, SR_autostart, true);
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("80386r", SETPROC_ALL|SETPROC_FATAL);
  return true;
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
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
//      take care of a moved segment (fix up relocations, for example)
  NULL,
//      initialize user configurable options based on the input file.
  init_loader_options,
};
//===============unpack=====================================================
static void memerr(void)
{
  nomem("NLM-loader (for unpacking)");
}

//==========================================================================
#define OUTSIZE 8192  //2**13

static void unp_process(void);

static void Unpack(void)
{
  uint32 fsize;
  FILE *fo;

  {
    const bool must_be_false = ((sizeof(lc) - qoffsetof(local_data, nlm)) <= 0x196) ||
           (qoffsetof(local_data,buf) != (qoffsetof(local_data,nlm)+sizeof(lc.nlm)));
    char dummy[must_be_false ? -1 : 1];
    (void)dummy;
  }
  if ( qlread(lc.li, lc.buf, 0x196-sizeof(lc.nlm)) != (0x196-sizeof(lc.nlm)) )
                                                                 errstruct();
  if ( lc.buf[0x190 - sizeof(lc.nlm )] != 1  ||
     lc.buf[0x191 - sizeof(lc.nlm)] != 10)
                                    loader_failure("Unknown compressing method");
  if ( (fsize = *((uint32 *)&lc.buf[0x192 - sizeof(lc.nlm)])) <= 0x190 )
                                                                 errstruct();

  if ( (fo = qtmpfile()) == NULL )
                   loader_failure("Can not create temporary file for decompressing");
  qfwrite(fo, &lc.nlm, 0x190);

  if ( (lc.unp.buff = (uchar *)qalloc(OUTSIZE)) == NULL) memerr( );
  lc.unp.b_pos = 0x190;
  lc.unp.pos   = 0x190;
  lc.unp.b_val = 0;
  lc.unp.fo    = fo;
  lc.unp.size  = fsize;

  msg("Decompressing module...");
  unp_process();

  qfree(lc.unp.buff);
  if ( qflush(lc.unp.fo) || ferror(lc.unp.fo) || feof(lc.unp.fo) )
      loader_failure("disk full or can not write temporary file");
//  qlseek(fo, sizeof(nlm), SEEK_SET);
  msg("Ok\n");
  lc.li = make_linput(lc.unp.fo);
}

//=========================================================================
struct record {
  record   *left;
  union {
    record *right;
    uchar  data;
  };
};

//=====================================================================
static void putUnpByte(uchar data)
{
  qfputc(data, lc.unp.fo);
  ++lc.unp.pos;
  lc.unp.buff[lc.unp.b_pos] = data;
  if ( ++lc.unp.b_pos == OUTSIZE ) lc.unp.b_pos = 0;
}

//=====================================================================
static void putUnpRepeatBlk(ushort off, register ushort sizeBlk)
{
  if ( !off || !sizeBlk || (uint32)off >= lc.unp.pos) errstruct( );
  register int pos = lc.unp.b_pos - off;
  if ( pos < 0 ) pos += OUTSIZE;
  for( ; ; ) {
    putUnpByte(lc.unp.buff[pos]);
    if ( --sizeBlk == 0 ) break;
    if ( ++pos == OUTSIZE ) pos = 0;
  }
}

//=====================================================================
inline ushort nextbyte(void)
{
  uchar i;
  if ( qlread(lc.li, &i, sizeof(i)) != sizeof(i) )
    errstruct();
  return i;
}

//=====================================================================
ushort getNbit(int cnt)
{
  register ushort res = 0;
  register ushort val = lc.unp.b_val;
  register int i = cnt;
  do {
    if ( val <= 0xFF) val = nextbyte( ) | 0x8000;
    res >>= 1;
    if ( val & 1 ) res |= 0x8000;
    val >>= 1;
  } while ( --i != 0 );
  lc.unp.b_val = val;
  return(res >> (16-cnt));
}

//=====================================================================
static int getbit(void)
{
  if ( lc.unp.b_val <= 0xFF) lc.unp.b_val = nextbyte( ) | 0x8000;
  register int i = lc.unp.b_val & 1;
  lc.unp.b_val >>= 1;
  return(i);
}

//=====================================================================
inline uchar getbyte(void)
{
  if ( lc.unp.b_val <= 0xFF) return((uchar)nextbyte() );
  return((uchar)getNbit(8));
}

//=====================================================================

static uchar extractByte(register record *p)
{
  while ( p->left) p = getbit( ) ? p->right : p->left;
  return(p->data);
}

//=====================================================================
static void free_record(register record *p)
{
  if ( p->left ) {
    free_record(p->left);
    free_record(p->right);
  }
  qfree(p);
}

//=====================================================================
static record *load_record(void)
{
  register record *p = (record *)qalloc(sizeof(record));
  if ( !p) memerr( );
  if ( getbit() ) {
    p->left = NULL;
    p->data = getbyte();
  } else {
    p->left  = load_record();
    p->right = load_record();
  }
  return(p);
}

//=====================================================================
static void unp_process(void)
{
  record *rOne = load_record();
  record *rKey = load_record();
  record *rPos = load_record();

  while ( lc.unp.pos < lc.unp.size ) {
    if ( getbit() ) {
      putUnpByte(extractByte(rOne));
      continue;
    }
    ushort data = extractByte(rKey);
    switch( data )
    {
      case 255:
        {
          uint32 cnt = 0;
          lc.unp.b_val = 0;
          register int i = 8;
          do putUnpByte((uchar)nextbyte()); while ( --i != 0 );
          do {
            uchar c;
            putUnpByte(c = (uchar)nextbyte());
            cnt |= ((uint32)c << (i*8));
          } while ( ++i < 4 );
          while ( cnt--) putUnpByte((uchar)nextbyte() );
        }
        break;

      case 254:
        data = getNbit(13);
      default:
        {
          register ushort off = getNbit(5);
          off |=((ushort)extractByte(rPos) << 5);
          putUnpRepeatBlk(off, data);
        }
        break;
    }
  } // while
  if ( lc.unp.pos != lc.unp.size) errstruct( );

  free_record(rOne);
  free_record(rKey);
  free_record(rPos);
}
//=====================================================================


#pragma pack(pop)

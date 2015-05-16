/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      RT11 executable Loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

/*
        L O A D E R  for RT11 .sav-files
*/

#include "../idaldr.h"
#include "../../module/pdp11/pdp_ml.h"

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  if ( n) return(0 );
  uint32 fsize = qlsize(li);

  if ( (fsize % 512) || !fsize) return(0 );
  qlseek(li, 040);

  ushort tmp;
  lread2bytes(li, &tmp, 0);
  if ( tmp > fsize || (tmp & 1) || tmp < 0400) return(0 );
  lread2bytes(li, &tmp, 0);
  if ( tmp > fsize) return(0 );
  qlseek(li, 050);
  lread2bytes(li, &tmp, 0);
  if ( tmp & 1 || tmp > fsize) return(0 );

// 20.11.01, ig
// got tired of too many false positives
// now we'll check the file extension

  char rf[QMAXFILE];
  get_root_filename(rf, sizeof(rf));
  const char *ext = get_file_ext(rf);
  if ( ext == NULL || stricmp(ext, "sav") != 0 ) return 0;

  qstrncpy(fileformatname, "RT11 (pdp11) sav-file", MAX_FILE_FORMAT_NAME);
  return f_LOADER;
}

//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
static void loadchunk(
        linput_t *li,
        ea_t ea,
        size_t size,
        ea_t base,
        int32 fpos,
        const char *sclass)
{
  int32 p = qltell(li);
  file2base(li, fpos, ea, ea+size, FILEREG_PATCHABLE);
  add_segm(base, ea, ea+size, NULL, sclass);
  qlseek(li, p);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//

void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  if ( ph.id != PLFM_PDP )
    set_processor_type("pdp11", SETPROC_ALL|SETPROC_FATAL);
  pdp_ml_t *ml = NULL;
  netnode  *ml_ovrtrans = NULL;
  if ( ph.notify(ph.loader, &ml, &ml_ovrtrans ) ||
      !ml || !ml_ovrtrans) error("Internal error in loader<->module link");

//
//  Find out asect section and load it
//
  int i;
  segment_t s;
  s.startEA = toEA(inf.baseaddr, 0);
  qlseek(li, 040);
  ushort startIP, topPrg, svrEnd, ovt;
  lread(li, &startIP, sizeof(ushort));
  lread(li, &ml->asect_top, sizeof(ushort));
  if ( (startIP & 1) || startIP < 0400 ) startIP = 0;
  else if ( startIP ) inf.startIP = startIP;
  qlseek(li, 050);
  lread(li, &topPrg, sizeof(ushort));
  if ( topPrg & 1 || (uint32)topPrg > qlsize(li) ) topPrg = 0;
  if ( topPrg > 01000 && ml->asect_top < (topPrg - 01000 ) &&
     ml->asect_top > 0400) {
      svrEnd = ml->asect_top;
      if ( ml->asect_top > 01000 ) svrEnd = 01000;
  } else ml->asect_top = svrEnd = 01000;
  if ( startIP && ml->asect_top > startIP ) {
    svrEnd = 01000;
    if ( svrEnd > startIP ) svrEnd = startIP;
    s.endEA = s.startEA + svrEnd;
  } else s.endEA = s.startEA + ml->asect_top;
  inf.start_cs = inf.baseaddr;
  file2base(li, 0, s.startEA, s.endEA, FILEREG_PATCHABLE);
  s.type = SEG_IMEM;
  s.sel  = find_selector(inf.baseaddr);
  add_segm_ex(&s, "asect", NULL, ADDSEG_NOSREG);

  if ( inf.startIP != BADADDR) set_offset(s.startEA + 040, 0, s.startEA );
  else                        doWord(s.startEA + 040, 2);
  doWord(s.startEA + 042, 2);  // begin stack value
  doWord(s.startEA + 044, 2);  // JSW
  doWord(s.startEA + 046, 2);  // load USR address
  doWord(s.startEA + 050, 2);  // top адрес загрузки программы

  ushort begovrtbl = get_word(s.startEA + 064);
  ea_t ei;
  for(ei = s.startEA; ei < s.startEA + 040; ei += 2)
    if ( get_word(ei)) doWord(ei, 2 );
    else { delValue(ei); delValue(ei+1); }
  for(ei = s.startEA + 052; ei < s.endEA; ei += 2)
    if ( get_word(ei)) doWord(ei, 2 );
    else { delValue(ei); delValue(ei+1); }

  ovt = ml->asect_top;
  if ( s.endEA != (s.startEA + ml->asect_top) ) {
    loadchunk(li, s.endEA, ml->asect_top - svrEnd, inf.baseaddr, svrEnd, "USER");
    s.endEA += (ml->asect_top - svrEnd);
    ml->asect_top = svrEnd;
  }

  if ( get_word(s.startEA + 044) & 01000 ) {
    if ( begovrtbl == 0 ) {
      static ushort chkold[] = {010046,010146,010246,0421,010001,062701};
      qlseek(li, ovt);
      ushort temp;
      for(i = 0; i < sizeof(chkold)/2; i++) {
        lread(li, &temp, sizeof(ushort));
        if ( temp != chkold[i] ) goto nons;
      }
      lread(li, &temp, sizeof(ushort));
      if ( temp != ovt + 076 ) goto nons;
      qlseek(li, ovt + 0100);
      lread(li, &temp, sizeof(ushort));
      if ( temp != 0104376 ) goto nons;
      lread(li, &temp, sizeof(ushort));
      if ( temp != 0175400 ) {
nons:
        warning("OLD-style overlay not implemented.");
        goto stdload;
      }
      begovrtbl = ovt + 0104;
      warning("Loader overlay v3 is not fully tested.");
    } else qlseek(li, begovrtbl);
     ushort root_top;
     lread(li, &root_top, sizeof(ushort));
     if ( root_top == 0 || (root_top & 1) || root_top >= topPrg ) {
       warning("Illegal overlay structure. Not implemented.");
       goto stdload;
     }
     msg("loading overlay program...\n");
     netnode temp;    // temporary array for overlay start addresses
     temp.create();
     // load root module at the end of asect (& USER)
     loadchunk(li, s.endEA += 0x20, root_top - ovt,
               inf.start_cs = inf.baseaddr+2, ovt, "ROOT");
     add_segment_translation(inf.start_cs<<4,
                             inf.baseaddr<<4); // translate to asect
     ushort loadAddr = root_top, fileBlock, ovrsizeW,
            oldBase = 0, numOvr = 0, numSeg = 0;
     char name[8] = "ov";
     for(i = 6; loadAddr != 04537; begovrtbl += 6, i += 6) {
       if ( loadAddr != oldBase ) {
         oldBase = loadAddr;
         ++numOvr;
         numSeg = 1;
       } else ++numSeg;
       qsnprintf(&name[2], sizeof(name)-2, "%02d_%02d", numOvr, numSeg);
       lread(li, &fileBlock, sizeof(ushort));// Номер блока в файле
       lread(li, &ovrsizeW, sizeof(ushort)); // Размер сегмента в словах
       ovrsizeW <<= 1;      // in bytes
            uint32 ovrstart = (inf.maxEA & ~0xF) + (loadAddr & 0xF) + 0x10;
       uint32 sel_l = ushort((ovrstart >> 4) - (loadAddr >> 4));
       loadchunk(li, ovrstart+2, ovrsizeW-2, sel_l, fileBlock*512L+2, "OVR");
       add_segment_translation(sel_l<<4, inf.baseaddr<<4); // translate to asect
       add_segment_translation(sel_l<<4, inf.start_cs<<4);  // translate to main
       segment_t *s = getseg(ovrstart+2);
       s->ovrname = ((uint32)numOvr << 16) | numSeg;
       set_segm_name(s, "%s", name);
       temp.altset(i, ovrstart - loadAddr);
       lread(li, &loadAddr, sizeof(ushort)); // Адрес загрузки сегмента
     }
     // Здесь загрузка точек входа
     ml->ovrcallbeg = begovrtbl;
     for( ; loadAddr == 04537; begovrtbl += 8) {
       ushort ovrentry, ovrind, ovraddr;
       lread(li, &ovrentry, sizeof(ushort)); // Вход в оверлейщик - фиктивно
       lread(li, &ovrind, sizeof(ushort));  // Индекс+6 в таблице сегментов
       lread(li, &ovraddr, sizeof(ushort)); // Точка входа в сегмент
       ml_ovrtrans->altset(begovrtbl, temp.altval(ovrind) + ovraddr);
       lread(li, &loadAddr, sizeof(ushort)); // Следующий jsr R5,@#
     }
     ml->ovrcallend = begovrtbl - 8;
     temp.kill();
     ea_t base = s.endEA - ovt + ml->ovrcallbeg;
     i = ml->ovrcallend - ml->ovrcallbeg + 8;
     set_segm_start(s.endEA, base+i, SEGMOD_KILL);
     set_segm_name(getseg(base+i),"main");
     loadchunk(li, base -= 0x10, i, inf.baseaddr+1, ml->ovrcallbeg, "TBL");
     ml->ovrtbl_base = (uint32)toEA(inf.baseaddr+1, 0);
     set_segm_name(getseg(base),"ov_call");
     char labname[17] = "cl_";
     for(int j = 0; j < i; j += 8) {
       uint32 trans = (uint32)ml_ovrtrans->altval(ml->ovrcallbeg+j);
       get_segm_name(getseg(trans), name, sizeof(name));
       labname[3+7] = '\0';
       if ( !strcmp(name, &labname[3]) ) ++numSeg;
       else {
         numSeg = 1;
         qstrncpy(&labname[3], name, sizeof(labname)-3);
       }
       qsnprintf(&labname[3+7], sizeof(labname)-3-7, "_en%02d", numSeg);
       auto_make_code(trans);
       set_name(trans, &labname[3]);
       set_name(base + j, labname);
       doWord(base + j, 2*3);
       set_offset(base + j + 6, 0, get_segm_base(getseg(trans)));
     }
  } else {
//
//      Load regular file/load root of overlay
//
stdload:
    loadchunk(li, s.endEA, qlsize(li) - ovt, inf.baseaddr, ovt, "CODE");
  }
  ml_ovrtrans->altset(n_asect,  ml->asect_top);
  ml_ovrtrans->altset(n_ovrbeg, ml->ovrcallbeg);
  ml_ovrtrans->altset(n_ovrend, ml->ovrcallend);
  ml_ovrtrans->altset(n_asciiX, false);
  ml_ovrtrans->altset(n_ovrbas, ml->ovrtbl_base);
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("pdp11", SETPROC_ALL|SETPROC_FATAL);
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

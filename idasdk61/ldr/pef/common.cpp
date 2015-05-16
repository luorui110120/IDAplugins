//----------------------------------------------------------------------
static void swap_pef(pef_t &pef)
{
#if __MF__
  qnotused(pef);
#else
  pef.formatVersion    = swap32(pef.formatVersion);
  pef.dateTimeStamp    = swap32(pef.dateTimeStamp);
  pef.oldDefVersion    = swap32(pef.oldDefVersion);
  pef.oldImpVersion    = swap32(pef.oldImpVersion);
  pef.currentVersion   = swap32(pef.currentVersion);
  pef.reservedA        = swap32(pef.reservedA);
  pef.sectionCount     = swap16(pef.sectionCount);
  pef.instSectionCount = swap16(pef.instSectionCount);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_section(pef_section_t &ps)
{
#if __MF__
  qnotused(ps);
#else
  ps.nameOffset        = swap32(ps.nameOffset     );
  ps.defaultAddress    = swap32(ps.defaultAddress );
  ps.totalSize         = swap32(ps.totalSize      );
  ps.unpackedSize      = swap32(ps.unpackedSize   );
  ps.packedSize        = swap32(ps.packedSize     );
  ps.containerOffset   = swap32(ps.containerOffset);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_loader(pef_loader_t &pl)
{
#if __MF__
  qnotused(pl);
#else
  pl.mainSection              = swap32(pl.mainSection             );
  pl.mainOffset               = swap32(pl.mainOffset              );
  pl.initSection              = swap32(pl.initSection             );
  pl.initOffset               = swap32(pl.initOffset              );
  pl.termSection              = swap32(pl.termSection             );
  pl.termOffset               = swap32(pl.termOffset              );
  pl.importLibraryCount       = swap32(pl.importLibraryCount      );
  pl.totalImportedSymbolCount = swap32(pl.totalImportedSymbolCount);
  pl.relocSectionCount        = swap32(pl.relocSectionCount       );
  pl.relocInstrOffset         = swap32(pl.relocInstrOffset        );
  pl.loaderStringsOffset      = swap32(pl.loaderStringsOffset     );
  pl.exportHashOffset         = swap32(pl.exportHashOffset        );
  pl.exportHashTablePower     = swap32(pl.exportHashTablePower    );
  pl.exportedSymbolCount      = swap32(pl.exportedSymbolCount     );
#endif
}

//----------------------------------------------------------------------
static void swap_pef_library(pef_library_t &pil)
{
#if __MF__
  qnotused(pil);
#else
  pil.nameOffset          = swap32(pil.nameOffset         );
  pil.oldImpVersion       = swap32(pil.oldImpVersion      );
  pil.currentVersion      = swap32(pil.currentVersion     );
  pil.importedSymbolCount = swap32(pil.importedSymbolCount);
  pil.firstImportedSymbol = swap32(pil.firstImportedSymbol);
  pil.reservedB           = swap16(pil.reservedB         );
#endif
}

//----------------------------------------------------------------------
static void swap_pef_reloc_header(pef_reloc_header_t &prh)
{
#if __MF__
  qnotused(prh);
#else
  prh.sectionIndex     = swap16(prh.sectionIndex);
  prh.reservedA        = swap16(prh.reservedA);
  prh.relocCount       = swap32(prh.relocCount);
  prh.firstRelocOffset = swap32(prh.firstRelocOffset);
#endif
}

//----------------------------------------------------------------------
static void swap_pef_export(pef_export_t &pe)
{
#if __MF__
  qnotused(pe);
#else
  pe.classAndName = swap32(pe.classAndName);
  pe.symbolValue  = swap32(pe.symbolValue);
  pe.sectionIndex = swap16(pe.sectionIndex);
#endif
}

//----------------------------------------------------------------------
bool is_pef_file(linput_t *li)
{
  pef_t pef;
  if ( qlread(li, &pef, sizeof(pef_t)) != sizeof(pef_t) )
    return false;
  swap_pef(pef);
  return strncmp(pef.tag1,PEF_TAG_1,4) == 0     // Joy!
      && strncmp(pef.tag2,PEF_TAG_2,4) == 0     // peff
      && pef.formatVersion == PEF_VERSION       // 1
      && (strncmp(pef.architecture,PEF_ARCH_PPC,4) == 0         // PowerPC
       || strncmp(pef.architecture,PEF_ARCH_68K,4) == 0);       // or 68K
}

//----------------------------------------------------------------------
static char *get_string(
        linput_t *li,
        int32 snames_table,
        int32 off,
        char *buf,
        size_t bufsize)
{
  if ( ssize_t(bufsize) <= 0 )
    return NULL;

  if ( off == -1 )
  {
    buf[0] = '\0';
    return NULL;
  }
  qlseek(li, snames_table+off);
  lread(li, buf, bufsize);
  buf[bufsize-1] = '\0';
  return buf;
}

//----------------------------------------------------------------------
inline char *get_impsym_name(char *stable, const void *end, uint32 *impsym, int i)
{
  size_t off = mflong(impsym[i]) & 0xFFFFFF;
  if ( stable+off >= end )
    return NULL;
  return stable+off;
}

//----------------------------------------------------------------------
inline size_t get_expsym_name_length(uint32 *keytable, int i)
{
  return mflong(keytable[i]) >> 16;
}

//----------------------------------------------------------------------
static bool get_expsym_name(
        char *stable,
        uint32 *keytable,
        pef_export_t *pe,
        int i,
        const void *end,
        char *buf,
        size_t bufsize)
{
  pe += i;
  size_t off = (pe->classAndName & 0xFFFFFFL);
  size_t len = get_expsym_name_length(keytable, i);
  if ( len >= bufsize )
    len = bufsize-1;
  if ( stable+off+len >= end )
    return false;
  memcpy(buf, stable+off, len);
  buf[len] = 0;
  return true;
}



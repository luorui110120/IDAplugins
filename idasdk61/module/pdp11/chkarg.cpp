
//---------------------------------------------------------------------
static bool cmpseg_pdp11(sel_t sel1, sel_t sel2)
{
  if ( sel1 && sel2 ) {
#ifndef CHKARG_TEST
    segment_t *s;
    ushort    ov;

    if(   (s = get_segm_by_sel(sel1)) != NULL
       && (ov = (ushort)(s->ovrname >> 16)) != 0
       && (s = get_segm_by_sel(sel2)) != NULL
       && (ushort)(s->ovrname >> 16) == ov)         return(true);
#else   // CHKARG_TEST
    short diff = (short)(sel1-sel2);
    if ( diff != 1 &&  diff != -1) return(true );
#endif  // CHKARG_TEST
  }
  return(false);
}

//---------------------------------------------------------------------
static bool preline_pdp11(char *ss, s_preline *S)
{
#ifdef CHKARG_TEST
  static const char * const RegNames[] = {
    "R0", "R1", "R2", "R3", "R4", "R5", "SP", "PC"
  };
#define is_visible_char(c)  qisalnum(c)
#endif  // CHKARG_TEST

  char  s[PRELINE_SIZE];
  int   i;
  char  *pc1, *pc2, *reg, *offset, *pc, *iaflg;

  iaflg   = S->iaflg;
  reg     = S->reg;
  offset  = S->offset;

  qstrncpy(reg, "(PC)", PRELINE_SIZE);

  pc1 = qstrncpy(s, ss, sizeof(s));

  if ( *pc1 == '@' ) {
    *iaflg = 1;
    ++pc1;
  }
  for(i = 0; i < 8; i++) {
    if ( !strnicmp(pc1, RegNames[i], 2) && !is_visible_char(pc1[2]) ) {
      if ( *iaflg ) {
        *iaflg = 0;
        qsnprintf(reg, PRELINE_SIZE, "(%s)", RegNames[i]);
      } else qstrncpy(reg, RegNames[i], PRELINE_SIZE);
      return(!pc1[2]);
    }
  }
  if ( *pc1 == '#' ) {
    qstrncpy(reg, "(PC)" CA_PLUS_STR, PRELINE_SIZE);
    pc1++;
  } else if ( (pc = strchr(pc1, '(')) != NULL ) {
    if ( pc > pc1 && pc[-1] == ca_minus ) --pc;
    *reg = *pc;
    *pc++ = '\0';
    for(pc2 = reg+1; ; ) {
      if ( !*pc) return(false );
      *pc2++ = *pc;
      if ( *pc++ == ')' ) {
        if ( *pc == ca_plus ) *pc2++ = *pc++;
        if ( (*pc2++ = *pc++) != '\0') return(false ); // syntax
        break;
      }
    }
  }

  strupr(reg);
  qstrncpy(offset, pc1, PRELINE_SIZE);
  if ( *iaflg && !*offset && strlen(reg) == 4) *(ushort* )offset = '0';
  return(true);
}

//---------------------------------------------------------------------
static bool idaapi chkarg_dispatch_pdp11(void *a1, void *a2, uchar cmd)
{
  static char const * const operdim[15] = {  // ALWAYS and STRONGLY 15
     "<", ">", "", "-", "+", "",
     "\\", "/", "*", "&", "!", "^", "", "", NULL};

  switch ( cmd ) {
    case chkarg_cmpseg:
      return(cmpseg_pdp11((sel_t)(size_t)a1, (sel_t)(size_t)a2));

    case chkarg_preline:
      return(preline_pdp11((char*)a1, (s_preline *)a2));

    case chkarg_gettable:
      *(const char * const **)a2 = operdim;
      return(true);

    default:  // chkarg_operseg, chkarg_atomprefix:
      break;
  }
  return(false);
}

//---------------------------------------------------------------------

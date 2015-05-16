#include <ieee.h>
#define E IEEE_E
#define M IEEE_M
#define EXONE IEEE_EXONE

int idaapi realcvt(void *m, eNE e, unsigned short swt)
{
  eNI x;
  long exp;
  register unsigned short r, *p = (unsigned short *)m;

  switch(swt) {
    case 1:            // in float
    case 0:            // in trunc. float
    case 3:            // in double
      ecleaz(x);
      x[0] = ((r = *p) & 0x8000) ? 0xffff : 0;  /* fill in our sign */
      if(!(r &= (0377 << 7))) {
        for(r = swt + 1; r; r--) if(*p++) return(-3);
      } else {
        x[E] = (r >> 7) + (EXONE - 0201); /* DEC exponent offset */
        x[M] = (*p++ & 0177) | 0200; /* now do the high order mantissa */
        if(swt) memcpy(&x[M+1], p, swt*sizeof(unsigned short));
        eshift(x, -8);  /* shift our mantissa down 8 bits */
      }
      if(e) emovo(x, e);  // convert to IEEE format
      break;

    case 011:          // out float
    case 010:          // out trunc. float
    case 013:          // out double
      emovi(e, x);
      r = swt & 3;
      if(!x[E]) goto clear;
      exp = (long )x[E] - (EXONE - 0201);
      if(!emdnorm(x, 0, 0, exp, 56) || x[E] >= 0377) return(-2); // overfloat
      if(!x[E]) {
clear:
        memset(p, 0, (r + 1)*sizeof(unsigned short));
      } else {
        *p = (x[0] ? 0100000 : 0) | (x[E] << 7);  /* sign & exp */
        eshift(x, 8);
        *p++ |= (x[M] & 0177);
        if(r) memcpy(p, &x[M+1], r*sizeof(unsigned short));
      }
      break;

    default:
      return(-1);
  }

  return(0);
}

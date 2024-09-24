#include <ieee.h>
#define E IEEE_E
#define M IEEE_M
#define EXONE IEEE_EXONE

// one of the many possible NaNs,
// the one produced by the base converter
const fpvalue_t ieee_nan = {{ 0, 0, 0, 0, 0, 0, 0xc000, 0xffff }};

fpvalue_error_t idaapi realcvt(void *m, fpvalue_t *e, uint16 swt)
{
  eNI x;
  long exp;
  uint16 r, msk, *p = (uint16 *)m;

  switch ( swt )
  {
    case 1:            // in float
    case 0:            // in trunc. float
    case 3:            // in double
      ecleaz(x);
      x[0] = ((r = *p) & 0x8000) ? 0xffff : 0;  /* fill in our sign */
      r &= (0377 << 7);
      if ( r == 0 )
      {
        if ( x[0] ) // negative and zero exponent = Undefined -> transformed to NaN
        {
          memcpy(e, &ieee_nan, sizeof(fpvalue_t));
          break;
        }
        // complain on dirty zero
        for ( msk = 0x7fff, r = swt + 1; r; r--, msk = 0xffff )
          if ( *p++ & msk )
            return REAL_ERROR_BADDATA; // signed zero accepted
      }
      else
      {
        x[E] = (r >> 7) + (EXONE - 0201); /* DEC exponent offset */
        x[M] = (*p++ & 0177) | 0200; /* now do the high order mantissa */
        if ( swt )
          memcpy(&x[M+1], p, swt*sizeof(uint16));
        eshift(x, -8);  /* shift our mantissa down 8 bits */
      }
      emovo(x, e);  // convert to IEEE format
      break;

    case 011:          // out float
    case 010:          // out trunc. float
    case 013:          // out double
      emovi(*e, x);
      r = swt & 3;
      if ( !x[E] )
        goto clear;
      if ( x[E] == E_SPECIAL_EXP )
      {
        // all of NaN, +/-Inf transformed to "Undefined value"
        x[0] = 0xffff;
        x[E] = 0;
        goto clear;
      }
      exp = (long )x[E] - (EXONE - 0201);
      if ( !emdnorm(x, 0, 0, exp, 56) || x[E] >= 0377 )
        return REAL_ERROR_RANGE; // overfloat
      if ( !x[E] )
      {
clear:
        memset(p, 0, (r + 1)*sizeof(uint16));
        if ( x[0] )
          *p = 0x8000; // signed zero accepted
      }
      else
      {
        *p = (x[0] ? 0100000 : 0) | (x[E] << 7);  /* sign & exp */
        eshift(x, 8);
        *p++ |= (x[M] & 0177);
        if ( r != 0 )
          memcpy(p, &x[M+1], r*sizeof(uint16));
      }
      break;

    default:
      return REAL_ERROR_FORMAT;
  }

  return REAL_ERROR_OK;
}

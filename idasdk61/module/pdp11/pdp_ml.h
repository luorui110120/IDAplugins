#ifndef __pdp_ml_h__
#define __pdp_ml_h__

typedef struct {
  uint32 ovrtbl_base;
  uint16 ovrcallbeg, ovrcallend, asect_top;
}pdp_ml_t;

#define ovrname orgbase         // for compatibily with old version
                                // in Segment structure

enum store_mode_values {
  n_asect  = -1,
  n_ovrbeg = -2,
  n_ovrend = -3,
  n_asciiX = -4,
  n_ovrbas = -5
};

#endif

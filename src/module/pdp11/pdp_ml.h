#ifndef __pdp_ml_h__
#define __pdp_ml_h__

struct pdp_ml_t
{
  uint32 ovrtbl_base;
  uint16 ovrcallbeg, ovrcallend, asect_top;
};

#define ovrname orgbase         // for compatibily with old version
                                // in Segment structure

enum store_mode_values
{
  n_asect  = -1,
  n_ovrbeg = -2,
  n_ovrend = -3,
  n_asciiX = -4,
  n_ovrbas = -5
};

//----------------------------------------------------------------------
// The following events are supported by the PDP11 module in the ph.notify() function
namespace pdp11_module_t
{
  enum event_codes_t
  {
    ev_get_ml_ptr = processor_t::ev_loader,
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline bool get_ml_ptr(pdp_ml_t **ml, netnode **ml_ovrtrans)
  {
    return processor_t::notify(idp_ev(ev_get_ml_ptr), ml, ml_ovrtrans) == 0;
  }
}

#endif

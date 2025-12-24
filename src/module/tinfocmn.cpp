
//-------------------------------------------------------------------------
// Some ABIs pass simple structures (like std::complex) in registers.
// To detect such structures the proc module can use the following helper.
struct flat_member_t
{
  uint    off;  // the member offset in the stucture (in bytes)
  tinfo_t type; // the member type
};
// Return the scalar members of the structure.
// For example, for 'struct { struct { float f[1]; } g[2]; }' it returns 2
// floats.
// \param[out] parts      the scalar members
// \param[in]  maxparts   the maximum number of members
// \param[in]  type       the stucture
// \return success (i.e. TYPE has less than MAXPARTS flat members and they
//         are in PARTS)
bool flatten_struct(
        qvector<flat_member_t> *parts,
        size_t maxparts,
        const tinfo_t &type)
{
  struct ida_local member_collector_t
  {
    qvector<flat_member_t> &parts;
    size_t maxparts;
    member_collector_t(
        qvector<flat_member_t> *_parts,
        size_t _maxparts)
      : parts(*_parts), maxparts(_maxparts) {}
    // it returns the 'success' flag
    bool visit_type(const tinfo_t &tif, uint offset)
    {
      if ( tif.is_udt() )
      {
        udt_type_data_t udt;
        if ( !tif.get_udt_details(&udt) )
          return false;
        if ( udt.is_union && udt.size() > 1 )
          return false;
        if ( parts.size() + udt.size() > maxparts )
          return false; // a fast path
        for ( const udm_t &udm : udt )
        {
          // the member must be on the byte boundary
          // a) argpart_t uses the byte offset
          // b) the flattening members are always on the byte boundary
          //    because we allow only the first bitfield
          if ( udm.offset % 8 != 0 )
            return false;
          uint udm_offset = offset + udm.offset / 8;
          if ( !visit_type(udm.type, udm_offset) )
            return false;
        }
        return true;
      }
      if ( tif.is_array() )
      {
        array_type_data_t ai;
        if ( !tif.get_array_details(&ai) )
          return false;
        if ( parts.size() + ai.nelems > maxparts )
          return false; // a fast path
        size_t elem_size = ai.elem_type.get_size();
        uint elem_offset = offset;
        for ( size_t i = 0; i < ai.nelems; ++i )
        {
          if ( !visit_type(ai.elem_type, elem_offset) )
            return false;
          elem_offset += elem_size;
        }
        return true;
      }
      if ( tif.is_ext_arithmetic() )
      {
        if ( parts.size() >= maxparts )
          return false; // only 2 members allowed
        parts.push_back( { offset, tif } );
        return true;
      }
      return false;
    }
  };
  member_collector_t mc(parts, maxparts);
  return mc.visit_type(type, 0);
}


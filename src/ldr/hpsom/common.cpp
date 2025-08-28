
//--------------------------------------------------------------------------
void sys_clock::swap(void)
{
  secs     = swap32(secs);
  nanosecs = swap32(nanosecs);
};

//--------------------------------------------------------------------------
void header::swap(void)
{
  system_id=                  swap16(system_id);
  a_magic=                    swap16(a_magic);
  file_time.swap();
  version_id=                 swap32(version_id);
  entry_space=                swap32(entry_space);
  entry_subspace=             swap32(entry_subspace);
  entry_offset=               swap32(entry_offset);
  aux_header_location=        swap32(aux_header_location);
  aux_header_size=            swap32(aux_header_size);
  som_length=                 swap32(som_length);
  presumed_dp=                swap32(presumed_dp);
  space_location=             swap32(space_location);
  space_total=                swap32(space_total);
  subspace_location=          swap32(subspace_location);
  subspace_total=             swap32(subspace_total);
  loader_fixup_location=      swap32(loader_fixup_location);
  loader_fixup_total=         swap32(loader_fixup_total);
  space_strings_location=     swap32(space_strings_location);
  space_strings_size=         swap32(space_strings_size);
  init_array_location=        swap32(init_array_location);
  init_array_total=           swap32(init_array_total);
  compiler_location=          swap32(compiler_location);
  compiler_total=             swap32(compiler_total);
  symbol_location=            swap32(symbol_location);
  symbol_total=               swap32(symbol_total);
  fixup_request_location=     swap32(fixup_request_location);
  fixup_request_total=        swap32(fixup_request_total);
  symbol_strings_location=    swap32(symbol_strings_location);
  symbol_strings_size=        swap32(symbol_strings_size);
  unloadable_sp_location=     swap32(unloadable_sp_location);
  unloadable_sp_size=         swap32(unloadable_sp_size);
  checksum=                   swap32(checksum);
}

//--------------------------------------------------------------------------
void aux_id::swap(void)
{
  type   = swap16(type);
  length = swap32(length);
}

//--------------------------------------------------------------------------
void som_exec_auxhdr::swap(void)
{
  header_id.swap();
  exec_tsize = swap32(exec_tsize);         /* text size */
  exec_tmem  = swap32(exec_tmem);          /* start address of text */
  exec_tfile = swap32(exec_tfile);         /* file ptr to text */
  exec_dsize = swap32(exec_dsize);         /* data size */
  exec_dmem  = swap32(exec_dmem);          /* start address of data */
  exec_dfile = swap32(exec_dfile);         /* file ptr to data */
  exec_bsize = swap32(exec_bsize);         /* bss size */
  exec_entry = swap32(exec_entry);         /* address of entry point */
  exec_flags = swap32(exec_flags);         /* loader flags */
  exec_bfill = swap32(exec_bfill);         /* bss initialization value */
}

//--------------------------------------------------------------------------
void user_string_aux_hdr::swap(void)       /* Version string auxiliary header */
{
  header_id.swap();
  string_length = swap32(string_length);   /* strlen(user_string) */
}

//--------------------------------------------------------------------------
void copyright_aux_hdr::swap(void)
{
  header_id.swap();
  string_length = swap32(string_length);   /* strlen(user_string) */
}

//--------------------------------------------------------------------------
void shlib_version_aux_hdr::swap(void)
{
  header_id.swap();
  version = swap16(version);               /* version number */
}

//--------------------------------------------------------------------------
void space_dictionary_record::swap(void)
{
  name.n_strx            = swap32(name.n_strx);
  space_number           = swap32(space_number);
  subspace_index         = swap32(subspace_index);
  subspace_quantity      = swap32(subspace_quantity);
  loader_fix_index       = swap32(loader_fix_index);
  loader_fix_quantity    = swap32(loader_fix_quantity);
  init_pointer_index     = swap32(init_pointer_index);
  init_pointer_quantity  = swap32(init_pointer_quantity);
};

//--------------------------------------------------------------------------
void subspace_dictionary_record::swap(void)
{
  space_index            = swap32(space_index);
  file_loc_init_value    = swap32(file_loc_init_value);
  initialization_length  = swap32(initialization_length);
  subspace_start         = swap32(subspace_start);
  subspace_length        = swap32(subspace_length);
  reserved2              = swap16(reserved2);
  alignment              = swap16(alignment);
  name.n_strx            = swap32(name.n_strx);
  fixup_request_index    = swap32(fixup_request_index);
  fixup_request_quantity = swap32(fixup_request_quantity);
}

//--------------------------------------------------------------------------
void symbol_dictionary_record::swap(void)
{
  name.n_strx           = swap32(name.n_strx);
  qualifier_name.n_strx = swap32(qualifier_name.n_strx);
  symbol_info           = swap32(symbol_info);
  symbol_value          = swap32(symbol_value);
}

//--------------------------------------------------------------------------
void dl_header::swap(void)
{
  hdr_version       = swap32(hdr_version);
  ltptr_value       = swap32(ltptr_value);
  shlib_list_loc    = swap32(shlib_list_loc);
  shlib_list_count  = swap32(shlib_list_count);
  import_list_loc   = swap32(import_list_loc);
  import_list_count = swap32(import_list_count);
  hash_table_loc    = swap32(hash_table_loc);
  hash_table_size   = swap32(hash_table_size);
  export_list_loc   = swap32(export_list_loc);
  export_list_count = swap32(export_list_count);
  string_table_loc  = swap32(string_table_loc);
  string_table_size = swap32(string_table_size);
  dreloc_loc        = swap32(dreloc_loc);
  dreloc_count      = swap32(dreloc_count);
  dlt_loc           = swap32(dlt_loc);
  plt_loc           = swap32(plt_loc);
  dlt_count         = swap32(dlt_count);
  plt_count         = swap32(plt_count);
  highwater_mark    = swap16(highwater_mark);
  flags             = swap16(flags);
  export_ext_loc    = swap32(export_ext_loc);
  module_loc        = swap32(module_loc);
  module_count      = swap32(module_count);
  elaborator        = swap32(elaborator);
  initializer       = swap32(initializer);
  embedded_path     = swap32(embedded_path);
  initializer_count = swap32(initializer_count);
  tdsize            = swap32(tdsize);
  fastbind_list_loc = swap32(fastbind_list_loc);
}

//--------------------------------------------------------------------------
void import_entry::swap(void)
{
  name = swap32(name);
}

//--------------------------------------------------------------------------
void misc_info::swap(void)
{
  version = swap16(version);
  flags   = swap16(flags);
}

//--------------------------------------------------------------------------
void export_entry::swap(void)
{
  next  = swap32(next);
  name  = swap32(name);
  value = swap32(value);
  if ( type == ST_STORAGE )
    info.size = swap32(info.size);
  else
    info.misc.swap();
  module_index = swap16(module_index);
}

//--------------------------------------------------------------------------
static uint32 compute_som_checksum(void *p)
{
  int n = sizeof(header) / sizeof(uint32);
  uint32 *ptr = (uint32 *)p;
  uint32 sum = 0;
  for ( int i=0; i < n; i++ )
    sum ^= *ptr++;
  return sum;
}


//--------------------------------------------------------------------------
static void swap_exec(exec &ex)
{
  ex.a_info   = swap32(ex.a_info);
  ex.a_text   = swap32(ex.a_text);
  ex.a_data   = swap32(ex.a_data);
  ex.a_bss    = swap32(ex.a_bss);
  ex.a_syms   = swap32(ex.a_syms);
  ex.a_entry  = swap32(ex.a_entry);
  ex.a_trsize = swap32(ex.a_trsize);
  ex.a_drsize = swap32(ex.a_drsize);
}

//--------------------------------------------------------------------------
int get_aout_file_format_index(linput_t *li, exec *_ex)
{
  exec &ex = *_ex;
  int i = 0;
  if ( qlread(li, &ex, sizeof(ex)) != sizeof(ex) )
    return false;

  if ( N_BADMAG(ex) )
  {
    swap_exec(ex);
    switch ( N_MACHTYPE(ex) )
    {
      case M_386_NETBSD:
      case M_68K_NETBSD:
      case M_68K4K_NETBSD:
      case M_532_NETBSD:
      case M_SPARC:
      case M_SPARC_NETBSD:
      case M_PMAX_NETBSD:
      case M_VAX_NETBSD:
      case M_ALPHA_NETBSD:
      case M_ARM6_NETBSD:
        break;

      default:
        return false;
    }
  }

  switch ( N_MAGIC(ex) )
  {
    case NMAGIC:
      ++i;
    case CMAGIC:
      ++i;
    case ZMAGIC:
      ++i;
    case OMAGIC:
      ++i;
    case QMAGIC:
      if ( N_MACHTYPE(ex) == M_SPARC )
        break; // SPARC uses different TXTOFF

#ifdef DEBUG
      msg("magic=%04x text=%08x data=%08x symsize=%08x txtoff=%08x sum=%08x // qlsize=%08x\n", N_MAGIC(ex), ex.a_text, ex.a_data,
          N_SYMSIZE(ex), N_TXTOFF(ex), ex.a_text + ex.a_data + N_SYMSIZE(ex) + N_TXTOFF(ex),
          qlsize(li));
#endif
      if ( qlsize(li) >= ex.a_text + ex.a_data + N_SYMSIZE(ex) + N_TXTOFF(ex) )
        break;
      if ( N_MAGIC(ex) == ZMAGIC
        && qlsize(li) >= ex.a_text + ex.a_data + N_SYMSIZE(ex) )
      {
        i = 5; // OpenBSD demand-paged
        break;
      }
    default:
      return false;
  }

  return i+1;
}

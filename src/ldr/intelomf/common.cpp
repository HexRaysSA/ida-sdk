
//-----------------------------------------------------------------------
bool is_intelomf_file(linput_t *li)
{
  uchar magic;
  lmh h;
  qlseek(li, 0);
  if ( qlread(li, &magic, sizeof(magic)) != sizeof(magic)
    || qlread(li, &h, sizeof(h)) != sizeof(h) )
  {
    return false;
  }
  int64 fsize = qlsize(li);
  return magic == INTELOMF_MAGIC_BYTE
      && h.tot_length < fsize;
}

//-----------------------------------------------------------------------
static int read_pstring(linput_t *li, char *name, int size)
{
  char buf[256];
  uchar nlen;
  lread(li, &nlen, sizeof(nlen));
  lread(li, buf, nlen);
  buf[nlen] = '\0';
  qstrncpy(name, buf, size);
  return nlen;
}

//-----------------------------------------------------------------------
static uint32 readdw(const uchar *&ptr, bool wide)
{
  uint32 x;
  if ( wide )
  {
    x = *(uint32 *)ptr;
    ptr += sizeof(uint32);
  }
  else
  {
    x = *(uint16 *)ptr;
    ptr += sizeof(uint16);
  }
  return x;
}


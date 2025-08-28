
//-------------------------------------------------------------------------
static void swap_prc(DatabaseHdrType &h)
{
  h.attributes         = swap16(h.attributes);
  h.version            = swap16(h.version);
  h.creationDate       = swap32(h.creationDate);
  h.modificationDate   = swap32(h.modificationDate);
  h.lastBackupDate     = swap32(h.lastBackupDate);
  h.modificationNumber = swap32(h.modificationNumber);
  h.appInfoID          = swap32(h.appInfoID);
  h.sortInfoID         = swap32(h.sortInfoID);
//  h.type             = swap32(h.type);
//  h.id               = swap32(h.id);
  h.uniqueIDSeed       = swap32(h.uniqueIDSeed);
  h.nextRecordListID   = swap32(h.nextRecordListID);
  h.numRecords         = swap16(h.numRecords);
}

//-------------------------------------------------------------------------
static void swap_resource_map_entry(ResourceMapEntry &re)
{
  re.id       = swap16(re.id);
  re.ulOffset = swap32(re.ulOffset);
}

//-------------------------------------------------------------------------
void swap_bitmap(pilot_bitmap_t *b)
{
  b->cx = swap16(b->cx);
  b->cy = swap16(b->cy);
  b->cbRow = swap16(b->cbRow);
  b->ausUnk[0] = swap16(b->ausUnk[0]);
  b->ausUnk[1] = swap16(b->ausUnk[1]);
  b->ausUnk[2] = swap16(b->ausUnk[2]);
  b->ausUnk[3] = swap16(b->ausUnk[3]);
}

//-------------------------------------------------------------------------
void swap_code0000(code0000_t *cp)
{
  cp->nBytesAboveA5 = swap32(cp->nBytesAboveA5);
  cp->nBytesBelowA5 = swap32(cp->nBytesBelowA5);
}

//-------------------------------------------------------------------------
void swap_pref0000(pref0000_t *pp)
{
  pp->flags      = swap16(pp->flags);
  pp->stack_size = swap32(pp->stack_size);
  pp->heap_size  = swap32(pp->heap_size);
}

//-------------------------------------------------------------------------
// Since the Palm Pilot programs are really poorly recognized by usual
// methods, we are forced to read the resource tablee to determine
// if everying is ok
// return 0 if not a PRC, 2 if has ARM code segments, 1 otherwise
int is_prc_file(linput_t *li)
{
  DatabaseHdrType h;
  if ( qlread(li,&h,sizeof(h)) != sizeof(h) )
    return 0;
  swap_prc(h);
  if ( (h.attributes & dmHdrAttrResDB) == 0 )
    return 0;
  if ( short(h.numRecords) <= 0 )
    return 0;
  const uint64 filesize = qlsize(li);
  const uint64 lowestpos = uint64(h.numRecords)*sizeof(ResourceMapEntry) + sizeof(h);
  if ( lowestpos > filesize )
    return 0;

  // the dates can be plain wrong, so don't check them:
  // uint32 now = time(nullptr);
  // && uint32(h.lastBackupDate) <= now    // use unsigned comparition!
  // && uint32(h.creationDate) <= now      // use unsigned comparition!
  // && uint32(h.modificationDate) <= now  // use unsigned comparition!

  qvector<ResourceMapEntry> re;
  re.resize(h.numRecords);
  size_t size = sizeof(ResourceMapEntry) * h.numRecords;
  if ( qlread(li, re.begin(), size) != size )
    return 0;

  bool hasArmCode = false;
  for ( int i=0; i < h.numRecords; i++ )
  {
    swap_resource_map_entry(re[i]);
    if ( re[i].ulOffset >= filesize || re[i].ulOffset < lowestpos )
      return 0;
    if ( re[i].fcType == PILOT_RSC_ARMC || re[i].fcType == PILOT_RSC_ARMCL )
      hasArmCode = true;
  }
  return hasArmCode ? 2 : 1;
}

bool isKnownResource(uint32 resId)
{
  switch ( resId )
  {
    case MC4('t', 'F', 'R', 'M'):
    case MC4('t', 'B', 'T', 'N'):
    case MC4('t', 'C', 'B', 'X'):
    case MC4('t', 'F', 'B', 'M'):
    case MC4('t', 'F', 'L', 'D'):
    case MC4('t', 'g', 'b', 'n'):
    case MC4('t', 'G', 'D', 'T'):
    case MC4('t', 'g', 'p', 'b'):
    case MC4('t', 'g', 'r', 'b'):
    case MC4('t', 'G', 'S', 'I'):
    case MC4('t', 'L', 'B', 'L'):
    case MC4('t', 'L', 'S', 'T'):
    case MC4('t', 'P', 'B', 'N'):
    case MC4('t', 'P', 'U', 'L'):
    case MC4('t', 'P', 'U', 'T'):
    case MC4('t', 'R', 'E', 'P'):
    case MC4('t', 'S', 'C', 'L'):
    case MC4('t', 's', 'l', 'd'):
    case MC4('t', 's', 'l', 'f'):
    case MC4('t', 'S', 'L', 'T'):
    case MC4('t', 'T', 'B', 'L'):
    case MC4('T', 'a', 'l', 't'):
    case MC4('M', 'B', 'A', 'R'):
    case MC4('M', 'E', 'N', 'U'):
    case MC4('t', 'S', 'T', 'R'):
    case MC4('t', 'S', 'T', 'L'):
    case MC4('T', 'b', 'm', 'p'):
    case MC4('t', 'b', 'm', 'f'):
    case MC4('P', 'I', 'C', 'T'):
    case MC4('t', 'v', 'e', 'r'):
    case MC4('t', 'A', 'I', 'N'):
    case MC4('t', 'a', 'i', 'c'):
    case MC4('t', 'A', 'I', 'S'):
    case MC4('t', 'A', 'I', 'B'):
    case MC4('t', 'a', 'i', 'f'):
    case MC4('I', 'C', 'O', 'N'):
    case MC4('c', 'i', 'c', 'n'):
    case MC4('p', 'r', 'e', 'f'):
    case MC4('x', 'p', 'r', 'f'):
      return true;
  }
  return false;
}

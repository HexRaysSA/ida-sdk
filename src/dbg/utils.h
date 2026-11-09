
//----------------------------------------------------------------------
inline int get_system_specific_errno()
{
  // this code must be acceptable by winerr()
#ifdef __NT__
  return GetLastError();
#else
  return errno;
#endif
}


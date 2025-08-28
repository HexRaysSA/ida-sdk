
#ifndef __MAS_HPP_
#define __MAS_HPP_
#pragma pack(push, 1)

#define START_SEQUENCE  0x1489

struct mas_header_t
{
  uchar header;
  uchar segment;
  uchar gran;
  int start_addr;
  short length;
};

#pragma pack(pop)
#endif /* __MAS_HPP_ */


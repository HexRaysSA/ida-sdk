/*
SPECIAL LICENSE AGREEMENT

This file originally comes from the 'higan' emulator
<http://byuu.org/emulation/higan/>, and should normally only be
used in agreement with the terms of the GPLv3 license. //-V1042

Hex-Rays has been granted, by written consent of its author, the use
of this file within the scope of the 'snes' loader plugin, as well as
within the scope of the '65816' processor module for the Interactive
DisAssembler, without requiring Hex-Rays to release any other source code
that composes the Interactive DisAssembler (or any of its plugins.)
This special license agreement extends to anyone who may want to
modify, re-compile & re-link the 'snes' loader or the '65816' processor
module.

The stated agreement stands only for use of this file within the
'snes' loader plugin and the '65816' processor module for the Interactive
DisAssembler, and cannot be applied to any other project (other
Interactive DisAssembler plugin, or unrelated project.)

Should this file be included in another project than the 'snes' loader
or the '65816' processor module for the Interactive DisAssembler, the
original GPLv3 licensing terms will apply.
*/

// This file is included from the loader module and the processor module

// original source: higan/ananke/heuristics/super-famicom.hpp

#ifndef __SUPER_FAMICOM_HPP__
#define __SUPER_FAMICOM_HPP__

struct SuperFamicomCartridge
{
  SuperFamicomCartridge() {}
  SuperFamicomCartridge(linput_t *li);

// private:
  void read_header(linput_t *li);
  static unsigned find_header(linput_t *li);
  static unsigned score_header(linput_t *li, unsigned addr);

  enum HeaderField
  {
    CartName    = 0x00,
    Mapper      = 0x15,
    RomType     = 0x16,
    RomSize     = 0x17,
    RamSize     = 0x18,
    CartRegion  = 0x19,
    Company     = 0x1a,
    Version     = 0x1b,
    Complement  = 0x1c,  // inverse checksum
    Checksum    = 0x1e,
    ResetVector = 0x3c,
  };

  enum Type
  {
    TypeNormal = 0,
    TypeBsxSlotted,
    TypeBsxBios,
    TypeBsx,
    TypeSufamiTurboBios,
    TypeSufamiTurbo,
    TypeSuperGameBoy1Bios,
    TypeSuperGameBoy2Bios,
    TypeGameBoy,
    TypeUnknown,
  };

  enum Region
  {
    NTSC = 0,
    PAL,
  };

  enum MemoryMapper
  {
    LoROM = 0,
    HiROM,
    ExLoROM,
    ExHiROM,
    SuperFXROM,
    SA1ROM,
    SPC7110ROM,
    BSCLoROM,
    BSCHiROM,
    BSXROM,
    STROM,
  };

  enum DSP1MemoryMapper
  {
    DSP1Unmapped = 0,
    DSP1LoROM1MB,
    DSP1LoROM2MB,
    DSP1HiROM,
  };

  static inline const char * type_to_string(Type type);
  static inline Type string_to_type(const char * str);
  static inline const char * region_to_string(Region region);
  static inline Region string_to_region(const char * str);
  static inline const char * mapper_to_string(MemoryMapper mapper);
  static inline MemoryMapper string_to_mapper(const char * str);
  static inline const char * dsp1_mapper_to_string(DSP1MemoryMapper dsp1_mapper);
  static inline DSP1MemoryMapper string_to_dsp1_mapper(const char * str);

  inline const char * type_string() const;
  inline const char * region_string() const;
  inline const char * mapper_string() const;
  inline const char * dsp1_mapper_string() const;

  void read_hash(const netnode & node);
  void write_hash(netnode & node) const;
  void print() const;

  unsigned rom_size = 0;
  unsigned ram_size = 0;
  bool firmware_appended = false;  // true if firmware is appended to end of ROM data

  bool has_copier_header = false;
  unsigned header_offset = 0;

  Type type = TypeUnknown;
  Region region = NTSC;
  MemoryMapper mapper = LoROM;
  DSP1MemoryMapper dsp1_mapper = DSP1Unmapped;

  bool has_bsx_slot = false;
  bool has_superfx = false;
  bool has_sa1 = false;
  bool has_sharprtc = false;
  bool has_epsonrtc = false;
  bool has_sdd1 = false;
  bool has_spc7110 = false;
  bool has_cx4 = false;
  bool has_dsp1 = false;
  bool has_dsp2 = false;
  bool has_dsp3 = false;
  bool has_dsp4 = false;
  bool has_obc1 = false;
  bool has_st010 = false;
  bool has_st011 = false;
  bool has_st018 = false;
};

SuperFamicomCartridge::SuperFamicomCartridge(linput_t *li)
{
  int32 size = qlsize(li);
  if ( size < 0 )
  {
    return;
  }

  firmware_appended = false;

  // skip copier header
  if ( (size & 0x7fff) == 512 )
    size -= 512;

  if ( size < 0x8000 )
    return;

  read_header(li);

  if ( type == TypeGameBoy )
    return;
  if ( type == TypeBsx )
    return;
  if ( type == TypeSufamiTurbo )
    return;

  if ( type == TypeSuperGameBoy1Bios || type == TypeSuperGameBoy2Bios )
  {
    if ( (rom_size & 0x7fff) == 0x100 )
    {
      firmware_appended = true;
      rom_size -= 0x100;
    }
  }
  else if ( has_cx4 )
  {
    if ( (rom_size & 0x7fff) == 0xc00 )
    {
      firmware_appended = true;
      rom_size -= 0xc00;
    }
  }

  if ( has_dsp1 )
  {
    if ( (size & 0x7fff) == 0x2000 )
    {
      firmware_appended = true;
      rom_size -= 0x2000;
    }
  }

  if ( has_dsp2 )
  {
    if ( (size & 0x7fff) == 0x2000 )
    {
      firmware_appended = true;
      rom_size -= 0x2000;
    }
  }

  if ( has_dsp3 )
  {
    if ( (size & 0x7fff) == 0x2000 )
    {
      firmware_appended = true;
      rom_size -= 0x2000;
    }
  }

  if ( has_dsp4 )
  {
    if ( (size & 0x7fff) == 0x2000 )
    {
      firmware_appended = true;
      rom_size -= 0x2000;
    }
  }

  if ( has_st010 )
  {
    if ( (size & 0xffff) == 0xd000 )
    {
      firmware_appended = true;
      rom_size -= 0xd000;
    }
  }

  if ( has_st011 )
  {
    if ( (size & 0xffff) == 0xd000 )
    {
      firmware_appended = true;
      rom_size -= 0xd000;
    }
  }

  if ( has_st018 )
  {
    if ( (size & 0x3ffff) == 0x28000 )
    {
      firmware_appended = true;
      rom_size -= 0x28000;
    }
  }
}

void SuperFamicomCartridge::read_header(linput_t *li)
{
  int32 size = qlsize(li);
  if ( size < 0 )
    return;

  // skip copier header
  uint32 start = 0;
  has_copier_header = (size & 0x7fff) == 512;
  if ( has_copier_header )
    start += 512, size -= 512;

  type        = TypeUnknown;
  mapper      = LoROM;
  dsp1_mapper = DSP1Unmapped;
  region      = NTSC;
  rom_size    = size;
  ram_size    = 0;

  has_bsx_slot   = false;
  has_superfx    = false;
  has_sa1        = false;
  has_sharprtc   = false;
  has_epsonrtc   = false;
  has_sdd1       = false;
  has_spc7110    = false;
  has_cx4        = false;
  has_dsp1       = false;
  has_dsp2       = false;
  has_dsp3       = false;
  has_dsp4       = false;
  has_obc1       = false;
  has_st010      = false;
  has_st011      = false;
  has_st018      = false;

  // =====================
  // detect Game Boy carts
  // =====================

  if ( size >= 0x0140 )
  {
    uint8 data[0x140];
    qlseek(li, start);
    qlread(li, data, 0x140);

    if ( data[0x0104] == 0xce && data[0x0105] == 0xed && data[0x0106] == 0x66 && data[0x0107] == 0x66
      && data[0x0108] == 0xcc && data[0x0109] == 0x0d && data[0x010a] == 0x00 && data[0x010b] == 0x0b )
    {
      type = TypeGameBoy;
      return;
    }
  }

  if ( size < 32768 )
  {
    type = TypeUnknown;
    return;
  }

  const unsigned index = find_header(li);
  header_offset = index;

  uint8 extended_header[16 + 64];
  qlseek(li, start + index - 16);
  qlread(li, extended_header, 16 + 64);
  uint8 * header = &extended_header[16];

  const uint8 mapperid = header[Mapper];
  const uint8 rom_type = header[RomType];
  const uint8 lrom_size = header[RomSize];
  const uint8 company  = header[Company];
  const uint8 regionid = header[CartRegion] & 0x7f;

  ram_size = 1024 << (header[RamSize] & 7);
  if ( ram_size == 1024 )
    ram_size = 0;  // no RAM present
  if ( lrom_size == 0 && ram_size )
    ram_size = 0;  // fix for Bazooka Blitzkrieg's malformed header (swapped ROM and RAM sizes)

  // 0, 1, 13 = NTSC; 2 - 12 = PAL
  region = (regionid <= 1 || regionid >= 13) ? NTSC : PAL;

  // =======================
  // detect BS-X flash carts
  // =======================

  if ( header[0x13] == 0x00 || header[0x13] == 0xff )
  {
    if ( header[0x14] == 0x00 )
    {
      const uint8 n15 = header[0x15];
      if ( n15 == 0x00 || n15 == 0x80 || n15 == 0x84 || n15 == 0x9c || n15 == 0xbc || n15 == 0xfc )
      {
        if ( header[0x1a] == 0x33 || header[0x1a] == 0xff )
        {
          type = TypeBsx;
          mapper = BSXROM;
          region = NTSC;  // BS-X only released in Japan
          return;
        }
      }
    }
  }

  // =========================
  // detect Sufami Turbo carts
  // =========================

  uint8 data[32];
  qlseek(li, start);
  qlread(li, data, 32);

  if ( !memcmp(data, "BANDAI SFC-ADX", 14) )
  {
    if ( !memcmp(data + 16, "SFC-ADX BACKUP", 14) )
    {
      type = TypeSufamiTurboBios;
    }
    else
    {
      type = TypeSufamiTurbo;
    }
    mapper = STROM;
    region = NTSC;  // Sufami Turbo only released in Japan
    return;         // RAM size handled outside this routine
  }

  // ==========================
  // detect Super Game Boy BIOS
  // ==========================

  if ( !memcmp(header, "Super GAMEBOY2", 14) )
  {
    type = TypeSuperGameBoy2Bios;
    return;
  }

  if ( !memcmp(header, "Super GAMEBOY", 13) )
  {
    type = TypeSuperGameBoy1Bios;
    return;
  }

  // =====================
  // detect standard carts
  // =====================

  // detect presence of BS-X flash cartridge connector (reads extended header information)
  if ( header[-14] == 'Z' )
  {
    if ( header[-11] == 'J' )
    {
      uint8 n13 = header[-13];
      if ( (n13 >= 'A' && n13 <= 'Z') || (n13 >= '0' && n13 <= '9') )
      {
        if ( company == 0x33 || (header[-10] == 0x00 && header[-4] == 0x00) )
        {
          has_bsx_slot = true;
        }
      }
    }
  }

  if ( has_bsx_slot )
  {
    if ( !memcmp(header, "Satellaview BS-X     ", 21) )
    {
      // BS-X base cart
      type = TypeBsxBios;
      mapper = BSXROM;
      region = NTSC;  // BS-X only released in Japan
      return;         // RAM size handled internally by load_cart_bsx() -> BSXCart class
    }
    else
    {
      type = TypeBsxSlotted;
      mapper = (index == 0x7fc0 ? BSCLoROM : BSCHiROM);
      region = NTSC;  // BS-X slotted cartridges only released in Japan
    }
  }
  else
  {
    // standard cart
    type = TypeNormal;

    if ( index == 0x7fc0 && size >= 0x401000 )
    {
      mapper = ExLoROM;
    }
    else if ( index == 0x7fc0 && mapperid == 0x32 )
    {
      mapper = ExLoROM;
    }
    else if ( index == 0x7fc0 )
    {
      mapper = LoROM;
    }
    else if ( index == 0xffc0 )
    {
      mapper = HiROM;
    }
    else
    {  // index == 0x40ffc0
      mapper = ExHiROM;
    }
  }

  if ( mapperid == 0x20 && (rom_type == 0x13 || rom_type == 0x14 || rom_type == 0x15 || rom_type == 0x1a) )
  {
    has_superfx = true;
    mapper = SuperFXROM;
    ram_size = 1024 << (header[-3] & 7);
    if ( ram_size == 1024 )
      ram_size = 0;
  }

  if ( mapperid == 0x23 && (rom_type == 0x32 || rom_type == 0x34 || rom_type == 0x35) )
  {
    has_sa1 = true;
    mapper = SA1ROM;
  }

  if ( mapperid == 0x35 && rom_type == 0x55 )
  {
    has_sharprtc = true;
  }

  if ( mapperid == 0x32 && (rom_type == 0x43 || rom_type == 0x45) )
  {
    has_sdd1 = true;
  }

  if ( mapperid == 0x3a && (rom_type == 0xf5 || rom_type == 0xf9) )
  {
    has_spc7110 = true;
    has_epsonrtc = (rom_type == 0xf9);
    mapper = SPC7110ROM;
  }

  if ( mapperid == 0x20 && rom_type == 0xf3 )
  {
    has_cx4 = true;
  }

  if ( (mapperid == 0x20 || mapperid == 0x21) && rom_type == 0x03 )
  {
    has_dsp1 = true;
  }

  if ( mapperid == 0x30 && rom_type == 0x05 && company != 0xb2 )
  {
    has_dsp1 = true;
  }

  if ( mapperid == 0x31 && (rom_type == 0x03 || rom_type == 0x05) )
  {
    has_dsp1 = true;
  }

  if ( has_dsp1 )
  {
    if ( (mapperid & 0x2f) == 0x20 && size <= 0x100000 )
    {
      dsp1_mapper = DSP1LoROM1MB;
    }
    else if ( (mapperid & 0x2f) == 0x20 )
    {
      dsp1_mapper = DSP1LoROM2MB;
    }
    else if ( (mapperid & 0x2f) == 0x21 )
    {
      dsp1_mapper = DSP1HiROM;
    }
  }

  if ( mapperid == 0x20 && rom_type == 0x05 )
  {
    has_dsp2 = true;
  }

  if ( mapperid == 0x30 && rom_type == 0x05 && company == 0xb2 )
  {
    has_dsp3 = true;
  }

  if ( mapperid == 0x30 && rom_type == 0x03 )
  {
    has_dsp4 = true;
  }

  if ( mapperid == 0x30 && rom_type == 0x25 )
  {
    has_obc1 = true;
  }

  if ( mapperid == 0x30 && rom_type == 0xf6 && lrom_size >= 10 )
  {
    has_st010 = true;
  }

  if ( mapperid == 0x30 && rom_type == 0xf6 && lrom_size < 10 )
  {
    has_st011 = true;
  }

  if ( mapperid == 0x30 && rom_type == 0xf5 )
  {
    has_st018 = true;
  }
}

unsigned SuperFamicomCartridge::find_header(linput_t *li)
{
  unsigned score_lo = score_header(li, 0x007fc0);
  unsigned score_hi = score_header(li, 0x00ffc0);
  unsigned score_ex = score_header(li, 0x40ffc0);
  if ( score_ex )
    score_ex += 4;  // favor ExHiROM on images > 32mbits

  if ( score_lo >= score_hi && score_lo >= score_ex )
  {
    return 0x007fc0;
  }
  else if ( score_hi >= score_ex )
  {
    return 0x00ffc0;
  }
  else
  {
    return 0x40ffc0;
  }
}

unsigned SuperFamicomCartridge::score_header(linput_t *li, unsigned addr)
{
  int32 size = qlsize(li);
  if ( size < 0x8000 )
    return 0;

  // skip copier header
  uint32 start = 0;
  if ( (size & 0x7fff) == 512 )
    start += 512, size -= 512;

  if ( (uint32)size < addr + 64 )
    return 0;    // image too small to contain header at this location?
  int score = 0;

  uint8 header[64];
  qlseek(li, start + addr);
  qlread(li, header, 64);

  uint16 resetvector = header[ResetVector] | (header[ResetVector + 1] << 8);
  uint16 checksum    = header[Checksum   ] | (header[Checksum    + 1] << 8);
  uint16 complement  = header[Complement ] | (header[Complement  + 1] << 8);

  uint32 resetop_addr = (addr & ~0x7fff) | (resetvector & 0x7fff);
  if ( qlseek(li, start + resetop_addr) != (start + resetop_addr) )
    return 0;
  uint8 resetop;
  if ( qlread(li, &resetop, sizeof(uint8)) != sizeof(uint8) )
    return 0;    // first opcode executed upon reset

  uint8 mapper = header[Mapper] & ~0x10;                               // mask off irrelevent FastROM-capable bit

  // $00:[000-7fff] contains uninitialized RAM and MMIO.
  // reset vector must point to ROM at $00:[8000-ffff] to be considered valid.
  if ( resetvector < 0x8000 )
    return 0;

  // some images duplicate the header in multiple locations, and others have completely
  // invalid header information that cannot be relied upon.
  // below code will analyze the first opcode executed at the specified reset vector to
  // determine the probability that this is the correct header.

  // most likely opcodes
  if ( resetop == 0x78    // sei
    || resetop == 0x18    // clc (clc; xce)
    || resetop == 0x38    // sec (sec; xce)
    || resetop == 0x9c    // stz $nnnn (stz $4200)
    || resetop == 0x4c    // jmp $nnnn
    || resetop == 0x5c )  // jml $nnnnnn
  {
    score += 8;
  }

  // plausible opcodes
  if ( resetop == 0xc2    // rep #$nn
    || resetop == 0xe2    // sep #$nn
    || resetop == 0xad    // lda $nnnn
    || resetop == 0xae    // ldx $nnnn
    || resetop == 0xac    // ldy $nnnn
    || resetop == 0xaf    // lda $nnnnnn
    || resetop == 0xa9    // lda #$nn
    || resetop == 0xa2    // ldx #$nn
    || resetop == 0xa0    // ldy #$nn
    || resetop == 0x20    // jsr $nnnn
    || resetop == 0x22 )  // jsl $nnnnnn
  {
    score += 4;
  }

  // implausible opcodes
  if ( resetop == 0x40    // rti
    || resetop == 0x60    // rts
    || resetop == 0x6b    // rtl
    || resetop == 0xcd    // cmp $nnnn
    || resetop == 0xec    // cpx $nnnn
    || resetop == 0xcc )  // cpy $nnnn
  {
    score -= 4;
  }

  // least likely opcodes
  if ( resetop == 0x00    // brk #$nn
    || resetop == 0x02    // cop #$nn
    || resetop == 0xdb    // stp
    || resetop == 0x42    // wdm
    || resetop == 0xff )  // sbc $nnnnnn,x
  {
    score -= 8;
  }

  // at times, both the header and reset vector's first opcode will match ...
  // fallback and rely on info validity in these cases to determine more likely header.

  // a valid checksum is the biggest indicator of a valid header.
  if ( (checksum + complement) == 0xffff && (checksum != 0) && (complement != 0) )
    score += 4;

  if ( addr == 0x007fc0 && mapper == 0x20 )
    score += 2;  // 0x20 is usually LoROM
  if ( addr == 0x00ffc0 && mapper == 0x21 )
    score += 2;  // 0x21 is usually HiROM
  if ( addr == 0x007fc0 && mapper == 0x22 )
    score += 2;  // 0x22 is usually ExLoROM
  if ( addr == 0x40ffc0 && mapper == 0x25 )
    score += 2;  // 0x25 is usually ExHiROM

  if ( header[Company] == 0x33 )
    score += 2;             // 0x33 indicates extended header
  if ( header[RomType] < 0x08 )
    score++;
  if ( header[RomSize] < 0x10 )
    score++;
  if ( header[RamSize] < 0x08 )
    score++;
  if ( header[CartRegion] < 14 )
    score++;

  if ( score < 0 )
    score = 0;
  return score;
}

const char * SuperFamicomCartridge::type_to_string(Type type)
{
  switch ( type )
  {
    case TypeNormal:
      return "TypeNormal";

    case TypeBsxSlotted:
      return "TypeBsxSlotted";

    case TypeBsxBios:
      return "TypeBsxBios";

    case TypeBsx:
      return "TypeBsx";

    case TypeSufamiTurboBios:
      return "TypeSufamiTurboBios";

    case TypeSufamiTurbo:
      return "TypeSufamiTurbo";

    case TypeSuperGameBoy1Bios:
      return "TypeSuperGameBoy1Bios";

    case TypeSuperGameBoy2Bios:
      return "TypeSuperGameBoy2Bios";

    case TypeGameBoy:
      return "TypeGameBoy";

    case TypeUnknown:
      return "TypeUnknown";
  }

  return nullptr;
}

SuperFamicomCartridge::Type SuperFamicomCartridge::string_to_type(const char * str)
{
  if ( streq(str, "TypeNormal") )
    return TypeNormal;
  else if ( streq(str, "TypeBsxSlotted") )
    return TypeBsxSlotted;
  else if ( streq(str, "TypeBsxBios") )
    return TypeBsxBios;
  else if ( streq(str, "TypeBsx") )
    return TypeBsx;
  else if ( streq(str, "TypeSufamiTurboBios") )
    return TypeSufamiTurboBios;
  else if ( streq(str, "TypeSufamiTurbo") )
    return TypeSufamiTurbo;
  else if ( streq(str, "TypeSuperGameBoy1Bios") )
    return TypeSuperGameBoy1Bios;
  else if ( streq(str, "TypeSuperGameBoy2Bios") )
    return TypeSuperGameBoy2Bios;
  else if ( streq(str, "TypeGameBoy") )
    return TypeGameBoy;
  else if ( streq(str, "TypeUnknown") )
    return TypeUnknown;
  else
    return TypeUnknown;
}

const char * SuperFamicomCartridge::region_to_string(Region region)
{
  switch ( region )
  {
    case NTSC:
      return "NTSC";

    case PAL:
      return "PAL";
  }

  return nullptr;
}

SuperFamicomCartridge::Region SuperFamicomCartridge::string_to_region(const char * str)
{
  if ( streq(str, "NTSC") )
    return NTSC;
  else if ( streq(str, "PAL") )
    return PAL;
  else
    return NTSC;
}

const char * SuperFamicomCartridge::mapper_to_string(MemoryMapper mapper)
{
  switch ( mapper )
  {
    case LoROM:
      return "LoROM";

    case HiROM:
      return "HiROM";

    case ExLoROM:
      return "ExLoROM";

    case ExHiROM:
      return "ExHiROM";

    case SuperFXROM:
      return "SuperFXROM";

    case SA1ROM:
      return "SA1ROM";

    case SPC7110ROM:
      return "SPC7110ROM";

    case BSCLoROM:
      return "BSCLoROM";

    case BSCHiROM:
      return "BSCHiROM";

    case BSXROM:
      return "BSXROM";

    case STROM:
      return "STROM";
  }

  return nullptr;
}

SuperFamicomCartridge::MemoryMapper SuperFamicomCartridge::string_to_mapper(const char * str)
{
  if ( streq(str, "LoROM") )
    return LoROM;
  else if ( streq(str, "HiROM") )
    return HiROM;
  else if ( streq(str, "ExLoROM") )
    return ExLoROM;
  else if ( streq(str, "ExHiROM") )
    return ExHiROM;
  else if ( streq(str, "SuperFXROM") )
    return SuperFXROM;
  else if ( streq(str, "SA1ROM") )
    return SA1ROM;
  else if ( streq(str, "SPC7110ROM") )
    return SPC7110ROM;
  else if ( streq(str, "BSCLoROM") )
    return BSCLoROM;
  else if ( streq(str, "BSCHiROM") )
    return BSCHiROM;
  else if ( streq(str, "BSXROM") )
    return BSXROM;
  else if ( streq(str, "STROM") )
    return STROM;
  else
    return LoROM;
}

const char * SuperFamicomCartridge::dsp1_mapper_to_string(DSP1MemoryMapper dsp1_mapper)
{
  switch ( dsp1_mapper )
  {
    case DSP1Unmapped:
      return "DSP1Unmapped";

    case DSP1LoROM1MB:
      return "DSP1LoROM1MB";

    case DSP1LoROM2MB:
      return "DSP1LoROM2MB";

    case DSP1HiROM:
      return "DSP1HiROM";
  }

  return nullptr;
}

SuperFamicomCartridge::DSP1MemoryMapper SuperFamicomCartridge::string_to_dsp1_mapper(const char * str)
{
  if ( streq(str, "DSP1Unmapped") )
    return DSP1Unmapped;
  else if ( streq(str, "DSP1LoROM1MB") )
    return DSP1LoROM1MB;
  else if ( streq(str, "DSP1LoROM2MB") )
    return DSP1LoROM2MB;
  else if ( streq(str, "DSP1HiROM") )
    return DSP1HiROM;
  else
    return DSP1Unmapped;
}

const char * SuperFamicomCartridge::type_string() const
{
  return type_to_string(type);
}

const char * SuperFamicomCartridge::region_string() const
{
  return region_to_string(region);
}

const char * SuperFamicomCartridge::mapper_string() const
{
  return mapper_to_string(mapper);
}

const char * SuperFamicomCartridge::dsp1_mapper_string() const
{
  return dsp1_mapper_to_string(dsp1_mapper);
}

void SuperFamicomCartridge::read_hash(const netnode & node)
{
  char buf[MAXSTR];
  ssize_t len;

  rom_size = node.hashval_long("rom_size");
  ram_size = node.hashval_long("ram_size");
  firmware_appended = node.hashval_long("firmware_appended") != 0;

  header_offset = node.hashval_long("header_offset");

  len = node.hashstr("type", buf, sizeof(buf));
  if ( len >= 0 )
    type = string_to_type(buf);
  len = node.hashstr("region", buf, sizeof(buf));
  if ( len >= 0 )
    region = string_to_region(buf);
  len = node.hashstr("mapper", buf, sizeof(buf));
  if ( len >= 0 )
    mapper = string_to_mapper(buf);
  len = node.hashstr("dsp1_mapper", buf, sizeof(buf));
  if ( len >= 0 )
    dsp1_mapper = string_to_dsp1_mapper(buf);

  has_bsx_slot = node.hashval_long("has_bsx_slot") != 0;
  has_superfx = node.hashval_long("has_superfx") != 0;
  has_sa1 = node.hashval_long("has_sa1") != 0;
  has_sharprtc = node.hashval_long("has_sharprtc") != 0;
  has_epsonrtc = node.hashval_long("has_epsonrtc") != 0;
  has_sdd1 = node.hashval_long("has_sdd1") != 0;
  has_spc7110 = node.hashval_long("has_spc7110") != 0;
  has_cx4 = node.hashval_long("has_cx4") != 0;
  has_dsp1 = node.hashval_long("has_dsp1") != 0;
  has_dsp2 = node.hashval_long("has_dsp2") != 0;
  has_dsp3 = node.hashval_long("has_dsp3") != 0;
  has_dsp4 = node.hashval_long("has_dsp4") != 0;
  has_obc1 = node.hashval_long("has_obc1") != 0;
  has_st010 = node.hashval_long("has_st010") != 0;
  has_st011 = node.hashval_long("has_st011") != 0;
  has_st018 = node.hashval_long("has_st018") != 0;
}

void SuperFamicomCartridge::write_hash(netnode & node) const
{
  node.hashset("rom_size", rom_size);
  node.hashset("ram_size", ram_size);
  node.hashset("firmware_appended", firmware_appended ? 1 : 0);

  node.hashset("header_offset", header_offset);

  node.hashset("type", type_string());
  node.hashset("region", region_string());
  node.hashset("mapper", mapper_string());
  node.hashset("dsp1_mapper", dsp1_mapper_string());

  node.hashset("has_bsx_slot", has_bsx_slot ? 1 : 0);
  node.hashset("has_superfx", has_superfx ? 1 : 0);
  node.hashset("has_sa1", has_sa1 ? 1 : 0);
  node.hashset("has_sharprtc", has_sharprtc ? 1 : 0);
  node.hashset("has_epsonrtc", has_epsonrtc ? 1 : 0);
  node.hashset("has_sdd1", has_sdd1 ? 1 : 0);
  node.hashset("has_spc7110", has_spc7110 ? 1 : 0);
  node.hashset("has_cx4", has_cx4 ? 1 : 0);
  node.hashset("has_dsp1", has_dsp1 ? 1 : 0);
  node.hashset("has_dsp2", has_dsp2 ? 1 : 0);
  node.hashset("has_dsp3", has_dsp3 ? 1 : 0);
  node.hashset("has_dsp4", has_dsp4 ? 1 : 0);
  node.hashset("has_obc1", has_obc1 ? 1 : 0);
  node.hashset("has_st010", has_st010 ? 1 : 0);
  node.hashset("has_st011", has_st011 ? 1 : 0);
  node.hashset("has_st018", has_st018 ? 1 : 0);
}

void SuperFamicomCartridge::print() const
{
  // print informations for debug purpose
  msg("SuperFamicomCartridge::rom_size=%d\n", rom_size);
  msg("SuperFamicomCartridge::ram_size=%d\n", ram_size);
  msg("SuperFamicomCartridge::firmware_appended=%s\n", firmware_appended ? "true" : "false");

  msg("SuperFamicomCartridge::has_copier_header=%s\n", has_copier_header ? "true" : "false");
  msg("SuperFamicomCartridge::header_offset=0x%04X\n", header_offset);

  msg("SuperFamicomCartridge::type=%d\n", type);
  msg("SuperFamicomCartridge::region=%d\n", region);
  msg("SuperFamicomCartridge::mapper=%d\n", mapper);
  msg("SuperFamicomCartridge::dsp1_mapper=%d\n", dsp1_mapper);

  msg("SuperFamicomCartridge::extra_chips=[");
  if ( has_bsx_slot )
    msg(" BSX Slot");
  if ( has_superfx )
    msg(" SuperFX");
  if ( has_sa1 )
    msg(" SA1");
  if ( has_sharprtc )
    msg(" Sharp RTC");
  if ( has_epsonrtc )
    msg(" Epson RTC");
  if ( has_sdd1 )
    msg(" SDD1");
  if ( has_spc7110 )
    msg(" SPC7110");
  if ( has_cx4 )
    msg(" CX4");
  if ( has_dsp1 )
    msg(" DSP1");
  if ( has_dsp2 )
    msg(" DSP2");
  if ( has_dsp3 )
    msg(" DSP3");
  if ( has_dsp4 )
    msg(" DSP4");
  if ( has_obc1 )
    msg(" OBC1");
  if ( has_st010 )
    msg(" ST010");
  if ( has_st011 )
    msg(" ST011");
  if ( has_st018 )
    msg(" ST018");
  msg(" ]\n");
}

#endif // __SUPER_FAMICOM_HPP__

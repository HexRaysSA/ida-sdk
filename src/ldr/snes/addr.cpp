
// This file is included from the loader module and the processor module

#include "super-famicom.hpp"

class snes_addr_t
{
  SuperFamicomCartridge g_cartridge;

  //----------------------------------------------------------------------------
  ea_t xlat_system(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // WRAM
    if ( bank >= 0x7e && bank <= 0x7f )
      return address;

    if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
    {
      if ( addr <= 0x1fff ) // Low RAM
        return 0x7e0000 + addr;
      else if ( addr >= 0x2100 && addr <= 0x213f ) // PPU registers
        return addr;
      else if ( addr >= 0x2140 && addr <= 0x2183 ) // CPU registers
        return addr;
      else if ( addr >= 0x4016 && addr <= 0x4017 ) // CPU registers
        return addr;
      else if ( addr >= 0x4200 && addr <= 0x421f ) // CPU registers
        return addr;
      else if ( addr >= 0x4300 && addr <= 0x437f ) // CPU registers
        return addr;
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // hitachidsp model=HG51B169 frequency=20000000
  //   rom id=program name=program.rom size=hex(rom_size)
  //   rom id=data name=cx4.data.rom size=0xc00
  //   ram id=data size=0xc00
  //   map id=io address=00-3f,80-bf:6000-7fff
  //   map id=rom address=00-7f,80-ff:8000-ffff mask=0x8000
  //   map id=ram address=70-77:0000-7fff
  ea_t xlat_cx4(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SRAM
    if ( g_cartridge.ram_size != 0
      && bank >= 0x70
      && bank <= 0x77
      && addr <= 0x7fff )
    {
      return address;
    }

    // mirror 00-7d => 80-fd (excluding SRAM)
    if ( bank <= 0x7d )
    {
      address += 0x800000;
      bank += 0x80;
    }

    if ( bank <= 0xbf )
    {
      if ( addr >= 0x8000 )
      {
        // ROM
        return address;
      }
      else if ( addr >= 0x6000 )
      {
        // CX4 registers
        return addr;
      }
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // spc7110
  //   rom id=program name=program.rom size=0x100000
  //   rom id=data name=data.rom size=hex(rom_size - 0x100000)
  //   ram name=save.ram size=0x", hex(ram_size)
  //   map id=io address=00-3f,80-bf:4800-483f
  //   map id=io address=50:0000-ffff
  //   map id=rom address=00-3f,80-bf:8000-ffff
  //   map id=rom address=c0-ff:0000-ffff
  //   map id=ram address=00-3f,80-bf:6000-7fff mask=0xe000
  ea_t xlat_spc7110(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SRAM
    if ( g_cartridge.ram_size != 0 )
    {
      if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
      {
        if ( addr >= 0x6000 && addr <= 0x7fff )
        {
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0x1f) << 13) + (addr - 0x6000)) & ram_mask;
          uint32 res = ((ram_offset >> 13) << 16) + (0x6000 + (ram_offset & 0x1fff));
          return res;
        }
      }
    }

    // Decompressed ROM
    if ( bank >= 0x50 && bank <= 0x5f )
      return address;

    // mirror 00-7d => 80-fd (excluding SRAM, Decompressed ROM)
    if ( bank <= 0x7d )
    {
      address += 0x800000;
      bank += 0x80;
    }

    if ( bank >= 0xc0 )
    {
      // ROM (HiROM layout)
      return address;
    }
    else
    {
      if ( addr >= 0x8000 )
      {
        // ROM (LoROM-like layout)
        return ((0xc0 + (bank & 0x3f)) << 16) + addr;
      }
      else if ( addr >= 0x4800 && addr <= 0x483f )
      {
        // SPC7110 registers
        return addr;
      }
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // sdd1
  //   rom name=program.rom size=hex(rom_size)
  //   ram name=save.ram size=hex(ram_size)
  //   map id=io address=00-3f,80-bf:4800-4807
  //   map id=rom address=00-3f,80-bf:8000-ffff mask=0x8000
  //   map id=rom address=c0-ff:0000-ffff
  //   map id=ram address=20-3f,a0-bf:6000-7fff mask=0xe000
  //   map id=ram address=70-7f:0000-7fff
  ea_t xlat_sdd1(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SRAM
    if ( g_cartridge.ram_size != 0 )
    {
      if ( bank >= 0x70 && bank <= 0x7d )
      {
        if ( addr <= 0x7fff )
        {
          // LoROM SRAM style
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0xf) << 15) + (addr & 0x7fff)) & ram_mask;
          uint32 res = ((0x70 + (ram_offset >> 15)) << 16) + (ram_offset & 0x7fff);
          return res;
        }
      }
      else if ( ( bank >= 0x20 && bank <= 0x3f ) || ( bank >= 0xa0 && bank <= 0xbf ) )
      {
        if ( addr >= 0x6000 && addr <= 0x7fff )
        {
          // HiROM SRAM style (not usually used?)
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0x1f) << 13) + (addr - 0x6000)) & ram_mask;
          uint32 res = ((0x20 + (ram_offset >> 13)) << 16) + (0x6000 + (ram_offset & 0x1fff));
          return res;
        }
      }
    }

    if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
    {
      if ( addr >= 0x8000 )
      {
        // ROM (LoROM style)
        return ((bank | 0x80) << 16) + addr;
      }
      else if ( addr >= 0x4800 && addr <= 0x4807 )
      {
        // S-DD1 registers
        return addr;
      }
    }
    else if ( bank >= 0xc0 )
    {
      // ROM (HiROM style)
      return address;
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // rom name=program.rom size=hex(rom_size)
  // ram name=save.ram size=hex(ram_size)
  // map id=rom address=00-7f,80-ff:8000-ffff mask=0x8000
  // map id=ram address=70-7f,f0-ff:[0000-7fff|0000-ffff]
  ea_t xlat_lorom(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SRAM
    if ( g_cartridge.ram_size != 0 )
    {
      bool preserve_rom_mirror = (g_cartridge.rom_size > 0x200000) || (g_cartridge.ram_size > 32 * 1024);

      if ( ( bank >= 0x70 && bank <= 0x7d ) || bank >= 0xf0 )
      {
        if ( addr <= 0x7fff || !preserve_rom_mirror )
        {
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0xf) << 15) + (addr & 0x7fff)) & ram_mask;
          uint32 ea = ((0x70 + (ram_offset >> 15)) << 16) + (ram_offset & 0x7fff);
          if ( bank >= 0xfe )
            ea += 0x800000;
          return ea;
        }
      }
    }

    // mirror 00-7d => 80-fd (excluding SRAM)
    if ( bank <= 0x7d )
    {
      address += 0x800000;
      bank += 0x80;
    }

    // ROM
    if ( bank <= 0xbf )
    {
      if ( addr >= 0x8000 )
      {
        return address;
      }
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // rom name=program.rom size=hex(rom_size)
  // ram name=save.ram size=hex(ram_size)
  // map id=rom address=00-3f,80-bf:8000-ffff
  // map id=rom address=40-7f,c0-ff:0000-ffff
  // map id=ram address=10-3f,90-bf:6000-7fff mask=0xe000
  ea_t xlat_hirom(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SRAM
    if ( g_cartridge.ram_size != 0 )
    {
      if ( ( bank >= 0x10 && bank <= 0x3f ) || ( bank >= 0x90 && bank <= 0xbf ) )
      {
        if ( addr >= 0x6000 && addr <= 0x7fff )
        {
          // Typically, HiROM SRAM starts from $20:0000, but there are exceptions.
          // Example: Donkey Kong Country 2 (reads $B0:6000 for 2 kilobytes SRAM)
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0x1f) << 13) + (addr - 0x6000)) & ram_mask;
          uint32 res = ((0x20 + (ram_offset >> 13)) << 16) + (0x6000 + (ram_offset & 0x1fff));
          return res;
        }
      }
    }

    // mirror 00-7d => 80-fd (excluding SRAM)
    if ( bank <= 0x7d )
    {
      address += 0x800000;
      bank += 0x80;
    }

    if ( bank >= 0xc0 )
    {
      // ROM (HiROM layout)
      return address;
    }
    else
    {
      if ( addr >= 0x8000 )
      {
        // ROM (LoROM-like layout)
        return ((0xc0 + (bank & 0x3f)) << 16) + addr;
      }
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // rom name=program.rom size=hex(rom_size)
  // ram name=save.ram size=hex(ram_size)
  // map id=rom address=00-3f,80-bf:8000-ffff mask=0x8000
  // map id=rom address=40-7f:0000-ffff
  // map id=ram address=20-3f,a0-bf:6000-7fff
  // map id=ram address=70-7f:0000-7fff
  ea_t xlat_exlorom(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SRAM
    if ( g_cartridge.ram_size != 0 )
    {
      if ( bank >= 0x70 && bank <= 0x7d )
      {
        if ( addr <= 0x7fff )
        {
          // LoROM SRAM style
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0xf) << 15) + (addr & 0x7fff)) & ram_mask;
          uint32 res = ((0x70 + (ram_offset >> 15)) << 16) + (ram_offset & 0x7fff);
          return res;
        }
      }
      else if ( ( bank >= 0x20 && bank <= 0x3f ) || ( bank >= 0xa0 && bank <= 0xbf ) )
      {
        if ( addr >= 0x6000 && addr <= 0x7fff )
        {
          // HiROM SRAM style (not usually used?)
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0x1f) << 13) + (addr - 0x6000)) & ram_mask;
          uint32 res = ((0x20 + (ram_offset >> 13)) << 16) + (0x6000 + (ram_offset & 0x1fff));
          return res;
        }
      }
    }

    if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
    {
      if ( addr >= 0x8000 )
      {
        // ROM (LoROM style)
        return ((bank | 0x80) << 16) + addr;
      }
    }
    else if ( bank <= 0x7f )
    {
      // ROM (HiROM style)
      return address;
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // rom name=program.rom size=hex(rom_size)
  // ram name=save.ram size=hex(ram_size)
  // map id=rom address=00-3f:8000-ffff base=0x400000
  // map id=rom address=40-7f:0000-ffff base=0x400000
  // map id=rom address=80-bf:8000-ffff mask=0xc00000
  // map id=rom address=c0-ff:0000-ffff mask=0xc00000
  // map id=ram address=20-3f,a0-bf:6000-7fff mask=0xe000
  // map id=ram address=70-7f:[0000-7fff|0000-ffff]
  ea_t xlat_exhirom(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SRAM
    if ( g_cartridge.ram_size != 0 )
    {
      if ( ( bank >= 0x20 && bank <= 0x3f ) || ( bank >= 0xa0 && bank <= 0xbf ) )
      {
        if ( addr >= 0x6000 && addr <= 0x7fff )
        {
          // HiROM SRAM style
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0x1f) << 13) + (addr - 0x6000)) & ram_mask;
          uint32 res = ((0x20 + (ram_offset >> 13)) << 16) + (0x6000 + (ram_offset & 0x1fff));
          return res;
        }
      }
      else if ( bank >= 0x70 && bank <= 0x7d )
      {
        bool preserve_rom_mirror = (g_cartridge.rom_size > 0x200000) || (g_cartridge.ram_size > 32 * 1024);

        if ( addr <= 0x7fff || !preserve_rom_mirror )
        {
          // LoROM SRAM style (not usually used?)
          uint32 ram_mask = g_cartridge.ram_size - 1;
          uint32 ram_offset = (((bank & 0xf) << 15) + (addr & 0x7fff)) & ram_mask;
          uint32 res = ((0x70 + (ram_offset >> 15)) << 16) + (ram_offset & 0x7fff);
          return res;
        }
      }
    }

    if ( bank >= 0xc0 )
    {
      // ROM
      return address;
    }
    else if ( bank >= 0x80 )
    {
      if ( addr >= 0x8000 )
      {
        // ROM (mirror to c0-ff)
        return ((bank + 0x40) << 16) + addr;
      }
    }
    else if ( bank >= 0x40 )
    {
      // Extended ROM
      return address;
    }
    else
    {
      if ( addr >= 0x8000 )
      {
        // Extended ROM (mirror to 40-7f)
        return ((bank + 0x40) << 16) + addr;
      }
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // superfx revision=4
  //   rom name=program.rom size=hex(rom_size)
  //   ram name=save.ram size=hex(ram_size)
  //   map id=io address=00-3f,80-bf:3000-34ff
  //   map id=rom address=00-3f,80-bf:8000-ffff mask=0x8000
  //   map id=rom address=40-5f,c0-df:0000-ffff
  //   map id=ram address=00-3f,80-bf:6000-7fff size=0x2000
  //   map id=ram address=70-71,f0-f1:0000-ffff
  ea_t xlat_superfxrom(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // SuperFX RAM
    if ( g_cartridge.ram_size != 0 )
    {
      if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
      {
        if ( addr >= 0x6000 && addr <= 0x7fff )
        {
          // 2kB Game Work RAM
          return (0x00 << 16) + addr;
        }
      }
      else if ( ( bank >= 0x70 && bank <= 0x7f ) || ( bank >= 0xf0 && bank <= 0xf1 ) )
      {
        // 128kB SRAM address space
        return ( ( bank & ~0x80 ) << 16 ) + addr;
      }
    }

    if ( ( bank >= 0x40 && bank <= 0x5f ) || ( bank >= 0xc0 && bank <= 0xdf ) )
    {
      // ROM (HiROM layout)
      return address;
    }
    else if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
    {
      if ( addr >= 0x8000 )
      {
        // ROM (LoROM layout)
        return address;
      }
    }

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // sa1
  //   rom name=program.rom size=hex(rom_size)
  //   ram id=bitmap name=save.ram size=hex(ram_size)
  //   ram id=internal size=0x800
  //   map id=io address=00-3f,80-bf:2200-23ff
  //   map id=rom address=00-3f,80-bf:8000-ffff
  //   map id=rom address=c0-ff:0000-ffff
  //   map id=bwram address=00-3f,80-bf:6000-7fff
  //   map id=bwram address=40-4f:0000-ffff
  //   map id=iram address=00-3f,80-bf:3000-37ff
  ea_t xlat_sa1rom(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    // mirror 80-bf => 00-3f
    if ( bank >= 0x80 && bank <= 0xbf )
    {
      address -= 0x800000;
      bank -= 0x80;
    }

    // SA1 BWRAM (SRAM)
    if ( g_cartridge.ram_size != 0 )
    {
      if ( bank <= 0x3f )
      {
        if ( addr >= 0x6000 && addr <= 0x7fff )
        {
          // 8 kilobytes RAM (shared with 40:0000-1fff)
          uint32 ram_offset = (addr & 0x7fff) - 0x6000;
          return (0x40 << 16) + ram_offset;
        }
      }
      else if ( bank <= 0x4f )
      {
        // 128 kB address space, redirects to banks 40-41
        return ((bank & ~0xe) << 16) + addr;
      }
    }

    if ( bank >= 0xc0 )
    {
      // ROM (HiROM layout)
      return address;
    }
    else if ( bank <= 0x3f )
    {
      if ( addr >= 0x8000 )
      {
        // ROM (LoROM layout)
        return address;
      }
    }

    // TODO: SA1 Missing Memory Map
    // 00-3f|80-bf:0000-07ff IWRAM (SA1 side)
    // 60-6f:0000-ffff       BWRAM Bitmap (SA1 side)

    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // sharprtc
  //   ram name=rtc.ram size=0x10
  //   map id=io address=00-3f,80-bf:2800-2801
  ea_t xlat_sharprtc(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
    {
      if ( addr >= 0x2800 && addr <= 0x2801 )
      {
        return addr;
      }
    }

    dispatched = false;
    return false;
  }

  //----------------------------------------------------------------------------
  // epsonrtc
  //   ram name=rtc.ram size=0x10
  //   map id=io address=00-3f,80-bf:4840-4842
  ea_t xlat_epsonrtc(ea_t address, bool & dispatched)
  {
    uint16 addr = address & 0xffff;
    uint8 bank = (address >> 16) & 0xff;

    dispatched = true;

    if ( bank <= 0x3f || ( bank >= 0x80 && bank <= 0xbf ) )
    {
      if ( addr >= 0x4840 && addr <= 0x4842 )
      {
        return addr;
      }
    }

    dispatched = false;
    return false;
  }

  //----------------------------------------------------------------------------
  // obc1
  //   ram name=save.ram size=0x2000
  //   map id=io address=00-3f,80-bf:6000-7fff
  ea_t xlat_obc1(ea_t address, bool & dispatched)
  {
    // TODO: Add OBC-1 address mapping
    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // necdsp model=uPD7725 frequency=8000000
  //   rom id=program name=dsp1b.program.rom size=0x1800
  //   rom id=data name=dsp1b.data.rom size=0x800
  //   ram id=data size=0x200
  //
  // when DSP1LoROM1MB:
  //   map id=io address=20-3f,a0-bf:8000-ffff select=0x4000
  //
  // when DSP1LoROM2MB:
  //   map id=io address=60-6f,e0-ef:0000-7fff select=0x4000
  //
  // when DSP1HiROM:
  //   map id=io address=00-1f,80-9f:6000-7fff select=0x1000
  ea_t xlat_dsp1(ea_t address, SuperFamicomCartridge::DSP1MemoryMapper /*dsp1_mapper*/, bool & dispatched)
  {
    // TODO: Add DSP-1 address mapping
    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // necdsp model=uPD7725 frequency=8000000
  //   rom id=program name=dsp2.program.rom size=0x1800
  //   rom id=data name=dsp2.data.rom size=0x800
  //   ram id=data size=0x200
  //   map id=io address=20-3f,a0-bf:8000-ffff select=0x4000
  ea_t xlat_dsp2(ea_t address, bool & dispatched)
  {
    // TODO: Add DSP-2 address mapping
    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // necdsp model=uPD7725 frequency=8000000
  //   rom id=program name=dsp3.program.rom size=0x1800
  //   rom id=data name=dsp3.data.rom size=0x800
  //   ram id=data size=0x200
  //   map id=io address=20-3f,a0-bf:8000-ffff select=0x4000
  ea_t xlat_dsp3(ea_t address, bool & dispatched)
  {
    // TODO: Add DSP-3 address mapping
    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // necdsp model=uPD7725 frequency=8000000
  //   rom id=program name=dsp4.program.rom size=0x1800
  //   rom id=data name=dsp4.data.rom size=0x800
  //   ram id=data size=0x200
  //   map id=io address=30-3f,b0-bf:8000-ffff select=0x4000
  ea_t xlat_dsp4(ea_t address, bool & dispatched)
  {
    // TODO: Add DSP-4 address mapping
    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // necdsp model=uPD96050 frequency=11000000
  //   rom id=program name=st010.program.rom size=0xc000
  //   rom id=data name=st010.data.rom size=0x1000
  //   ram id=data name=save.ram size=0x1000
  //   map id=io address=60-67,e0-e7:0000-3fff select=0x0001
  //   map id=ram address=68-6f,e8-ef:0000-7fff
  ea_t xlat_st010(ea_t address, bool & dispatched)
  {
    // TODO: Add ST-010 address mapping
    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // necdsp model=uPD96050 frequency=15000000
  //   rom id=program name=st011.program.rom size=0xc000
  //   rom id=data name=st011.data.rom size=0x1000
  //   ram id=data name=save.ram size=0x1000
  //   map id=io address=60-67,e0-e7:0000-3fff select=0x0001
  //   map id=ram address=68-6f,e8-ef:0000-7fff
  ea_t xlat_st011(ea_t address, bool & dispatched)
  {
    // TODO: Add ST-011 address mapping
    dispatched = false;
    return address;
  }

  //----------------------------------------------------------------------------
  // armdsp frequency=21477272
  //   rom id=program name=st018.program.rom size=0x20000
  //   rom id=data name=st018.data.rom size=0x8000
  //   ram name=save.ram size=0x4000
  //   map id=io address=00-3f,80-bf:3800-38ff
  ea_t xlat_st018(ea_t address, bool & dispatched)
  {
    // TODO: Add ST-018 address mapping
    dispatched = false;
    return address;
  }

public:
  //----------------------------------------------------------------------------
  bool addr_init(const SuperFamicomCartridge & cartridge)
  {
    g_cartridge = cartridge;

    switch ( g_cartridge.mapper )
    {
      case SuperFamicomCartridge::LoROM:
      case SuperFamicomCartridge::HiROM:
      case SuperFamicomCartridge::ExLoROM:
      case SuperFamicomCartridge::ExHiROM:
      case SuperFamicomCartridge::SuperFXROM:
      case SuperFamicomCartridge::SA1ROM:
      case SuperFamicomCartridge::SPC7110ROM:
        return true;
      default:
        return false;
    }
  }

  //----------------------------------------------------------------------------
  ea_t xlat(ea_t address)
  {
    bool dispatched;
    ea_t remapped_address;

    remapped_address = xlat_system(address, dispatched);
    if ( dispatched )
      return remapped_address;

    if ( g_cartridge.has_cx4 )
    {
      remapped_address = xlat_cx4(address, dispatched);
    }
    else if ( g_cartridge.has_sdd1 )
    {
      remapped_address = xlat_sdd1(address, dispatched);
    }
    else
    {
      switch ( g_cartridge.mapper )
      {
        case SuperFamicomCartridge::LoROM:
          remapped_address = xlat_lorom(address, dispatched);
          break;
        case SuperFamicomCartridge::HiROM:
          remapped_address = xlat_hirom(address, dispatched);
          break;
        case SuperFamicomCartridge::ExLoROM:
          remapped_address = xlat_exlorom(address, dispatched);
          break;
        case SuperFamicomCartridge::ExHiROM:
          remapped_address = xlat_exhirom(address, dispatched);
          break;
        case SuperFamicomCartridge::SuperFXROM:
          remapped_address = xlat_superfxrom(address, dispatched);
          break;
        case SuperFamicomCartridge::SA1ROM:
          remapped_address = xlat_sa1rom(address, dispatched);
          break;
        case SuperFamicomCartridge::SPC7110ROM:
          remapped_address = xlat_spc7110(address, dispatched);
          break;
        default:
          break;
      }
    }
    if ( dispatched )
      return remapped_address;

    if ( g_cartridge.has_sharprtc )
    {
      remapped_address = xlat_sharprtc(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_epsonrtc )
    {
      remapped_address = xlat_epsonrtc(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_obc1 )
    {
      remapped_address = xlat_obc1(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_dsp1 )
    {
      remapped_address = xlat_dsp1(address, g_cartridge.dsp1_mapper, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_dsp2 )
    {
      remapped_address = xlat_dsp2(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_dsp3 )
    {
      remapped_address = xlat_dsp3(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_dsp4 )
    {
      remapped_address = xlat_dsp4(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_st010 )
    {
      remapped_address = xlat_st010(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_st011 )
    {
      remapped_address = xlat_st011(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    if ( g_cartridge.has_st018 )
    {
      remapped_address = xlat_st018(address, dispatched);
      if ( dispatched )
        return remapped_address;
    }

    return address;
  }
};


#include "m65816.hpp"
#include "bt.hpp"

// ---------------------------------------------------------------------------
//lint -estring(823,BTWALK_PREAMBLE) definition of macro ends in semi-colon
#define BTWALK_PREAMBLE(walker_ea, opcode_var, itype_var) \
  if ( (walker_ea) < 4 )                                  \
    break;                                                \
  (walker_ea) = prev_head((walker_ea), (walker_ea) - 4);  \
  if ( (walker_ea) == BADADDR )                           \
    break;                                                \
  flags64_t F = get_flags(walker_ea);                     \
  if ( is_func(F) || !is_code(F) )                        \
    break;                                                \
  opcode_var = get_byte(walker_ea);                       \
  itype_var = get_opcode_info(opcode_var).itype;

// ---------------------------------------------------------------------------
// FIXME: The following are lacks in implementation:
// * If the value we asked for is 16bits, and
//   at some point we are reduced to an 8-bits one, we should
//   fail.
int32 backtrack_value(ea_t from_ea, uint8 size, btsource_t source)
{
  // Note: At some point, we were using:
  // ---
  //   const func_t * const func = get_fchunk(from_ea);
  //   if (func == nullptr)
  //     return -1;
  //   ea_t chunk_start_ea = func->start_ea;
  // ---
  // in order to determine where we had to stop backtracking
  // values.
  // Unfortunately, that doesn't work because, during the initial
  // analysis, where functions & chunks aren't properly formed yet,
  // the 'func' ptr would always be nullptr. Therefore, we wouldn't
  // be capable of backtracking a value properly; which also
  // means that wrong values were propagated to other
  // functions.
  //
  // A particularily interesting example is this: In a certain
  // rom, we had the following seq. of instructions:
  //
  // --------------------------------------------------------------------------
  // .C0:0019                 SEI
  // .C0:001A                 CLC
  // .C0:001B                 XCE
  // .C0:001C                 SEP     #$20 ; ' '      ; .a8, .i16
  // .C0:001E                 REP     #$10            ; .a8, .i16
  // .C0:0020                 LDX     #$15FF
  // .C0:0023                 TXS
  // .C0:0024                 LDX     #0
  // .C0:0027                 PHX
  // .C0:0028                 PLD
  // .C0:0029                 TDC
  // .C0:002A                 PHA
  // .C0:002B                 PLB
  // .C0:002C                 LDA     #1
  // .C0:002E                 STA     CYCLE_SPEED_DESIGNATION ; 0000000a a: 0 = 2.68 MHz, 1 = 3.58 MHz
  // .C0:0031                 STZ     REGULAR_DMA_CHANNEL_ENABLE ; abcdefgh a = Channel 7...h = Channel 0: 1 = Enable 0 = Disable
  // .C0:0034                 STZ     H_DMA_CHANNEL_ENABLE ; abcdefgh a = Channel 7 .. h = Channel 0: 1 = Enable 0 = Disable
  // .C0:0037                 LDA     #$8F ; ''
  // .C0:0039                 STA     SCREEN_DISPLAY_REGISTER ; a000bbbb a: 0=screen on 1=screen off, b = brightness
  // .C0:003C                 STZ     NMI_V_H_COUNT_AND_JOYPAD_ENABLE ; a0bc000d a = NMI b = V-Count c = H-Count d = Joypad
  // .C0:003F                 JSR     sub_C00525
  // --------------------------------------------------------------------------
  //
  // And, at 0xc00525:
  //
  // --------------------------------------------------------------------------
  // .C0:0525 sub_C00525:                             ; CODE XREF: sub_C00019+26p
  // .C0:0525                 TDC
  // .C0:0526                 TAX
  // .C0:0527                 STX     WRAM_ADDRESS_LOW_BYTE
  // .C0:052A                 STA     WRAM_ADDRESS_HIGH_BYTE
  // .C0:052D                 LDX     #$120
  // .C0:0530
  // .C0:0530 loc_C00530:                             ; CODE XREF: sub_C00525+3Cj
  // .C0:0530                 STA     WRAM_DATA_READ_WRITE
  // .C0:0533                 STA     WRAM_DATA_READ_WRITE
  // .C0:0536                 STA     WRAM_DATA_READ_WRITE
  // .C0:0539                 STA     WRAM_DATA_READ_WRITE
  // .C0:053C                 STA     WRAM_DATA_READ_WRITE
  // .C0:053F                 STA     WRAM_DATA_READ_WRITE
  // .C0:0542                 STA     WRAM_DATA_READ_WRITE
  // .C0:0545                 STA     WRAM_DATA_READ_WRITE
  // .C0:0548                 STA     WRAM_DATA_READ_WRITE
  // .C0:054B                 STA     WRAM_DATA_READ_WRITE
  // .C0:054E                 STA     WRAM_DATA_READ_WRITE
  // .C0:0551                 STA     WRAM_DATA_READ_WRITE
  // .C0:0554                 STA     WRAM_DATA_READ_WRITE
  // .C0:0557                 STA     WRAM_DATA_READ_WRITE
  // .C0:055A                 STA     WRAM_DATA_READ_WRITE
  // .C0:055D                 STA     WRAM_DATA_READ_WRITE
  // .C0:0560                 DEX
  // .C0:0561                 BNE     loc_C00530
  // .C0:0563                 RTS
  // --------------------------------------------------------------------------
  //
  // What would happen is that the 'STA's starting at
  // C0:0530 would not reference the proper register:
  // The B was 0xffffffff (from a previous
  // propagation), and when a later propagation tried to set
  // the B value to 0x00, starting at C0:0525, that
  // propagation stopped at the next segment start.
  // That is, C0:0530,
  // which was established because of the BNE that
  // appears below.
  // Which also makes me think.. should we propagate from a BNE?

  uint8 opcode;
  ea_t cur_ea = from_ea;
  uint8 itype;
  switch ( source )
  {
    case BT_STACK:
      while ( true )
      {
        BTWALK_PREAMBLE(cur_ea, opcode, itype);
        if ( M65_ITYPE_PUSH(itype) )
        {
          switch ( itype )
          {
            case M65816_pea:    // Push effective absolute address
              {
                uint16 val = get_word(cur_ea + 1);
                if ( size == 1 )
                  val &= 0xff;
                return val;
              }
            case M65816_pei:    // Push effective indirect address
              return -1;
            case M65816_per:    // Push effective PC-relative indirect address
              {
                uint16 val = cur_ea + 3;
                val += get_word(cur_ea + 1);
                val &= (size == 1 ? 0xff : 0xffff);
                return val;
              }
            case M65816_pha:    // Push A
              return backtrack_value(cur_ea, size, BT_A);
            case M65816_phb:    // Push B (data bank register)
              return get_sreg(cur_ea, rB);
            case M65816_phd:    // Push D (direct page register)
              return get_sreg(cur_ea, rD);
            case M65816_phk:    // Push K (program bank register)
              return get_sreg(cur_ea, rPB);
            case M65816_php:    // Push processor status
              return -1;
            case M65816_phx:    // Push X
              return backtrack_value(cur_ea, size, BT_X);
            case M65816_phy:    // Push Y
              return backtrack_value(cur_ea, size, BT_Y);
            default:
              return -1;
          }
        }
        else if ( M65_ITYPE_PULL(itype) )
        {
          // TODO: keep track of additional displacements in the stack
          return -1;
        }
      }
      break;
    case BT_A:
      while ( true )
      {
        BTWALK_PREAMBLE(cur_ea, opcode, itype);
        uint8 opsize = from_ea - cur_ea;
        uint8 cur_ea_acc_is_16 = is_acc_16_bits(cur_ea);
        uint8 new_size = cur_ea_acc_is_16 ? 2 : 1;
        switch ( itype )
        {
          // All these modify A in a way we cannot
          // easily determine its value anymore.
          // We'll thus stop.
          case M65816_adc:    // Add with carry
          case M65816_and:    // AND A with memory
          case M65816_asl:    // Shift memory or A left
          case M65816_dec:    // Decrement
          case M65816_eor:    // XOR A with M
          case M65816_inc:    // Increment
          case M65816_mvn:    // Block move next
          case M65816_mvp:    // Block move prev
          case M65816_ora:    // Or A with memory
          case M65816_sbc:    // Subtract with borrow from A
          case M65816_xba:    // Exchange bytes in A
            return -1;
            // For these next ones, there's hope.
          case M65816_lsr:    // Logical shift memory or A right
            if ( opcode == 0x4a ) // LSR    A
              return -1;
            break;
          case M65816_rol:    // Rotate memory or A left
          case M65816_ror:    // Rotate memory or A right
            if ( opcode == 0x30 || opcode == 0x70 )
              return -1;
            break;
          case M65816_lda:    // Load A from memory
            if ( opcode == 0xa9 ) // LDA    imm
              return opsize == 3 ? get_word(cur_ea + 1) : get_byte(cur_ea + 1);
            else
              return -1;
          case M65816_pla:    // Pull A
            return backtrack_value(cur_ea, new_size, BT_STACK);
          case M65816_tdc:    // Transfer 16-bit D to A
            return get_sreg(cur_ea, rD);
          case M65816_tsc:    // Transfer S to A
            return get_sreg(cur_ea, rS);
          case M65816_txa:    // Transfer X to A
            return backtrack_value(cur_ea, new_size, BT_X);
          case M65816_tya:    // Transfer Y to A
            return backtrack_value(cur_ea, new_size, BT_Y);
        }
      }
      break;
    case BT_X:
      while ( true )
      {
        BTWALK_PREAMBLE(cur_ea, opcode, itype);
        uint8 opsize = from_ea - cur_ea;
        uint8 cur_ea_xy_is_16 = is_xy_16_bits(cur_ea);
        uint8 new_size = cur_ea_xy_is_16 ? 2 : 1;
        switch ( itype )
        {
          // All these modify X in a way we cannot
          // easily determine its value anymore.
          // We'll thus stop.
          case M65816_dex:    // Decrement X
          case M65816_inx:    // Increment X
          case M65816_mvn:    // Block move next
          case M65816_mvp:    // Block move prev
            return -1;
          case M65816_ldx:    // Load X from memory
            if ( opcode == 0xa2 ) // LDX    imm
              return opsize == 3 ? get_word(cur_ea + 1) : get_byte(cur_ea + 1);
            else
              return -1;
          case M65816_plx:    // Pull X
            return backtrack_value(cur_ea, new_size, BT_STACK);
          case M65816_tax:    // Transfer A to X
            return backtrack_value(cur_ea, new_size, BT_A);
          case M65816_tsx:    // Transfer S to X
            return get_sreg(cur_ea, rS);
          case M65816_tyx:    // Transfer Y to X
            return backtrack_value(cur_ea, new_size, BT_Y);
        }
      }
      break;
    case BT_Y:
      while ( true )
      {
        BTWALK_PREAMBLE(cur_ea, opcode, itype);
        uint8 opsize = from_ea - cur_ea;
        uint8 cur_ea_xy_is_16 = is_xy_16_bits(cur_ea);
        uint8 new_size = cur_ea_xy_is_16 ? 2 : 1;
        switch ( itype )
        {
          // All these modify X in a way we cannot
          // easily determine its value anymore.
          // We'll thus stop.
          case M65816_dey:    // Decrement Y
          case M65816_iny:    // Increment Y
          case M65816_mvn:    // Block move next
          case M65816_mvp:    // Block move prev
            return -1;
          case M65816_ldy:    // Load Y from memory
            if ( opcode == 0xa0 ) // LDY    imm
              return opsize == 3 ? get_word(cur_ea + 1) : get_byte(cur_ea + 1);
            else
              return -1;
          case M65816_ply:    // Pull Y
            return backtrack_value(cur_ea, new_size, BT_STACK);
          case M65816_tay:    // Transfer A to Y
            return backtrack_value(cur_ea, new_size, BT_A);
          case M65816_txy:    // Transfer X to Y
            return backtrack_value(cur_ea, new_size, BT_X);
        }
      }
      break;
    case BT_DP:
      while ( true )
      {
        BTWALK_PREAMBLE(cur_ea, opcode, itype);
        switch ( itype )
        {
          // All these modify D in a way we cannot
          // easily determine its value anymore.
          // We'll thus stop.
          case M65816_pld:    // Pull D
            return backtrack_value(cur_ea, size, BT_STACK);
          case M65816_tcd:    // Transfer 16-bit Accumulator to Direct Page Register
            return backtrack_value(cur_ea, size, BT_A);
        }
      }
      break;
    default:
      msg("WARNING: backtrack_value() of unsupported BT-type: %d\n", source);
      break;
  }

  return -1;
}

// ---------------------------------------------------------------------------
ea_t backtrack_prev_ins(ea_t from_ea, m65_itype_t itype)
{
  uint8 opcode;
  ea_t cur_ea = from_ea;
  uint8 candidate_itype;
  while ( true )
  {
    BTWALK_PREAMBLE(cur_ea, opcode, candidate_itype);
    if ( candidate_itype == itype )
      return cur_ea;
  }

  return BADADDR;
}

#undef BTWALK_LOOP
#undef BTWALK_PREAMBLE



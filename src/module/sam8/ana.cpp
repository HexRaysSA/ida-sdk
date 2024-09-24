/************************************************************************/
/* Disassembler for Samsung SAM8 processors                             */
/************************************************************************/

#include "sam8.hpp"


/**
 * Register operand
 */
static void reg_operand(
        insn_t &insn,
        int op,
        bool indirect,
        bool workingReg,
        bool regPair,
        uint16 regNum)
{
  // do it
  if ( !indirect )
  {
    insn.ops[op].type = o_reg;
    insn.ops[op].reg = regNum;
    insn.ops[op].fl_workingReg = workingReg;
    insn.ops[op].fl_regPair = regPair;
  }
  else
  {
    insn.ops[op].type = o_phrase;
    insn.ops[op].phrase = fIndReg;
    insn.ops[op].v_phrase_reg = regNum;
    insn.ops[op].fl_workingReg = workingReg;
    insn.ops[op].fl_regPair = regPair;
  }
}


/**
 * Indexed register operand
 */
static void idx_reg_operand(insn_t &insn, int op, uint16 baseRegNum, uint16 idxRegNum)
{
  insn.ops[op].type = o_phrase;
  insn.ops[op].phrase = fIdxReg;
  insn.ops[op].v_phrase_reg = baseRegNum;
  insn.ops[op].v_phrase_idxreg = idxRegNum;
}


/**
 * Indexed address operand in code memory
 */
static void idx_cdata_operand(
        insn_t &insn,
        int op,
        int offset,
        int baseAddr,
        uint16 idxRegNum)
{
  insn.ops[op].type = o_displ;
  insn.ops[op].phrase = fIdxCAddr;
  insn.ops[op].addr = baseAddr;
  insn.ops[op].v_phrase_idxreg = idxRegNum;
  insn.ops[op].dtype = dt_word;
  insn.ops[op].offb = (uchar)offset;
}


/**
 * Indexed address operand in external (data) memory
 */
static void idx_edata_operand(
        insn_t &insn,
        int op,
        int offset,
        int baseAddr,
        uint16 idxRegNum)
{
  insn.ops[op].type = o_displ;
  insn.ops[op].phrase = fIdxEAddr;
  insn.ops[op].addr = baseAddr;
  insn.ops[op].v_phrase_idxreg = idxRegNum;
  insn.ops[op].dtype = dt_word;
  insn.ops[op].offb = (uchar)offset;
}


/**
 * Register bit operand
 */
static void regbit_operand(insn_t &insn, int op, bool workingReg, uint16 regNum, int bit)
{
  insn.ops[op].type = o_reg_bit;
  insn.ops[op].reg = regNum;
  insn.ops[op].fl_workingReg = workingReg;
  insn.ops[op].v_bit = bit;
}


/**
 * Immediate operand
 */
static void imm_operand(insn_t &insn, int op, int offset, uint32 value, char dtype)
{
  insn.ops[op].type = o_imm;
  insn.ops[op].value = value;
  insn.ops[op].dtype = dtype;
  insn.ops[op].offb = (uchar)offset;
}


/**
 * Address operand in external (data) memory
 */
static void addr_edata_operand(insn_t &insn, int op, int offset, ea_t address)
{
  insn.ops[op].type = o_emem;
  insn.ops[op].addr = address;
  insn.ops[op].offb = (uchar)offset;
}


/**
 * Address operand in code memory
 */
static void addr_cdata_operand(insn_t &insn, int op, int offset, ea_t address)
{
  insn.ops[op].type = o_cmem;
  insn.ops[op].addr = address;
  insn.ops[op].offb = (uchar)offset;
}


/**
 * Code operand (e.g. JP destination)
 */
static void code_operand(insn_t &insn, int op, int offset, ea_t address)
{
  insn.ops[op].type = o_near;
  insn.ops[op].addr = address;
  insn.ops[op].offb = (uchar)offset;
}


/**
 * Indirect code operand in "zero" page
 */
static void ind_code_operand(insn_t &insn, int op, int offset, ea_t address)
{
  insn.ops[op].type = o_cmem_ind;
  insn.ops[op].addr = address;
  insn.ops[op].offb = (uchar)offset;
}


/**
 * Finalise cmd data structure
 */
static int finalise_insn(insn_t &insn, uint16 opcode)
{
  // final checks on operands
  for ( int i=0; i < 3; i++ )
  {
    // check reg pair operands are even
    if ( insn.ops[i].type == o_reg
      && insn.ops[i].fl_regPair
      && insn.ops[i].reg & 1 )
    {
      return 0;
    }

    // check idxreg is even
    if ( insn.ops[i].type == o_displ
      && (insn.ops[i].phrase == fIdxCAddr
       || insn.ops[i].phrase == fIdxEAddr)
      && insn.ops[i].v_phrase_idxreg & 1 )
    {
      return 0;
    }

    // check workingReg is valid for register operands
    if ( insn.ops[i].type == o_reg
      && insn.ops[i].fl_workingReg
      && insn.ops[i].reg > 15 )
    {
      return 0;
    }

    // check workingReg is valid for indreg operands
    if ( insn.ops[i].type == o_phrase
      && insn.ops[i].phrase == fIndReg
      && insn.ops[i].fl_workingReg
      && insn.ops[i].v_phrase_reg > 15 )
    {
      return 0;
    }
  }

  // set opcode & set no condition code
  insn.itype = opcode;
  insn.c_condition = ccNone;

  // return size
  return insn.size;
}


/**
 * Finalise cmd data structure, with condition code
 */
static int finalise_insn(insn_t &insn, uint16 opcode, uchar condition)
{
  // do initial instruction setup
  if ( !finalise_insn(insn, opcode) )
    return 0;

  // set return code
  insn.c_condition = condition;

  // return size
  return insn.size;
}


/**
 * Get the next LITTLE ENDIAN word.
 * For some reason this processor uses LITTLE ENDIAN OCCASIONALLY!!!
 */
static inline ushort next_word_le(insn_t &insn)
{
  return insn.get_next_byte() | (insn.get_next_byte() << 8);
}



//----------------------------------------------------------------------
// analyze an basic instruction
static int ana_basic(insn_t &insn)
{
  // get the command code byte
  ushort code = insn.get_next_byte();

  // decode the special case (annoying) instructions
  switch ( code )
  {
    case 0x30:
      reg_operand(insn, 0, true, false, true, insn.get_next_byte());
      return finalise_insn(insn, SAM8_JP);

    case 0x31:
      {
        // need to decode second byte to determine exact type
        ushort tmp = insn.get_next_byte();
        switch ( tmp & 0x03 )
        {
          case 0:
            imm_operand(insn, 0, 1, tmp & 0xF0, dt_byte);
            return finalise_insn(insn, SAM8_SRP);

          case 1:
            imm_operand(insn, 0, 1, tmp & 0xF8, dt_byte);
            return finalise_insn(insn, SAM8_SRP1);

          case 2:
            imm_operand(insn, 0, 1, tmp & 0xF8, dt_byte);
            return finalise_insn(insn, SAM8_SRP0);

          case 3:
            return 0; // invalid instruction
        }
      }
      // fallthrough

    case 0x82: case 0x92: case 0x83: case 0x93:
      {
        // work out correct code
        ushort opcode = 0;
        switch ( code )
        {
          case 0x82: opcode = SAM8_PUSHUD; break;
          case 0x92: opcode = SAM8_POPUD; break;
          case 0x83: opcode = SAM8_PUSHUI; break;
          case 0x93: opcode = SAM8_POPUI; break;
        }

        // setup operands
        if ( opcode == SAM8_POPUD || opcode == SAM8_POPUI )
        {
          reg_operand(insn, 1, true, false, false, insn.get_next_byte());
          reg_operand(insn, 0, false, false, false, insn.get_next_byte());
        }
        else
        {
          reg_operand(insn, 0, true, false, false, insn.get_next_byte());
          reg_operand(insn, 1, false, false, false, insn.get_next_byte());
        }
        return finalise_insn(insn, opcode);
      }

    case 0xC2: case 0xD2:
      {
        // work out correct code
        ushort opcode = 0;
        switch ( code )
        {
          case 0xC2: opcode = SAM8_CPIJE; break;
          case 0xD2: opcode = SAM8_CPIJNE; break;
        }

        // decode it
        ushort tmp = insn.get_next_byte();
        reg_operand(insn, 0, false, true, false, bottom_nibble(tmp));
        reg_operand(insn, 1, true, true, false, top_nibble(tmp));
        code_operand(insn, 2, 2, insn.ea + 3 + (char) insn.get_next_byte());
        return finalise_insn(insn, opcode);
      }

    case 0xE2: case 0xF2: case 0xC3: case 0xD3: case 0xE3: case 0xF3:
      {
        // need the next byte to tell whether data or code memory
        ushort opcode = 0;
        ushort tmp = insn.get_next_byte();
        ushort operandT = top_nibble(tmp);
        ushort operandB = bottom_nibble(tmp);
        if ( operandB & 1 )
        {
          switch ( code )
          {
            case 0xE2: opcode = SAM8_LDED; break;
            case 0xF2: opcode = SAM8_LDEPD; break;
            case 0xC3: opcode = SAM8_LDE; break;
            case 0xD3: opcode = SAM8_LDE; break;
            case 0xE3: opcode = SAM8_LDEI; break;
            case 0xF3: opcode = SAM8_LDEPI; break;
          }
          operandB--;
        }
        else
        {
          switch ( code )
          {
            case 0xE2: opcode = SAM8_LDCD; break;
            case 0xF2: opcode = SAM8_LDCPD; break;
            case 0xC3: opcode = SAM8_LDC; break;
            case 0xD3: opcode = SAM8_LDC; break;
            case 0xE3: opcode = SAM8_LDCI; break;
            case 0xF3: opcode = SAM8_LDCPI; break;
          }
        }

        // decode it
        if ( code & 0x10 )
        {
          reg_operand(insn, 0, true, true, true, operandB);
          reg_operand(insn, 1, false, true, false, operandT);
        }
        else
        {
          reg_operand(insn, 0, false, true, false, operandT);
          reg_operand(insn, 1, true, true, true, operandB);
        }
        return finalise_insn(insn, opcode);
      }

    case 0xD4:
      {
        // get indirect address & check it is valid
        ushort tmp = insn.get_next_byte();
        if ( tmp & 1 )
          return 0;

        // generate operation
        ind_code_operand(insn, 0, 1, tmp);
        return finalise_insn(insn, SAM8_CALL);
      }

    case 0xF4:
      reg_operand(insn, 0, true, false, true, insn.get_next_byte());
      return finalise_insn(insn, SAM8_CALL);

    case 0xF6:
      code_operand(insn, 0, 1, insn.get_next_word());
      return finalise_insn(insn, SAM8_CALL);

    case 0xE4:
      reg_operand(insn, 1, false, false, false, insn.get_next_byte());
      reg_operand(insn, 0, false, false, false, insn.get_next_byte());
      return finalise_insn(insn, SAM8_LD);

    case 0xE5:
      reg_operand(insn, 1, true, false, false, insn.get_next_byte());
      reg_operand(insn, 0, false, false, false, insn.get_next_byte());
      return finalise_insn(insn, SAM8_LD);

    case 0xF5:
      reg_operand(insn, 1, false, false, false, insn.get_next_byte());
      reg_operand(insn, 0, true, false, false, insn.get_next_byte());
      return finalise_insn(insn, SAM8_LD);

    case 0xD5:
      return 0; // invalid instruction

    case 0x87: case 0x97:
      {
        // get next byte
        ushort tmp = insn.get_next_byte();

        // setup operands
        switch ( code )
        {
          case 0x87:
            reg_operand(insn, 0, false, true, false, top_nibble(tmp));
            idx_reg_operand(insn, 1, insn.get_next_byte(), bottom_nibble(tmp));
            break;

          case 0x97:
            idx_reg_operand(insn, 0, insn.get_next_byte(), bottom_nibble(tmp));
            reg_operand(insn, 1, false, true, false, top_nibble(tmp));
            break;
        }

        // finalise the instruction
        return finalise_insn(insn, SAM8_LD);
      }

    case 0xd6:
      reg_operand(insn, 0, true, false, false, insn.get_next_byte());
      imm_operand(insn, 1, 2, insn.get_next_byte(), dt_byte);
      return finalise_insn(insn, SAM8_LD);

    case 0xe6:
      reg_operand(insn, 0, false, false, false, insn.get_next_byte());
      imm_operand(insn, 1, 2, insn.get_next_byte(), dt_byte);
      return finalise_insn(insn, SAM8_LD);

    case 0xc7:
      {
        ushort tmp = insn.get_next_byte();
        reg_operand(insn, 0, false, true, false, top_nibble(tmp));
        reg_operand(insn, 1, true, true, false, bottom_nibble(tmp));
        return finalise_insn(insn, SAM8_LD);
      }

    case 0xd7:
      {
        ushort tmp = insn.get_next_byte();
        reg_operand(insn, 0, true, true, false, top_nibble(tmp));
        reg_operand(insn, 1, false, true, false, bottom_nibble(tmp));
        return finalise_insn(insn, SAM8_LD);
      }

    case 0xa7: case 0xb7:
      {
        // extract data
        ushort tmp = insn.get_next_byte();

        // decode opcode + setup operands
        ushort opcode;
        switch ( bottom_nibble(tmp) )
        {
          case 0:
            opcode = SAM8_LDC;
            switch ( code )
            {
              case 0xa7:
                reg_operand(insn, 0, false, true, false, top_nibble(tmp));
                addr_cdata_operand(insn, 1, 2, next_word_le(insn));
                break;

              case 0xb7:
                addr_cdata_operand(insn, 0, 2, next_word_le(insn));
                reg_operand(insn, 1, false, true, false, top_nibble(tmp));
                break;
            }
            break;

          case 1:
            opcode = SAM8_LDE;
            switch ( code )
            {
              case 0xa7:
                reg_operand(insn, 0, false, true, false, top_nibble(tmp));
                addr_edata_operand(insn, 1, 2, next_word_le(insn));
                break;

              case 0xb7:
                addr_edata_operand(insn, 0, 2, next_word_le(insn));
                reg_operand(insn, 1, false, true, false, top_nibble(tmp));
                break;
            }
            break;

          default:
            // extract operand nibbles
            ushort operandT = top_nibble(tmp);
            ushort operandB = bottom_nibble(tmp);

            // decode the correct opcode
            if ( operandB & 1 )
            {
              opcode = SAM8_LDE;
              operandB--;
            }
            else
            {
              opcode = SAM8_LDC;
            }

            // generate operands
            switch ( code )
            {
              case 0xA7:
                reg_operand(insn, 0, false, true, false, operandT);
                if ( opcode == SAM8_LDC )
                  idx_cdata_operand(insn, 1, 2, next_word_le(insn), operandB);
                else
                  idx_edata_operand(insn, 1, 2, next_word_le(insn), operandB);
                break;

              case 0xB7:
                if ( opcode == SAM8_LDC )
                  idx_cdata_operand(insn, 0, 2, next_word_le(insn), operandB);
                else
                  idx_edata_operand(insn, 0, 2, next_word_le(insn), operandB);
                reg_operand(insn, 1, false, true, false, operandT);
                break;
            }
        }

        // finalise instruction
        return finalise_insn(insn, opcode);
      }

    case 0xE7: case 0xF7:
      {
        // extract data
        ushort tmp = insn.get_next_byte();
        ushort operandT = top_nibble(tmp);
        ushort operandB = bottom_nibble(tmp);

        // decode the correct opcode
        ushort opcode;
        if ( operandB & 1 )
        {
          opcode = SAM8_LDE;
          operandB--;
        }
        else
        {
          opcode = SAM8_LDC;
        }

        // generate operands
        switch ( code )
        {
          case 0xE7:
            reg_operand(insn, 0, false, true, false, operandT);
            if ( opcode == SAM8_LDC )
              idx_cdata_operand(insn, 1, 2, (int) (char) insn.get_next_byte(), operandB);
            else
              idx_edata_operand(insn, 1, 2, (int) (char) insn.get_next_byte(), operandB);
            break;

          case 0xF7:
            if ( opcode == SAM8_LDC )
              idx_cdata_operand(insn, 0, 2, (int) (char) insn.get_next_byte(), operandB);
            else
              idx_edata_operand(insn, 0, 2, (int) (char) insn.get_next_byte(), operandB);
            reg_operand(insn, 1, false, true, false, operandT);
            break;
        }

        // finalise the instruction
        return finalise_insn(insn, opcode);
      }

    case 0x84: case 0x85: case 0x86:
    case 0x94: case 0x95: case 0x96:
      {
        // decode correct opcode
        ushort opcode = 0;
        switch ( top_nibble(code) )
        {
          case 8: opcode = SAM8_MULT; break;
          case 9: opcode = SAM8_DIV; break;
        }

        // Now, generate instruction
        ushort src = insn.get_next_byte();
        ushort dst = insn.get_next_byte();
        reg_operand(insn, 0, false, false, true, dst);
        switch ( bottom_nibble(code) )
        {
          case 4: reg_operand(insn, 1, false, false, false, src); break;
          case 5: reg_operand(insn, 1, true, false, false, src); break;
          case 6: imm_operand(insn, 1, 1, src, dt_byte); break;
        }
        return finalise_insn(insn, opcode);
      }

    case 0xC4: case 0xC5:
      {
        // get data
        ushort src = insn.get_next_byte();
        ushort dst = insn.get_next_byte();

        // generate instruction
        reg_operand(insn, 0, false, false, true, dst);

        // decode addrmode for opcode 2
        switch ( code )
        {
          case 0xC4: reg_operand(insn, 1, false, false, true, src); break;
          case 0xC5: reg_operand(insn, 1, true, false, false, src); break;
        }
        return finalise_insn(insn, SAM8_LDW);
      }

    case 0xC6:
      reg_operand(insn, 0, false, false, true, insn.get_next_byte());
      imm_operand(insn, 1, 2, insn.get_next_word(), dt_word);
      return finalise_insn(insn, SAM8_LDW);

    case 0x17:
      {
        // get data
        ushort operandA = insn.get_next_byte();
        ushort src = insn.get_next_byte();

        // ensure operandA bit0 is 0
        if ( operandA & 1 )
          return 0;

        // generate instruction
        reg_operand(insn, 0, false, true, false, top_nibble(operandA));
        regbit_operand(insn, 1, false, src, bottom_nibble(operandA) >> 1);
        return finalise_insn(insn, SAM8_BCP);
      }

    case 0x37:
      {
        // get data
        ushort operandA = insn.get_next_byte();
        ushort dst = insn.get_next_byte();

        // generate operands
        code_operand(insn, 0, 2, insn.ea + 3 + (char) dst);
        regbit_operand(insn, 1, true,
                       top_nibble(operandA), bottom_nibble(operandA) >> 1);

        // generate operand
        switch ( operandA & 1 )
        {
          case 0: return finalise_insn(insn, SAM8_BTJRF);
          case 1: return finalise_insn(insn, SAM8_BTJRT);
        }
      }
      // fallthrough

    case 0x57:
      {
        // get data
        ushort operandA = insn.get_next_byte();

        // ensure operandA bit0 is 0
        if ( operandA & 1 )
          return 0;

        // generate instruction
        regbit_operand(insn, 0, true,
                       top_nibble(operandA), bottom_nibble(operandA) >> 1);
        return finalise_insn(insn, SAM8_BITC);
      }

    case 0x77:
      {
        // get data
        ushort operandA = insn.get_next_byte();

        // generate instruction
        regbit_operand(insn, 0, true,
                       top_nibble(operandA), bottom_nibble(operandA) >> 1);
        switch ( operandA & 1 )
        {
          case 0: return finalise_insn(insn, SAM8_BITR);
          case 1: return finalise_insn(insn, SAM8_BITS);
        }
      }
  }


  // Decode bit instructions
  if ( (bottom_nibble(code) == 7) && (top_nibble(code) < 8) )
  {
    static const uint16 codeTable[] =
    {
      SAM8_BOR, SAM8_null,
      SAM8_BXOR, SAM8_null,
      SAM8_LDB, SAM8_null,
      SAM8_BAND, SAM8_null
    };

    // extract data
    ushort operandA = insn.get_next_byte();
    ushort operandB = insn.get_next_byte();

    // generate instruction
    switch ( operandA & 1 )
    {
      case 0:
        reg_operand(insn, 0, false, true, false, top_nibble(operandA));
        regbit_operand(insn, 1, false, operandB, bottom_nibble(operandA) >> 1);
        break;

      case 1:
        regbit_operand(insn, 0, false, operandB, bottom_nibble(operandA) >> 1);
        reg_operand(insn, 1, false, true, false, top_nibble(operandA));
        break;
    }
    return finalise_insn(insn, codeTable[top_nibble(code)]);
  }


  // Do the instructions with stuff encoded in them
  switch ( bottom_nibble(code) )
  {
    case 0x08:
      reg_operand(insn, 0, false, true, false, top_nibble(code));
      reg_operand(insn, 1, false, false, false, insn.get_next_byte());
      return finalise_insn(insn, SAM8_LD);

    case 0x09:
      reg_operand(insn, 0, false, false, false, insn.get_next_byte());
      reg_operand(insn, 1, false, true, false, top_nibble(code));
      return finalise_insn(insn, SAM8_LD);

    case 0x0A:
      reg_operand(insn, 0, false, true, false, top_nibble(code));
      code_operand(insn, 1, 1, insn.ea + 2 + (char) insn.get_next_byte());
      return finalise_insn(insn, SAM8_DJNZ);

    case 0x0B:
      code_operand(insn, 0, 1, insn.ea + 2 + (char) insn.get_next_byte());
      return finalise_insn(insn, SAM8_JR, top_nibble(code));

    case 0x0C:
      reg_operand(insn, 0, false, true, false, top_nibble(code));
      imm_operand(insn, 1, 1, insn.get_next_byte(), dt_byte);
      return finalise_insn(insn, SAM8_LD);

    case 0x0D:
      code_operand(insn, 0, 1, insn.get_next_word()); // UNSURE ****
      return finalise_insn(insn, SAM8_JP, top_nibble(code));

    case 0x0E:
      reg_operand(insn, 0, false, true, false, top_nibble(code));
      return finalise_insn(insn, SAM8_INC);

    case 0x0F:
      {
        static const uint16 codeTable[] =
        {
          SAM8_NEXT, SAM8_ENTER,
          SAM8_EXIT, SAM8_WFI,
          SAM8_SB0,  SAM8_SB1,
          SAM8_IDLE, SAM8_STOP,
          SAM8_DI,   SAM8_EI,
          SAM8_RET,  SAM8_IRET,
          SAM8_RCF,  SAM8_SCF,
          SAM8_CCF,  SAM8_NOP
        };
        return finalise_insn(insn, codeTable[top_nibble(code)]);
      }
  }

  // Do R/RR/IR-only mode instructions
  if ( bottom_nibble(code) < 2 )
  {
    static const uint16 codeTable[] =
    {
      SAM8_DEC, SAM8_RLC,
      SAM8_INC, SAM8_null,
      SAM8_DA, SAM8_POP,
      SAM8_COM, SAM8_PUSH,
      SAM8_DECW, SAM8_RL,
      SAM8_INCW, SAM8_CLR,
      SAM8_RRC, SAM8_SRA,
      SAM8_RR, SAM8_SWAP
    };
    // do the operand
    if ( code & 1 )
    {
      reg_operand(insn, 0, true, false, false, insn.get_next_byte());
    }
    else
    {
      if ( (top_nibble(code) == 8) || (top_nibble(code) == 0xA) )
        reg_operand(insn, 0, false, false, true, insn.get_next_byte());
      else
        reg_operand(insn, 0, false, false, false, insn.get_next_byte());
    }

    // finalise it
    return finalise_insn(insn, codeTable[top_nibble(code)]);
  }

  // Decode arithmetic-style instructions
  if ( (bottom_nibble(code) > 1) && (bottom_nibble(code) < 7) )
  {
    static const uint16 codeTable[] =
    {
      SAM8_ADD,  SAM8_ADC,
      SAM8_SUB,  SAM8_SBC,
      SAM8_OR,   SAM8_AND,
      SAM8_TCM,  SAM8_TM,
      SAM8_null, SAM8_null,
      SAM8_CP,   SAM8_XOR,
      SAM8_null, SAM8_null,
      SAM8_null, SAM8_null
    };
    ushort operandA = insn.get_next_byte();
    switch ( bottom_nibble(code) )
    {
      case 2:
        reg_operand(insn, 0, false, true, false, top_nibble(operandA));
        reg_operand(insn, 1, false, true, false, bottom_nibble(operandA));
        return finalise_insn(insn, codeTable[top_nibble(code)]);

      case 3:
        reg_operand(insn, 0, false, true, false, top_nibble(operandA));
        reg_operand(insn, 1, true, true, false, bottom_nibble(operandA));
        return finalise_insn(insn, codeTable[top_nibble(code)]);

      case 4:
        reg_operand(insn, 0, false, false, false, insn.get_next_byte());
        reg_operand(insn, 1, false, false, false, operandA);
        return finalise_insn(insn, codeTable[top_nibble(code)]);

      case 5:
        reg_operand(insn, 0, false, false, false, insn.get_next_byte());
        reg_operand(insn, 1, true, false, false, operandA);
        return finalise_insn(insn, codeTable[top_nibble(code)]);

      case 6:
        reg_operand(insn, 0, false, false, false, operandA);
        imm_operand(insn, 1, 1, insn.get_next_byte(), dt_byte);
        return finalise_insn(insn, codeTable[top_nibble(code)]);
    }
  }

  // If we get here, we've got an invalid instruction
  return 0;
}

//----------------------------------------------------------------------
// analyze an instruction
int idaapi ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  // analyze it!
  return ana_basic(insn);
}

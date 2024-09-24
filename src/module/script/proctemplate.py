# ----------------------------------------------------------------------
# Processor module template script
# (c) Hex-Rays
import sys

import ida_pro
import ida_idp
import ida_funcs
import ida_ua
import ida_xref
import ida_idaapi

retcode_0 = 0xC3
retcode_1 = 0xC2
g_retcodes = [retcode_0, retcode_1]

# ----------------------------------------------------------------------
class sample_processor_t(ida_idp.processor_t):
    """
    Processor module classes must derive from ida_idp.processor_t

    A processor_t instance is, conceptually, both an IDP_Hooks and
    an IDB_Hooks. This means any callback from those two classes
    can be implemented. Below, you'll find a handful of those
    as an example (e.g., ev_out_header(), ev_newfile(), ...)
    Also note that some IDP_Hooks callbacks must be implemented
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = ida_idp.PR_ASSEMBLE \
         | ida_idp.PR_SEGS     \
         | ida_idp.PR_DEFSEG32 \
         | ida_idp.PR_USE32    \
         | ida_idp.PRN_HEX     \
         | ida_idp.PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['myproc']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['My processor module']

    # register names
    reg_names = [
        # General purpose registers
        "SP", # aka R0
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7",
        # VM registers
        "FLAGS", # 0
        "IP",    # 1
        "VM2",
        "VM3",
        "VM4",
        "VM5",
        "VM6",
        "VM7",
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(reg_names))
    regs_num = len(reg_names)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    reg_first_sreg = 16 # index of CS
    reg_last_sreg  = 17 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    reg_code_sreg = 16
    reg_data_sreg = 17

    # Array of typical code start sequences (optional)
    codestart = ['\x55\x8B', '\x50\x51']

    # Array of 'return' instruction opcodes (optional)
    retcodes = g_retcodes

    # Array of instructions. Since this is only a template,
    # this list will be extremely limited.
    instruc = [
        {'name': 'ADD', 'feature': ida_idp.CF_USE1 | ida_idp.CF_CHG1 | ida_idp.CF_USE2}, # ADD <reg>, <#imm> -- opcodes [0x00 -> 0x7F]
        {'name': 'MOV', 'feature': ida_idp.CF_USE1 | ida_idp.CF_CHG1 | ida_idp.CF_USE2}, # MOV <reg>, <reg> -- opcodes [0x80 -> 0xEF] (but retcodes)
        {'name': 'RET', 'feature': 0}, # RET -- opcodes 0xC2, 0xC3
        {'name': 'JMP', 'feature': ida_idp.CF_USE1 | ida_idp.CF_JUMP}, # JMP -- opcodes [0xF0 -> 0xFF]
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc)

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = 5

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ida_idp.ASH_HEXF3 \
               | ida_idp.AS_UNEQU  \
               | ida_idp.AS_COLON  \
               | ida_idp.ASB_BINF4 \
               | ida_idp.AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # remove if not allowed
        'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler

    def regname2index(self, regname):
        for idx in range(len(self.reg_names)):
            if regname == self.reg_names[idx]:
                return idx
        return -1


    OPTION_KEY_OPERAND_SEPARATOR = "PROCTEMPLATE_OPERAND_SEPARATOR"
    OPTION_KEY_OPERAND_SPACES = "PROCTEMPLATE_OPERAND_SPACES"


    # ----------------------------------------------------------------------
    def __init__(self):
      ida_idp.processor_t.__init__(self)
      self.operand_separator = ','
      self.operand_spaces = 1

    def asm_out_func_header(self, ctx, func_ea):
        """generate function header lines"""
        pass

    def asm_out_func_footer(self, ctx, func_ea):
        """generate function footer lines"""
        pass

    def asm_get_type_name(self, flag, ea_or_id):
        """
        Get name of type of item at ea or id.
        (i.e. one of: byte,word,dword,near,far,etc...)
        """
        if is_code(flag):
            pfn = get_func(ea_or_id)
            # return get func name
        elif is_word(flag):
            return "word"
        return ""

    #
    # IDP_Hooks callbacks (the first 4 are mandatory)
    #

    def ev_emu_insn(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        if insn.itype == 4: # JMP
            ida_xref.add_cref(insn.ea, insn.Op1.addr, ida_xref.fl_JN)
        elif insn.itype != 2: # 2 == RET, 4 == JMP
            ida_xref.add_cref(insn.ea, insn.ea + insn.size, ida_xref.fl_F)
        return True

    def ev_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: success
        """
        if op.type == ida_ua.o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif op.type == ida_ua.o_imm:
            ctx.out_value(op, ida_ua.OOFW_IMM)
        elif op.type == ida_ua.o_near:
            ctx.out_name_expr(op, op.addr, ida_idaapi.BADADDR)
        else:
            return False
        return True

    def ev_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()

        for i in range(0, 2):
            op = ctx.insn[i]
            if op.type == ida_ua.o_void:
                break;
            if i > 0:
                ctx.out_symbol(self.operand_separator)
                for _ in range(self.operand_spaces):
                  ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    def ev_ana_insn(self, insn):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        b = insn.get_next_byte()
        if b < 0x80:              # ADD
            insn.itype = 0
            insn.Op1.type = ida_ua.o_reg
            insn.Op1.reg = b & 0xF
            insn.Op2.type = ida_ua.o_imm
            insn.Op2.dtype = ida_ua.dt_byte
            insn.Op2.value = (b >> 4) & 0xF
        elif b in g_retcodes:     # RET
            insn.itype = 2
        elif b < 0xF0:            # MOV
            insn.itype = 1
            insn.Op1.type = ida_ua.o_reg
            insn.Op1.reg = b & 0xF
            insn.Op2.type = ida_ua.o_reg
            insn.Op2.value = (b >> 4) & 0xF
        else:
            insn.itype = 3
            insn.Op1.type = ida_ua.o_near
            insn.Op1.dtype = ida_ua.dt_dword
            insn.Op1.addr = insn.ea + (b & 0xF)

        return True

    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    def ev_out_header(self, ctx):
        """function to produce start of disassembled text"""
        return 0

    def ev_out_footer(self, ctx):
        """function to produce end of disassembled text"""
        return 0

    def ev_out_segstart(self, ctx, segment):
        """function to produce start of segment"""
        return 0

    def ev_out_segend(self, ctx, segment):
        """function to produce end of segment"""
        return 0

    def ev_out_assumes(self, ctx):
        """function to produce assume directives"""
        return 0

    def ev_term(self):
        """called when the processor module is unloading"""
        return 0

    def ev_setup_til(self):
        """Setup default type libraries (called after loading a new file into the database)
        The processor module may load tils, setup memory model and perform other actions required to set up the type system
        """
        return 0

    def ev_newprc(self, nproc, keep_cfg):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        return >=0-ok,<0-prohibit
        """
        return 0

    def ev_newfile(self, filename):
        """A new file is loaded (already)"""
        return 0

    def ev_oldfile(self, filename):
        """An old file is loaded (already)"""
        return 0

    def ev_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
         args:
          filename  - binary file name
          fileoff   - offset in the file
          basepara  - base loading paragraph
          binoff    - loader offset
          nbytes    - number of bytes to load
        """
        return 0

    def ev_undefine(self, ea):
        """
        An item in the database (insn or data) is being deleted
        @param args: ea
        @return: >=0-ok, <0 - the kernel should stop
                 if the return value is not negative:
                     bit0 - ignored
                     bit1 - do not delete srareas at the item end
        """
        return 0

    def ev_endbinary(self, ok):
        """
         After loading a binary file
         args:
          ok - file loaded successfully?
        """
        return 0

    def ev_assemble(self, ea, cs, ip, use32, line):
        """
        Assemble an instruction
         (make sure that PR_ASSEMBLE flag is set in the processor flags)
         (display a warning if an error occurs)
         args:
           ea -  linear address of instruction
           cs -  cs of instruction
           ip -  ip of instruction
           use32 - is 32bit segment?
           line - line to assemble
        returns the opcode string, or None
        """
        return 0

    def ev_out_data(self, ctx, analyze_only):
        """
        Generate text represenation of data items
        This function MAY change the database and create cross-references, etc.
        """
        ctx.out_data(analyze_only)
        return 1

    def ev_cmp_operands(self, op1, op2):
        """
        Compare instruction operands.
        Returns 1-equal, -1-not equal, 0-not implemented
        """
        return 0

    def ev_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
        """
        Set IDP-specific option
        args:
          keyword    - the option name
                       or empty string (check value_type when 0 below)
          value_type - one of
                         IDPOPT_STR  string constant
                         IDPOPT_NUM  number
                         IDPOPT_BIT  zero/one
                         IDPOPT_I64  64bit number
                         0 -> You should display a dialog to configure the processor module
          value   - the actual value
          idb_loaded - true if the ev_oldfile/ev_newfile events have been generated
        Returns:
           1 ok
           0 not implemented
           -1 error
        """
        if keyword == self.OPTION_KEY_OPERAND_SEPARATOR and value_type == ida_idp.IDPOPT_STR:
          self.operand_separator = value
          return 1
        if keyword == self.OPTION_KEY_OPERAND_SPACES and value_type == ida_idp.IDPOPT_NUM:
          self.operand_spaces = value
          return 1
        else:
          return -1

    def ev_gen_map_file(self, nlines, qfile):
        """
        Generate map file. If this function is absent then the kernel will create the map file.
        This function returns number of lines in output file.
        0 - not implemented, 1 - ok, -1 - write error
        """
        import ida_fpro
        qfile = ida_fpro.qfile_t_from_fp(fp)
        lines = ["Line 1\n", "Line 2\n!"]
        ida_pro.int_pointer.frompointer(nlines).assign(len(lines))
        for l in lines:
            qfile.write(l)
        return 1

    def ev_create_func_frame(self, pfn):
        """
        Create a function frame for a newly created function.
        Set up frame size, its attributes etc.
        """
        return 0

    def ev_is_far_jump(self, icode):
        """
        Is indirect far jump or call instruction?
        meaningful only if the processor has 'near' and 'far' reference types
        """
        return 0

    def ev_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return 0

    def ev_out_special_item(self, ctx, segtype):
        """
        Generate text representation of an item in a special segment
        i.e. absolute symbols, externs, communal definitions etc.
        Returns: 1-ok, 0-not implemented
        """
        return 0

    def ev_get_frame_retsize(self, frsize, pfn):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        ida_pro.int_pointer.frompointer(frsize).assign(2)
        return 1

    def ev_is_switch(self, swi, insn):
        """
        Find 'switch' idiom at instruction 'insn'.
        Fills 'swi' structure with information
        """
        return 0

    def ev_is_sp_based(self, mode, insn, op):
        """
        Check whether the operand is relative to stack pointer or frame pointer.
        This function is used to determine how to output a stack variable
        This function may be absent. If it is absent, then all operands
        are sp based by default.
        Define this function only if some stack references use frame pointer
        instead of stack pointer.
        returns flags:
          OP_FP_BASED   operand is FP based
          OP_SP_BASED   operand is SP based
          OP_SP_ADD     operand value is added to the pointer
          OP_SP_SUB     operand value is substracted from the pointer
        """
        ida_pro.int_pointer.frompointer(mode).assign(ida_idp.OP_FP_BASED)
        return 1

    def ev_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        return "comment for %d" % insn.itype

    def ev_create_switch_xrefs(self, jumpea, swi):
        """Create xrefs for a custom jump table
           @param jumpea: address of the jump insn
           @param swi: switch information
        """
        return 0

    def ev_calc_step_over(self, target, ip):
        ida_pro.ea_pointer.frompointer(target).assign(ida_idp.BADADDR)
        return 1

    def ev_may_be_func(self, insn, state):
        """
        can a function start here?
        the instruction is in 'insn'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        return 0

    def ev_str2reg(self, regname):
        """
        Convert a register name to a register number
          args: regname
          Returns: register number or -1 if not avail
          The register number is the register index in the reg_names array
          Most processor modules do not need to implement this callback
          It is useful only if ph.reg_names[reg] does not provide
          the correct register names
        """
        r = self.regname2index(regname)
        if r < 0:
            return 0
        else:
            return r + 1

    def ev_is_sane_insn(self, insn, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'insn'
        returns: >=0-ok, <0-no, the instruction isn't
        likely to appear in the program
        """
        return -1

    def ev_func_bounds(self, code, func_ea, max_func_end_ea):
        ida_pro.int_pointer.frompointer(code).assign(ida_funcs.FIND_FUNC_OK)
        return 1

    def ev_init(self, idp_file):
        return 0

    def ev_out_label(self, ctx, label):
        """
        The kernel is going to generate an instruction label line
        or a function header.
        args:
          ctx - output context
          label - label to output
        If returns value <0, then the kernel should not generate the label
        """
        return 0

    def ev_rename(self, ea, new_name):
        """
        The kernel is going to rename a byte
        args:
          ea -
          new_name -
        If returns value <0, then the kernel should not rename it
        """
        return 0

    def ev_may_show_sreg(self, ea):
        """
        The kernel wants to display the segment registers
        in the messages window.
        args:
          ea
        if this function returns <0
        then the kernel will not show
        the segment registers.
        (assuming that the module have done it)
        """
        return 0

    def ev_coagulate(self, start_ea):
        """
        Try to define some unexplored bytes
        This notification will be called if the
        kernel tried all possibilities and could
        not find anything more useful than to
        convert to array of bytes.
        The module can help the kernel and convert
        the bytes into something more useful.
        args:
          start_ea -
        returns: number of converted bytes
        """
        return 0

    def ev_is_call_insn(self, insn):
        """
        Is the instruction a "call"?
        args
          insn  - instruction
        returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def ev_is_ret_insn(self, insn, iri_flags):
        """
        Is the instruction a "return"?
        insn  - instruction
        iri_flags - combination of IRI_... constants
          IRI_EXTENDED       - include instructions like "leave"
                               which begins the function epilog
          IRI_RET_LITERALLY  - report only 'ret' instructions
          IRI_SKIP_RETTARGET - exclude 'ret' instructions that have special targets
        returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def ev_is_alloca_probe(self, ea):
        """
        Does the function at 'ea' behave as __alloca_probe?
        args:
          ea
        returns: 1-yes, 0-false
        """
        return 0

    def ev_gen_src_file_lnnum(self, ctx, filename, lnnum):
        """
        Callback: generate analog of
        #line "file.c" 123
        directive.
        args:
          ctx   - output context
          file  - source file (may be NULL)
          lnnum - line number
        returns: 1-directive has been generated
        """
        return 0

    def ev_is_indirect_jump(self, insn):
        """
        Callback: determine if instruction is an indrect jump
        If CF_JUMP bit cannot describe all jump types
        jumps, please define this callback.
        input: insn structure contains the current instruction
        returns: 0-use CF_JUMP, 1-no, 2-yes
        """
        return 0

    def ev_validate_flirt_func(self, ea, funcname):
        """
        flirt has recognized a library function
        this callback can be used by a plugin or proc module
        to intercept it and validate such a function
        args:
          start_ea
          funcname
        returns: -1-do not create a function,
                  0-function is validated
        """
        return 0

    def ev_set_proc_options(self, options, confidence):
        """
        called if the user specified an option string in the command line:
        -p<processor name>:<options>
        can be used for e.g. setting a processor subtype
        also called if option string is passed to set_processor_type()
        and IDC's set_processor_type()
        args:
          options
          confidence - 0: loader's suggestion,
                       1: user's decision
        returns: <0 - bad option string
        """
        return 0

    def ev_creating_segm(self, s):
        return 0

    def ev_auto_queue_empty(self, atype):
        return 0

    def ev_gen_regvar_def(self, ctx, v):
        return 0

    def ev_is_basic_block_end(self, insn, call_insn_stops_block):
        """
        Is the current instruction end of a basic block?
        This function should be defined for processors
        with delayed jump slots. The current instruction
        is stored in 'insn'
        args:
          call_insn_stops_block
          returns: 0-unknown, -1-no, 1-yes
        """
        return 0

    def ev_moving_segm(self, segment, to, flags):
        """
        May the kernel move the segment?
        returns: 0-yes, <0-the kernel should stop
        """
        return 0

    def ev_segm_moved(self, from_ea, to_ea, size, changed_netdelta):
        """
        A segment is moved
        """
        return 0

    def ev_verify_noreturn(self, pfn):
        """
        The kernel wants to set 'noreturn' flags for a function
        Returns: 0-ok, <0-do not set 'noreturn' flag
        """
        return 0

    def ev_treat_hindering_item(self, hindering_item_ea, new_item_flags, new_item_ea, new_item_length):
        """
        An item hinders creation of another item
        args:
          hindering_item_ea
          new_item_flags
          new_item_ea
          new_item_length
        Returns: 0-no reaction, <0-the kernel may delete the hindering item
        """
        return 0

    def ev_coagulate_dref(self, from_ea, to_ea, may_define, code_ea):
        """
        data reference is being analyzed
        args:
          from_ea, to_ea, may_define, code_ea
        plugin may correct code_ea (e.g. for thumb mode refs, we clear the last bit)
        Returns: new code_ea or -1 - cancel dref analysis
        """
        if False: # some condition
            ida_pro.ea_pointer.frompointer(code_ea).assign(0x1337)
        return 0

    #
    # IDB_Hooks callbacks
    #

    def savebase(self):
        """The database is being saved. Processor module should save its local data"""
        return 0

    def closebase(self):
        """
        The database will be closed now
        """
        return 0

    def idasgn_loaded(self, short_sig_name):
        """
        FLIRT signature have been loaded for normal processing
        (not for recognition of startup sequences)
        args:
          short_sig_name
        """
        return 0

    def auto_empty(self):
        """
        Info: all analysis queues are empty.
        This callback is called once when the
        initial analysis is finished. If the queue is
        not empty upon the return from this callback,
        it will be called later again
        """
        return 0

    def kernel_config_loaded(self, pass_number):
        """
        This callback is called when ida.cfg is parsed
        """
        return 0

    def auto_empty_finally(self):
        """
        Info: all analysis queues are empty definitively
        """
        return 0

    def determined_main(self, main_ea):
        """
        The main() function has been determined
        """
        return 0

    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        return 0

    def compiler_changed(self, adjust_inf_fields):
        return 0

    def make_code(self, insn):
        """
        An instruction is being created
        args:
          insn
        returns: 0-ok, <0-the kernel should stop
        """
        return 0

    def make_data(self, ea, flags, tid, size):
        """
        A data item is being created
        args:
          ea
          flags
          tid
          size
        returns: 0-ok, <0-the kernel should stop
        """
        return 0

    def notify_verify_sp(self, pfn):
        """
        All function instructions have been analyzed
        Now the processor module can analyze the stack pointer
        for the whole function
        Returns: 0-ok, <0-bad stack pointer
        """
        return 0

    def renamed(self, ea, new_name, is_local_name):
        """
        The kernel has renamed a byte
        args:
          ea
          new_name
          is_local_name
        Returns: nothing. See also the 'rename' event
        """
        return 0

    def set_func_start(self, pfn, new_ea):
        """
        Function chunk start address will be changed
        args:
          pfn
          new_ea
        Returns: 0-ok,<0-do not change
        """
        return 0

    def set_func_end(self, pfn, new_end_ea):
        """
        Function chunk end address will be changed
        args:
          pfn
          new_end_ea
        Returns: 0-ok,<0-do not change
        """
        return 0

    def func_added(self, pfn):
        """
        The kernel has added a function.
        @param pfn: function
        """
        return 0

    def deleting_func(self, pfn):
        """
        The kernel is about to delete a function
        @param func: function
        """
        return 0

    def translate(self, base, offset):
        """
        Translation function for offsets
        Currently used in the offset display functions
        to calculate the referenced address
        Returns: ea_t
        """
        return ida_idaapi.BADADDR

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from ida_idp.processor_t
def PROCESSOR_ENTRY():
    return sample_processor_t()

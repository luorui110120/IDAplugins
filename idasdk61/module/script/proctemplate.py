# ----------------------------------------------------------------------
# Processor module template script
# (c) Hex-Rays
import sys
import idaapi
from idaapi import *


# ----------------------------------------------------------------------
class sample_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    The required and optional attributes/callbacks are illustrated in this template
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['myproc']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['My processor module']

    # number of registers (optional: deduced from the len(regNames))
    regsNum = len(proc_Registers)

    # register names
    regNames = [
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

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    regFirstSreg = 16 # index of CS
    regLastSreg = 16 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    regCodeSreg = 16
    regDataSreg = 17

    # Array of typical code start sequences (optional)
    codestart = ['\x55\x8B', '\x50\x51']

    # Array of 'return' instruction opcodes (optional)
    retcodes = ['\xC3', '\xC2']

    # Array of instructions
    instruc = [
        {'name': 'INSN1', 'feature': CF_USE1},
        {'name': 'INSN2', 'feature': CF_USE1 | CF_CHG1}
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

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

    # If the FIXUP_VHIGH and FIXUP_VLOW fixup types are supported
    # then the number of bits in the HIGH part. For example,
    # SPARC will have here 22 because it has HIGH22 and LOW10 relocations.
    # See also: the description of PR_FULL_HIFXP bit
    # (optional)
    high_fixup_bits = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # array of unsupported instructions (array of cmd.itype) (optional)
        'badworks': [6, 11],

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

        #
        # translation to use in character and string constants.
        # usually 1:1, i.e. trivial translation
        # If specified, must be 256 chars long
        # (optional)
        'XlatAsciiOutput': [chr(x) for x in xrange(256)],

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

        # 3-byte data (optional)
        'a_3byte': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler


    # ----------------------------------------------------------------------
    # The following callbacks are optional.
	# *** Please remove the callbacks that you don't plan to implement ***

    def header(self):
        """function to produce start of disassembled text"""
        pass

    def footer(self):
        """function to produce end of disassembled text"""
        pass

    def segstart(self, ea):
        """function to produce start of segment"""
        pass

    def segend(self, ea):
        """function to produce end of segment"""
        pass

    def assumes(self, ea):
        """function to produce assume directives"""
        pass

    def notify_term(self):
        """called when the processor module is unloading"""
        pass

    def notify_setup_til(self):
        """Setup default type libraries (called after loading a new file into the database)
        The processor module may load tils, setup memory model and perform other actions required to set up the type system
        @return: None
        """
        pass

    def notify_newprc(self, nproc):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        return 1-ok,0-prohibit
        """
        return 1

    def notify_newfile(self, filename):
        """A new file is loaded (already)"""
        pass

    def notify_oldfile(self, filename):
        """An old file is loaded (already)"""
        pass

    def notify_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
         args:
          filename  - binary file name
          fileoff   - offset in the file
          basepara  - base loading paragraph
          binoff    - loader offset
          nbytes    - number of bytes to load
        Returns nothing
        """
        pass

    def notify_undefine(self, ea):
        """
        An item in the database (insn or data) is being deleted
        @param args: ea
        @return: >0-ok, <=0 - the kernel should stop
                 if the return value is positive:
                     bit0 - ignored
                     bit1 - do not delete srareas at the item end
        """
        return 1

    def notify_endbinary(self, ok):
        """
         After loading a binary file
         args:
          ok - file loaded successfully?
        """
        pass

    def notify_assemble(self, ea, cs, ip, use32, line):
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
        returns the opcode string
        """
        pass

    def notify_savebase(self):
        """The database is being saved. Processor module should save its local data"""
        pass

    def data_out(self, ea):
        """
        Generate text represenation of data items
        This function MAY change the database and create cross-references, etc.
        """
        pass

    def cmp_opnd(self, op1, op2):
        """
        Compare instruction operands.
        Returns 1-equal,0-not equal operands.
        """
        return False

    def can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return True

    def translate(self, base, offset):
        """
        Translation function for offsets
        Currently used in the offset display functions
        to calculate the referenced address
        Returns: ea_t
        """
        return BADADDR

    def set_idp_options(self, keyword, type, value):
        """
        Set IDP-specific option
        args:
          keyword - the option name
                    or empty string (check type when 0 below)
          type    - one of
                      IDPOPT_STR  string constant
                      IDPOPT_NUM  number
                      IDPOPT_BIT  zero/one
                      IDPOPT_FLT  float
                      IDPOPT_I64  64bit number
                      0 -> You should display a dialog to configure the processor module
          value   - the actual value
        Returns:
           IDPOPT_OK        ok
           IDPOPT_BADKEY    illegal keyword
           IDPOPT_BADTYPE   illegal type of value
           IDPOPT_BADVALUE  illegal value (bad range, for example)
        otherwise return a string containing the error messages
        """
        return idaapi.IDPOPT_OK

    def gen_map_file(self, qfile):
        """
        Generate map file. If this function is absent then the kernel will create the map file.
        This function returns number of lines in output file.
        0 - empty file, -1 - write error
        """
        r1 = qfile.write("Line 1\n")
        r2 = qfile.write("Line 2\n!")
        return 2 # two lines

    def create_func_frame(self, func_ea):
        """
        Create a function frame for a newly created function.
        Set up frame size, its attributes etc.
        """
        return False

    def is_far_jump(self, icode):
        """
        Is indirect far jump or call instruction?
        meaningful only if the processor has 'near' and 'far' reference types
        """
        return False

    def is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return 0

    def outspec(self, ea, segtype):
        """
        Generate text representation of an item in a special segment
        i.e. absolute symbols, externs, communal definitions etc.
        Returns: 1-overflow, 0-ok
        """
        return 0

    def get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        return 2

    def is_switch(self, swi):
        """
        Find 'switch' idiom.
        Fills 'si' structure with information

        @return: Boolean (True if switch was found and False otherwise)
        """
        return False

    def is_sp_based(self, op):
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
        return idaapi.OP_FP_BASED

    def notify_add_func(self, func_ea):
        """
        The kernel has added a function.
        @param func_ea: function start EA
        @return: Nothing
        """
        pass

    def notify_del_func(self, func_ea):
        """
        The kernel is about to delete a function
        @param func_ea: function start EA
        @return: 1-ok,<=0-do not delete
        """
        return 1

    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """
        return "comment for %d" % self.cmd.itype

    def notify_create_switch_xrefs(self, jumpea, swi):
        """Create xrefs for a custom jump table
           @param jumpea: address of the jump insn
           @param swi: switch information
           @return: None
        """
        pass

    def notify_calc_step_over(self, ip):
        """
        Calculate the address of the instruction which will be
        executed after "step over". The kernel will put a breakpoint there.
        If the step over is equal to step into or we can not calculate
        the address, return BADADDR.
        args:
          ip - instruction address
        returns: target or BADADDR
        """
        return idaapi.BADADDR

    def notify_may_be_func(self, state):
        """
        can a function start here?
        the instruction is in 'cmd'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        return 0

    def notify_str2reg(self, regname):
        """
        Convert a register name to a register number
          args: regname
          Returns: register number or -1 if not avail
          The register number is the register index in the regNames array
          Most processor modules do not need to implement this callback
          It is useful only if ph.regNames[reg] does not provide
          the correct register names
        """
        r = regname2index(regname)
        if r < 0:
            return -1
        else:
            return r

    def notify_is_sane_insn(self, no_crefs):
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
        The instruction is in 'cmd'
        returns: 1-ok, <=0-no, the instruction isn't
        likely to appear in the program
        """
        return 0

    def notify_func_bounds(self, code, func_ea, max_func_end_ea):
        """
        find_func_bounds() finished its work
        The module may fine tune the function bounds
        args:
          possible code - one of FIND_FUNC_XXX (check find_func_bounds)
          func_ea - func start ea
          max_func_end_ea (from the kernel's point of view)
        returns: possible_return_code
        """
        return FIND_FUNC_OK

    def asm_func_header(self, func_ea):
        """generate function header lines"""
        pass

    def asm_func_footer(self, func_ea):
         """generate function footer lines"""
        pass

    def asm_get_type_name(self, flag, ea_or_id):
        """
        Get name of type of item at ea or id.
        (i.e. one of: byte,word,dword,near,far,etc...)
        """
        if isCode(flag):
            pfn = get_func(ea_or_id)
            # return get func name
        elif isWord(flag):
            return "word"
        return ""

    def notify_init(self, idp_file):
        # init returns non-zero on success
        return 1


    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #

    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        return 1

    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        return True

    def out(self):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """

    def ana(self):
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """

        # Return decoded instruction size or zero
        return self.cmd.size

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return sample_processor_t()

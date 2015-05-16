
//---------------------------------------------------------------------
static bool preline_i51(char *argstr, s_preline *S)
{
  if ( *argstr == '#' ) {
    *S->iaflg = 1;
    ++argstr;
  }
  qstrncpy(S->offset, argstr, PRELINE_SIZE);
  return(true);
}

//---------------------------------------------------------------------
static bool idaapi chkarg_dispatch_i51(void *a1, void *a2, uchar cmd)
{
  // The order of operation mnemonics in this table must be the same
  // as the declaration order in the 'ca_operation_t' enum.
  // Missing operations must be represented by empty strings ("").
  // The array must be exactly 15 elements.
  static char const * const operdim[15] = {
     "(", ")", "!", "-", "+", "%",
     "\\", "/", "*", "&", "|", "^", "<<", ">>", NULL};

  switch ( cmd ) {
    // Request the operation mnemonic table
    // This events will happen only once.
    // We must store the address of the 'operdim' array in the memory
    // location pointed by 'a2'.
    // This function must be implemented.
    case chkarg_gettable:
      *(const char * const **)a2 = operdim;
      return(true);

    // Parse operand string to and fill the s_preline structure
    //   a1 - ptr to operand string
    //        The operand has its operations replaced by binary codes.
    //        For example, left braces are replaced by '\1'.
    //   a2 - ptr to s_preline structure. The structure has all its
    //        fields initialized (they point to allocated buffers).
    //        The buffers contain empty strings.
    // This function breaks down the input operand into the prefix,
    // register, segment, and offset parts. If it recognizes an indirected
    // addressing (ex: [var]), then it must set the iaflg flag.
    //
    // Returns: success (0-failure, 1-ok)
    // The function may modify the input operand (though it is not obliged to do so).
    // If the assembler has several equivalent representations of the same
    // register expression (ex: eax*4 and 4*eax), then such an expression
    // must be normalized. Normalization is transformation of a token into
    // a preselect form. For example, you may decide that all register
    // expressions must have the coefficient part before the name part.
    // Example: if the input operand looks like 'label[eax+edx*8+2]',
    // then we must fill the output buffers like this:
    //   iaflg  - 0
    //   reg    - "eax+8*edx"
    //   offset - "label+2"

    case chkarg_preline:
      return(preline_i51((char*)a1, (s_preline *)a2));

/*
    // Scan the operand for special prefixes like SEG, OFFSET, SIZE, etc.
    //    a1 - ptr to ptr to operand
    //         the function may modify the ptr or the operand itself
    //    a2 - ptr to result code. The result code is a byte (char)
    //         and it may be one of CA_PRF_... constants.
    //         Initialliy the result code is CF_PRF_NONE.
    // If we find a special prefix, we have to remove it from the
    // operand (by moving the pointer or modifying the operand).
    // We must also remove all whitespace after the removed keyword.
    // Returns: success (0-failure, 1-ok)
    case chkarg_atomprefix:
      return((*(char **)a1 = atomprefix_x86(*(char**)a1, (char*)a2)) != NULL);
*/

/*
    // Get the default segment for the specified operand
    //    a1 - ptr to output buffer
    //         We must put the default segment as a string
    //         into the output buffer
    //    a2 - the operand number (0..n). The operand itself
    //         is stored in the 'cmd' structure along with
    //         all other information about the current insruction.
    // Returns: success (0-failure, 1-ok)
    // Example: if the current instruction is
    //             lods[esi]
    //          and operand number is 0,
    //          then we must put "ds:" into the output buffer and return 'true'
    // If the specified operand does not refer to memory, return 'false'
    case chkarg_operseg:
      return(get_operseg_x86((char*)a1, (int)(size_t)a2));
*/

/*
    // Check if the selectors are interchangeable
    //     a1 - first selector (sel_t)
    //     a2 - second selector (sel_t)
    // Returns: 0-selectors are different, 1-selectors are interchangeable
    // This callback will be called only if the selector values are different.
    // (the kernel will handle the case of 2 equal selectors automatically)
    // The callback must be implemented for the processors with overlayed
    // memory segments. In this case we can have 2 different selectors pointing
    // to the same memory addresses.
    case chkarg_cmpseg:
      return(cmpseg_pdp11((sel_t)a1, (sel_t)a2));
*/

    default:  // chkarg_atomprefix, chkarg_operseg, chkarg_cmpseg
      break;
  }
  return(false);
}

//---------------------------------------------------------------------

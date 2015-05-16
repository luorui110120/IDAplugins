/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"


//----------------------------------------------------------------------

static void dir_reg( op_t &op, int dbl_reg = 0, int indir = 0 )
{
  uint tmp = ua_next_byte();

  if( dbl_reg )
  {
    op.reg  = 16;       // RRx
    op.dtyp = dt_word;
  }
  else
    op.reg = 0;         // Rx

  if( (tmp & 0xF0 ) == 0xE0 )   // Ex - special reg bank
  {
    op.reg += tmp & 0xF;
    op.type = indir ? o_ind_reg : o_reg;
  }
  else
  {
    op.addr = tmp;
    op.type = indir ? o_ind_mem : o_mem;
  }
}

//----------------------------------------------------------------------

int idaapi ana( void )
{
  cmd.Op1.dtyp = dt_byte;
  cmd.Op2.dtyp = dt_byte;

  uint16 code = ua_next_byte();

  uint16 nibble0 = (code & 0xF);
  uint16 nibble1 = (code >> 4);

  char offc;
  uint16 tmp;

  if( nibble0 == 0xF )      // xF
  {
    static const char cmdxF[] =
    {
      Z8_null, Z8_null, Z8_null, Z8_null,
      Z8_null, Z8_null, Z8_stop, Z8_halt,
      Z8_di,   Z8_ei,   Z8_ret,  Z8_iret,
      Z8_rcf,  Z8_scf,  Z8_ccf,  Z8_nop
    };

    cmd.itype = cmdxF[nibble1];
  }
  else if( nibble0 >= 8 )   // x8..xE
  {
    static const char cmdx8E[] =
    {
      Z8_ld, Z8_ld, Z8_djnz, Z8_jrcond, Z8_ld, Z8_jpcond, Z8_inc
    };

    cmd.itype = cmdx8E[nibble0-8];

    if( nibble0 == 8 || nibble0 == 0xA || nibble0 == 0xC || nibble0 == 0xE )
    {
      cmd.Op1.type = o_reg;
      cmd.Op1.reg  = nibble1 + rR0;
    }

    if( nibble0 == 0xB || nibble0 == 0xD )
    {
      cmd.Op1.type   = o_phrase;
      cmd.Op1.phrase = nibble1;
    }

    switch( nibble0 )
    {
      case 0x8:     // ld r1,R2
        dir_reg( cmd.Op2 );
        break;

      case 0x9:     // ld r2,R1
        dir_reg( cmd.Op1 );
        cmd.Op2.reg  = nibble1 + rR0;
        cmd.Op2.type = o_reg;
        break;

      case 0xA:     // djnz r1,RA
      case 0xB:     // jr cc,RA
        offc = ua_next_byte();
        cmd.Op2.addr = ushort(cmd.ip + cmd.size + offc);  // signed addition
        cmd.Op2.dtyp = dt_word;
        cmd.Op2.type = o_near;
        break;

      case 0xC:     // ld r1,#im
        cmd.Op2.value = ua_next_byte();
        cmd.Op2.type  = o_imm;
        break;

      case 0xD:     // jp cc,DA
        cmd.Op2.addr = ua_next_word();
        cmd.Op2.dtyp = dt_word;
        cmd.Op2.type = o_near;
    }

    if( (nibble0 == 0xB || nibble0 == 0xD) &&
        (nibble1 == 0   || nibble1 == 8) )
      switch( nibble1 )
      {
        case 0:                     // never true - seems as 2-byte NOP
          cmd.Op1.type = o_void;
          cmd.itype    = Z8_nop;
          cmd.Op2.type = o_void;
          break;

        case 8:
          cmd.Op1 = cmd.Op2;
//ig: при копировании операндов надо исправить их номера
//    именно поэтому у тебя оффсет то появлялся, то пропадал
//    я сейчас добавлю это в ядро, чтобы даже если модуль портит
//    эти номера, то после вызова анализатора ядро их восстановит
//        cmd.Op1.n = 0;
//        cmd.Op2.n = 1;
          cmd.itype--;              // Z8_jpcond -> Z8_jp, Z8_jrcond -> Z8_jr
          cmd.Op2.type = o_void;
      }
  }
  else if( nibble0 >= 2 )   // x2..x7
  {
    static const char cmdx2[] =
    {
      Z8_add,  Z8_adc,  Z8_sub, Z8_sbc,
      Z8_or,   Z8_and,  Z8_tcm, Z8_tm,
      Z8_null, Z8_null, Z8_cp,  Z8_xor,
      Z8_null, Z8_null, Z8_ld,  Z8_null
    };

    switch( code )
    {
      case 0xD6:
      case 0xD4:
        cmd.itype    = Z8_call;
        cmd.Op1.dtyp = dt_word;

        if( code == 0xD6 )
        {
          cmd.Op1.addr = ua_next_word();
          cmd.Op1.type = o_near;
        }
        else  // D4 - call @RR
          dir_reg( cmd.Op1, 1, 1 );
        break;

      case 0xC7:
        tmp = ua_next_byte();
        cmd.Op1.reg   = (tmp >> 4) + rR0;
        cmd.Op1.type  = o_reg;
        cmd.Op2.reg   = tmp & 0xF;
        cmd.Op2.type  = o_displ;
        cmd.Op2.addr  = ua_next_byte();
        cmd.itype     = Z8_ld;
        break;

      case 0xD7:
        tmp = ua_next_byte();
        cmd.Op2.reg   = (tmp >> 4) + rR0;
        cmd.Op2.type  = o_reg;
        cmd.Op1.reg   = tmp & 0xF;
        cmd.Op1.type  = o_displ;
        cmd.Op1.addr  = ua_next_byte();
        cmd.itype     = Z8_ld;
        break;

      case 0x82: case 0x83: case 0x92: case 0x93:
        tmp = ua_next_byte();
        cmd.itype = (nibble0 == 2) ? Z8_lde : Z8_ldei;
        if( nibble1 == 8 )
        {
          cmd.Op1.reg  = (tmp >> 4)  + rR0;
          cmd.Op2.reg  = (tmp & 0xF) + rRR0;
          cmd.Op1.type = (nibble0 == 2) ? o_reg : o_ind_reg;
          cmd.Op2.type = o_ind_reg;
        }
        else
        {
          cmd.Op1.reg  = (tmp & 0xF) + rRR0;
          cmd.Op2.reg  = (tmp >> 4) + rR0;
          cmd.Op1.type = o_ind_reg;
          cmd.Op2.type = (nibble0 == 2) ? o_reg : o_ind_reg;
        }
        break;

      case 0xC2: case 0xC3: case 0xD2: case 0xD3:
        tmp = ua_next_byte();
        cmd.itype = (nibble0 == 2) ? Z8_ldc : Z8_ldci;
        if( nibble1 == 0xC )
        {
          cmd.Op1.reg  = (tmp >> 4)  + rR0;
          cmd.Op2.reg  = (tmp & 0xF) + rRR0;
          cmd.Op1.type = (nibble0 == 2) ? o_reg : o_ind_reg;
          cmd.Op2.type = o_ind_reg;
        }
        else
        {
          cmd.Op1.reg  = (tmp & 0xF) + rRR0;
          cmd.Op2.reg  = (tmp >> 4)  + rR0;
          cmd.Op1.type = o_ind_reg;
          cmd.Op2.type = (nibble0 == 2) ? o_reg : o_ind_reg;
        }
        break;

      default:
        cmd.itype = cmdx2[nibble1];

        switch( nibble0 )
        {
          case 2:     // r1,r2
          case 3:     // r1,Ir2
            tmp = ua_next_byte();
            cmd.Op2.reg  = (tmp & 0xF) + rR0;
            cmd.Op2.type = (nibble0 == 2) ? o_reg : o_ind_reg;
            cmd.Op1.reg  = (tmp >> 4) + rR0;
            cmd.Op1.type = o_reg;
            break;

          case 4:     // R2,R1
          case 5:     // IR2,R1
            dir_reg( cmd.Op2, 0, nibble0 == 5 );
            dir_reg( cmd.Op1 );
            break;

          case 6:     // R1,IM
          case 7:     // IR1,IM
            dir_reg( cmd.Op1, 0, nibble0 == 7 );
            cmd.Op2.value = ua_next_byte();
            cmd.Op2.type  = o_imm;
        }

        switch( nibble1 )
        {
          case 0xF:   // ld
            switch( nibble0 )
            {
              case 3: // ld Ir1,r2
                cmd.Op2.type = o_reg;
                cmd.Op1.type = o_ind_reg;
                cmd.itype    = Z8_ld;
                break;

              case 5: // ld R2,IR1
                {
                  op_t tmp_op = cmd.Op1;
                  cmd.Op1     = cmd.Op2;
                  cmd.Op2     = tmp_op;
                  cmd.itype   = Z8_ld;
                }
            }
            break;

          case 0xE:   // ld
            if( nibble0 != 2 )  cmd.itype = Z8_ld;
        }
    }
  }
  else                      // x0..x1
  {                                                    /*Z8_srp*/
    static const char cmdx01[] =
    {
      Z8_dec,  Z8_rlc, Z8_inc,  Z8_jp,
      Z8_da,   Z8_pop, Z8_com,  Z8_push,
      Z8_decw, Z8_rl,  Z8_incw, Z8_clr,
      Z8_rrc,  Z8_sra, Z8_rr,   Z8_swap
    };

    cmd.itype = cmdx01[nibble1];
    switch( code )
    {
      case 0x30:    // jp @intmem
        dir_reg( cmd.Op1, 1, 1 );
        break;

      case 0x31:    // srp #xx
        cmd.itype     = Z8_srp;
        cmd.Op1.type  = o_imm;
        cmd.Op1.value = ua_next_byte();
        cmd.Op1.flags |= OF_NUMBER;
        break;

      default:
        dir_reg( cmd.Op1, (code == 0x80) || (code == 0xA0), nibble0 );
    }
  }

  if( cmd.itype == Z8_null )  return 0;   // unknown command
  return cmd.size;
}

/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _QUEUE_HPP
#define _QUEUE_HPP
#pragma pack(push, 1)   // IDA uses 1 byte alignments!

//
//      This file contains functions that deal with the list of problems.
//      There are several problem lists.
//      An address may be inserted to any list.
//      The kernel simply maintains these lists, no additional processing
//      is done. The problem lists are accessible for the user
//      from the View->Subviews->Problems menu item.
//      Addresses in the lists are kept sorted.

//      The following problem lists exist:

typedef uchar qtype_t;
const qtype_t
  Q_noBase  =  1,  // Can't find offset base
  Q_noName  =  2,  // Can't find name
  Q_noFop   =  3,  // Can't find forced op
  Q_noComm  =  4,  // Can't find comment           !!!! not used anymore !!!
  Q_noRef   =  5,  // Can't find references
  Q_jumps   =  6,  // Jump by table                !!!! ignored
  Q_disasm  =  7,  // Can't disasm
  Q_head    =  8,  // Already head
  Q_noValid =  9,  // Exec flows beyond limits
  Q_lines   = 10,  // Too many lines
  Q_badstack= 11,  // Failed to trace the value of the stack pointer
  Q_att     = 12,  // Attention! Probably erroneous situation.
  Q_final   = 13,  // Decision to convert to instruction/data is made by IDA
  Q_rolled  = 14,  // The decision made by IDA was wrong and rolled back
  Q_collsn  = 15,  // FLAIR collision: the function with the given name already exists
  Q_Qnum    = 16;  // Number of qtypes


// Insert an address to a list of problems.
// Display a message saying about the problem (except of Q_att,Q_final)
// Q_jumps is temporarily ignored.
//      ea   - linear address
//      type - problem queue type

idaman void ida_export QueueMark(qtype_t type,ea_t ea);


// Get an address from any problem list.
// The address is not removed from the list. The kernel returns an address
// from a list with the smallest type value.
//      type - problem queue type the address is got from
// returns: linear address or BADADDR

idaman ea_t ida_export QueueGet(qtype_t *type);


// Get an address from the specified problem list
// The address is not removed from the list.
//      type  - problem queue type
//      lowea - the returned address will be higher or equal
//              than the specified address
// returns: linear address or BADADDR

idaman ea_t ida_export QueueGetType(qtype_t type,ea_t lowea);


// Remove an address from a problem list
//      ea   - linear address
//      type - problem queue type

idaman void ida_export QueueDel(qtype_t type,ea_t ea);


// Remove an address from all problem lists
//      ea   - linear address

void QueueDel(ea_t ea);


// Get queue problem description string

idaman const char *ida_export get_long_queue_name(qtype_t type);
idaman const char *ida_export get_short_queue_name(qtype_t type);


// Check if the specified address is present in the queue

idaman bool ida_export QueueIsPresent(qtype_t t, ea_t ea);


// The kernel only functions:

       void init_queue(void);
inline void save_queue(void) {}
       void term_queue(void);

void move_problems(ea_t from, ea_t to, asize_t size);
void queue_del(ea_t ea1, ea_t ea2);

void mark_ida_decision(ea_t ea);
void unmark_ida_decision(ea_t ea);
inline bool was_ida_decision(ea_t ea) { return QueueIsPresent(Q_final, ea); }

void mark_rollback(ea_t ea, int rollback_type);
int get_rollback_type(ea_t ea);
// rollback types are combination of:
#define ROLLBACK_CODE  0x01
#define ROLLBACK_DATA  0x02
#define ROLLBACK_ALIGN 0x04

#pragma pack(pop)
#endif  //  _QUEUE_HPP

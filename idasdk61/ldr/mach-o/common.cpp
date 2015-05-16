#include "common.h"
#include <area.hpp>
#include <kernwin.hpp>

//lint -esym(843, mf) could be declared const
static bool mf;  // need to swap endianness

//--------------------------------------------------------------------------
local void swap_mach_header(struct mach_header *mh)
{
  mh->magic      = swap32(mh->magic);
  mh->cputype    = swap32(mh->cputype);
  mh->cpusubtype = swap32(mh->cpusubtype);
  mh->filetype   = swap32(mh->filetype);
  mh->ncmds      = swap32(mh->ncmds);
  mh->sizeofcmds = swap32(mh->sizeofcmds);
  mh->flags      = swap32(mh->flags);
}

local void swap_mach_header_64(struct mach_header_64 *mh)
{
  mh->magic      = swap32(mh->magic);
  mh->cputype    = swap32(mh->cputype);
  mh->cpusubtype = swap32(mh->cpusubtype);
  mh->filetype   = swap32(mh->filetype);
  mh->ncmds      = swap32(mh->ncmds);
  mh->sizeofcmds = swap32(mh->sizeofcmds);
  mh->flags      = swap32(mh->flags);
  mh->reserved   = swap32(mh->reserved);
}

//--------------------------------------------------------------------------
local void swap_load_command(load_command *lc)
{
        lc->cmd = swap32(lc->cmd);
        lc->cmdsize = swap32(lc->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_segment_command(segment_command *sg)
{
        /* segname[16] */
        sg->cmd = swap32(sg->cmd);
        sg->cmdsize = swap32(sg->cmdsize);
        sg->vmaddr = swap32(sg->vmaddr);
        sg->vmsize = swap32(sg->vmsize);
        sg->fileoff = swap32(sg->fileoff);
        sg->filesize = swap32(sg->filesize);
        sg->maxprot = swap32(sg->maxprot);
        sg->initprot = swap32(sg->initprot);
        sg->nsects = swap32(sg->nsects);
        sg->flags = swap32(sg->flags);
}

local void swap_segment_command_64(segment_command_64 *sg)
{
        /* segname[16] */
        sg->cmd = swap32(sg->cmd);
        sg->cmdsize = swap32(sg->cmdsize);
        sg->vmaddr = swap64(sg->vmaddr);
        sg->vmsize = swap64(sg->vmsize);
        sg->fileoff = swap64(sg->fileoff);
        sg->filesize = swap64(sg->filesize);
        sg->maxprot = swap32(sg->maxprot);
        sg->initprot = swap32(sg->initprot);
        sg->nsects = swap32(sg->nsects);
        sg->flags = swap32(sg->flags);
}

//--------------------------------------------------------------------------
local void swap_section(section *s, uint32 nsects)
{
        for(uint32 i = 0; i < nsects; i++){
            /* sectname[16] */
            /* segname[16] */
            s[i].addr = swap32(s[i].addr);
            s[i].size = swap32(s[i].size);
            s[i].offset = swap32(s[i].offset);
            s[i].align = swap32(s[i].align);
            s[i].reloff = swap32(s[i].reloff);
            s[i].nreloc = swap32(s[i].nreloc);
            s[i].flags = swap32(s[i].flags);
            s[i].reserved1 = swap32(s[i].reserved1);
            s[i].reserved2 = swap32(s[i].reserved2);
        }
}

//--------------------------------------------------------------------------
local void swap_section_64(section_64 *s, uint32 nsects)
{
        for(uint32 i = 0; i < nsects; i++){
            /* sectname[16] */
            /* segname[16] */
            s[i].addr = swap64(s[i].addr);
            s[i].size = swap64(s[i].size);
            s[i].offset = swap32(s[i].offset);
            s[i].align = swap32(s[i].align);
            s[i].reloff = swap32(s[i].reloff);
            s[i].nreloc = swap32(s[i].nreloc);
            s[i].flags = swap32(s[i].flags);
            s[i].reserved1 = swap32(s[i].reserved1);
            s[i].reserved2 = swap32(s[i].reserved2);
        }
}

//--------------------------------------------------------------------------
local void swap_symtab_command(symtab_command *st)
{
        st->cmd = swap32(st->cmd);
        st->cmdsize = swap32(st->cmdsize);
        st->symoff = swap32(st->symoff);
        st->nsyms = swap32(st->nsyms);
        st->stroff = swap32(st->stroff);
        st->strsize = swap32(st->strsize);
}

//--------------------------------------------------------------------------
local void swap_dysymtab_command(dysymtab_command *dyst)
{
        dyst->cmd = swap32(dyst->cmd);
        dyst->cmdsize = swap32(dyst->cmdsize);
        dyst->ilocalsym = swap32(dyst->ilocalsym);
        dyst->nlocalsym = swap32(dyst->nlocalsym);
        dyst->iextdefsym = swap32(dyst->iextdefsym);
        dyst->nextdefsym = swap32(dyst->nextdefsym);
        dyst->iundefsym = swap32(dyst->iundefsym);
        dyst->nundefsym = swap32(dyst->nundefsym);
        dyst->tocoff = swap32(dyst->tocoff);
        dyst->ntoc = swap32(dyst->ntoc);
        dyst->modtaboff = swap32(dyst->modtaboff);
        dyst->nmodtab = swap32(dyst->nmodtab);
        dyst->extrefsymoff = swap32(dyst->extrefsymoff);
        dyst->nextrefsyms = swap32(dyst->nextrefsyms);
        dyst->indirectsymoff = swap32(dyst->indirectsymoff);
        dyst->nindirectsyms = swap32(dyst->nindirectsyms);
        dyst->extreloff = swap32(dyst->extreloff);
        dyst->nextrel = swap32(dyst->nextrel);
        dyst->locreloff = swap32(dyst->locreloff);
        dyst->nlocrel = swap32(dyst->nlocrel);
}

//--------------------------------------------------------------------------
local void swap_symseg_command(symseg_command *ss)
{
        ss->cmd = swap32(ss->cmd);
        ss->cmdsize = swap32(ss->cmdsize);
        ss->offset = swap32(ss->offset);
        ss->size = swap32(ss->size);
}

//--------------------------------------------------------------------------
local void swap_fvmlib_command(fvmlib_command *fl)
{
        fl->cmd = swap32(fl->cmd);
        fl->cmdsize = swap32(fl->cmdsize);
        fl->fvmlib.name.offset = swap32(fl->fvmlib.name.offset);
        fl->fvmlib.minor_version = swap32(fl->fvmlib.minor_version);
        fl->fvmlib.header_addr = swap32(fl->fvmlib.header_addr);
}

//--------------------------------------------------------------------------
local void swap_thread_command(thread_command *tc)
{
        tc->cmd = swap32(tc->cmd);
        tc->cmdsize = swap32(tc->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_dylib_command(dylib_command *dl)
{
        dl->cmd = swap32(dl->cmd);
        dl->cmdsize = swap32(dl->cmdsize);
        dl->dylib.name.offset = swap32(dl->dylib.name.offset);
        dl->dylib.timestamp = swap32(dl->dylib.timestamp);
        dl->dylib.current_version = swap32(dl->dylib.current_version);
        dl->dylib.compatibility_version =
                                swap32(dl->dylib.compatibility_version);
}

//--------------------------------------------------------------------------
local void swap_sub_framework_command(sub_framework_command *sub)
{
        sub->cmd = swap32(sub->cmd);
        sub->cmdsize = swap32(sub->cmdsize);
        sub->umbrella.offset = swap32(sub->umbrella.offset);
}

//--------------------------------------------------------------------------
local void swap_sub_umbrella_command(sub_umbrella_command *usub)
{
        usub->cmd = swap32(usub->cmd);
        usub->cmdsize = swap32(usub->cmdsize);
        usub->sub_umbrella.offset = swap32(usub->sub_umbrella.offset);
}

//--------------------------------------------------------------------------
local void swap_sub_library_command(struct sub_library_command *lsub)
{
  lsub->cmd = SWAP_LONG(lsub->cmd);
  lsub->cmdsize = SWAP_LONG(lsub->cmdsize);
  lsub->sub_library.offset = SWAP_LONG(lsub->sub_library.offset);
}

//--------------------------------------------------------------------------
local void swap_sub_client_command(sub_client_command *csub)
{
        csub->cmd = swap32(csub->cmd);
        csub->cmdsize = swap32(csub->cmdsize);
        csub->client.offset = swap32(csub->client.offset);
}

//--------------------------------------------------------------------------
local void swap_prebound_dylib_command(prebound_dylib_command *pbdylib)
{
        pbdylib->cmd = swap32(pbdylib->cmd);
        pbdylib->cmdsize = swap32(pbdylib->cmdsize);
        pbdylib->name.offset = swap32(pbdylib->name.offset);
        pbdylib->nmodules = swap32(pbdylib->nmodules);
        pbdylib->linked_modules.offset =
                swap32(pbdylib->linked_modules.offset);
}

//--------------------------------------------------------------------------
local void swap_dylinker_command(dylinker_command *dyld)
{
        dyld->cmd = swap32(dyld->cmd);
        dyld->cmdsize = swap32(dyld->cmdsize);
        dyld->name.offset = swap32(dyld->name.offset);
}

//--------------------------------------------------------------------------
local void swap_fvmfile_command(fvmfile_command *ff)
{
        ff->cmd = swap32(ff->cmd);
        ff->cmdsize = swap32(ff->cmdsize);
        ff->name.offset = swap32(ff->name.offset);
        ff->header_addr = swap32(ff->header_addr);
}

//--------------------------------------------------------------------------
/*
#ifndef EFD_COMPILE
local void swap_thread_command(thread_command *ut)
{
        ut->cmd = swap32(ut->cmd);
        ut->cmdsize = swap32(ut->cmdsize);
}
#endif // EFD_COMPILE
*/

//--------------------------------------------------------------------------
/*
local void swap_m68k_thread_state_regs(struct m68k_thread_state_regs *cpu)
{
    uint32 i;
        for(i = 0; i < 8; i++)
            cpu->dreg[i] = SWAP_LONG(cpu->dreg[i]);
        for(i = 0; i < 8; i++)
            cpu->areg[i] = SWAP_LONG(cpu->areg[i]);
        cpu->pad0 = SWAP_SHORT(cpu->pad0);
        cpu->sr = SWAP_SHORT(cpu->sr);
        cpu->pc = SWAP_LONG(cpu->pc);
}

//--------------------------------------------------------------------------
local void swap_m68k_thread_state_68882(struct m68k_thread_state_68882 *fpu)
{
    uint32 i, tmp;

        for(i = 0; i < 8; i++){
                           tmp = SWAP_LONG(fpu->regs[i].fp[0]);
            fpu->regs[i].fp[1] = SWAP_LONG(fpu->regs[i].fp[1]);
            fpu->regs[i].fp[0] = SWAP_LONG(fpu->regs[i].fp[2]);
            fpu->regs[i].fp[2] = tmp;
        }
        fpu->cr = SWAP_LONG(fpu->cr);
        fpu->sr = SWAP_LONG(fpu->sr);
        fpu->iar = SWAP_LONG(fpu->iar);
        fpu->state = SWAP_LONG(fpu->state);
}

//--------------------------------------------------------------------------
local void swap_m68k_thread_state_user_reg(struct m68k_thread_state_user_reg *user_reg)
{
        user_reg->user_reg = SWAP_LONG(user_reg->user_reg);
}

//--------------------------------------------------------------------------
local void swap_m88k_thread_state_grf_t(m88k_thread_state_grf_t *cpu)
{
        cpu->r1 = SWAP_LONG(cpu->r1);
        cpu->r2 = SWAP_LONG(cpu->r2);
        cpu->r3 = SWAP_LONG(cpu->r3);
        cpu->r4 = SWAP_LONG(cpu->r4);
        cpu->r5 = SWAP_LONG(cpu->r5);
        cpu->r6 = SWAP_LONG(cpu->r6);
        cpu->r7 = SWAP_LONG(cpu->r7);
        cpu->r8 = SWAP_LONG(cpu->r8);
        cpu->r9 = SWAP_LONG(cpu->r9);
        cpu->r10 = SWAP_LONG(cpu->r10);
        cpu->r11 = SWAP_LONG(cpu->r11);
        cpu->r12 = SWAP_LONG(cpu->r12);
        cpu->r13 = SWAP_LONG(cpu->r13);
        cpu->r14 = SWAP_LONG(cpu->r14);
        cpu->r15 = SWAP_LONG(cpu->r15);
        cpu->r16 = SWAP_LONG(cpu->r16);
        cpu->r17 = SWAP_LONG(cpu->r17);
        cpu->r18 = SWAP_LONG(cpu->r18);
        cpu->r19 = SWAP_LONG(cpu->r19);
        cpu->r20 = SWAP_LONG(cpu->r20);
        cpu->r21 = SWAP_LONG(cpu->r21);
        cpu->r22 = SWAP_LONG(cpu->r22);
        cpu->r23 = SWAP_LONG(cpu->r23);
        cpu->r24 = SWAP_LONG(cpu->r24);
        cpu->r25 = SWAP_LONG(cpu->r25);
        cpu->r26 = SWAP_LONG(cpu->r26);
        cpu->r27 = SWAP_LONG(cpu->r27);
        cpu->r28 = SWAP_LONG(cpu->r28);
        cpu->r29 = SWAP_LONG(cpu->r29);
        cpu->r30 = SWAP_LONG(cpu->r30);
        cpu->r31 = SWAP_LONG(cpu->r31);
        cpu->xip = SWAP_LONG(cpu->xip);
        cpu->xip_in_bd = SWAP_LONG(cpu->xip_in_bd);
        cpu->nip = SWAP_LONG(cpu->nip);
}

//--------------------------------------------------------------------------
local void swap_m88k_thread_state_xrf_t(m88k_thread_state_xrf_t *fpu)
{
    struct swapped_m88k_fpsr {
        union {
            struct {
                unsigned        afinx:BIT_WIDTH(0);
                unsigned        afovf:BIT_WIDTH(1);
                unsigned        afunf:BIT_WIDTH(2);
                unsigned        afdvz:BIT_WIDTH(3);
                unsigned        afinv:BIT_WIDTH(4);
                unsigned        :BITS_WIDTH(15,5);
                unsigned        xmod:BIT_WIDTH(16);
                unsigned        :BITS_WIDTH(31,17);
            } fields;
            uint32 word;
        } u;
    } ssr;
    struct swapped_m88k_fpcr {
        union {
            struct {
                unsigned        efinx:BIT_WIDTH(0);
                unsigned        efovf:BIT_WIDTH(1);
                unsigned        efunf:BIT_WIDTH(2);
                unsigned        efdvz:BIT_WIDTH(3);
                unsigned        efinv:BIT_WIDTH(4);
                unsigned        :BITS_WIDTH(13,5);
                m88k_fpcr_rm_t  rm:BITS_WIDTH(15,14);
                unsigned        :BITS_WIDTH(31,16);
            } fields;
            uint32 word;
        } u;
    } scr;

        fpu->x1.x[0] = SWAP_LONG(fpu->x1.x[0]);
        fpu->x1.x[1] = SWAP_LONG(fpu->x1.x[1]);
        fpu->x1.x[2] = SWAP_LONG(fpu->x1.x[2]);
        fpu->x1.x[3] = SWAP_LONG(fpu->x1.x[3]);
        fpu->x2.x[0] = SWAP_LONG(fpu->x2.x[0]);
        fpu->x2.x[1] = SWAP_LONG(fpu->x2.x[1]);
        fpu->x2.x[2] = SWAP_LONG(fpu->x2.x[2]);
        fpu->x2.x[3] = SWAP_LONG(fpu->x2.x[3]);
        fpu->x3.x[0] = SWAP_LONG(fpu->x3.x[0]);
        fpu->x3.x[1] = SWAP_LONG(fpu->x3.x[1]);
        fpu->x3.x[2] = SWAP_LONG(fpu->x3.x[2]);
        fpu->x3.x[3] = SWAP_LONG(fpu->x3.x[3]);
        fpu->x4.x[0] = SWAP_LONG(fpu->x4.x[0]);
        fpu->x4.x[1] = SWAP_LONG(fpu->x4.x[1]);
        fpu->x4.x[2] = SWAP_LONG(fpu->x4.x[2]);
        fpu->x4.x[3] = SWAP_LONG(fpu->x4.x[3]);
        fpu->x5.x[0] = SWAP_LONG(fpu->x5.x[0]);
        fpu->x5.x[1] = SWAP_LONG(fpu->x5.x[1]);
        fpu->x5.x[2] = SWAP_LONG(fpu->x5.x[2]);
        fpu->x5.x[3] = SWAP_LONG(fpu->x5.x[3]);
        fpu->x6.x[0] = SWAP_LONG(fpu->x6.x[0]);
        fpu->x6.x[1] = SWAP_LONG(fpu->x6.x[1]);
        fpu->x6.x[2] = SWAP_LONG(fpu->x6.x[2]);
        fpu->x6.x[3] = SWAP_LONG(fpu->x6.x[3]);
        fpu->x7.x[0] = SWAP_LONG(fpu->x7.x[0]);
        fpu->x7.x[1] = SWAP_LONG(fpu->x7.x[1]);
        fpu->x7.x[2] = SWAP_LONG(fpu->x7.x[2]);
        fpu->x7.x[3] = SWAP_LONG(fpu->x7.x[3]);
        fpu->x8.x[0] = SWAP_LONG(fpu->x8.x[0]);
        fpu->x8.x[1] = SWAP_LONG(fpu->x8.x[1]);
        fpu->x8.x[2] = SWAP_LONG(fpu->x8.x[2]);
        fpu->x8.x[3] = SWAP_LONG(fpu->x8.x[3]);
        fpu->x9.x[0] = SWAP_LONG(fpu->x9.x[0]);
        fpu->x9.x[1] = SWAP_LONG(fpu->x9.x[1]);
        fpu->x9.x[2] = SWAP_LONG(fpu->x9.x[2]);
        fpu->x9.x[3] = SWAP_LONG(fpu->x9.x[3]);
        fpu->x10.x[0] = SWAP_LONG(fpu->x10.x[0]);
        fpu->x10.x[1] = SWAP_LONG(fpu->x10.x[1]);
        fpu->x10.x[2] = SWAP_LONG(fpu->x10.x[2]);
        fpu->x10.x[3] = SWAP_LONG(fpu->x10.x[3]);
        fpu->x11.x[0] = SWAP_LONG(fpu->x11.x[0]);
        fpu->x11.x[1] = SWAP_LONG(fpu->x11.x[1]);
        fpu->x11.x[2] = SWAP_LONG(fpu->x11.x[2]);
        fpu->x11.x[3] = SWAP_LONG(fpu->x11.x[3]);
        fpu->x12.x[0] = SWAP_LONG(fpu->x12.x[0]);
        fpu->x12.x[1] = SWAP_LONG(fpu->x12.x[1]);
        fpu->x12.x[2] = SWAP_LONG(fpu->x12.x[2]);
        fpu->x12.x[3] = SWAP_LONG(fpu->x12.x[3]);
        fpu->x13.x[0] = SWAP_LONG(fpu->x13.x[0]);
        fpu->x13.x[1] = SWAP_LONG(fpu->x13.x[1]);
        fpu->x13.x[2] = SWAP_LONG(fpu->x13.x[2]);
        fpu->x13.x[3] = SWAP_LONG(fpu->x13.x[3]);
        fpu->x14.x[0] = SWAP_LONG(fpu->x14.x[0]);
        fpu->x14.x[1] = SWAP_LONG(fpu->x14.x[1]);
        fpu->x14.x[2] = SWAP_LONG(fpu->x14.x[2]);
        fpu->x14.x[3] = SWAP_LONG(fpu->x14.x[3]);
        fpu->x15.x[0] = SWAP_LONG(fpu->x15.x[0]);
        fpu->x15.x[1] = SWAP_LONG(fpu->x15.x[1]);
        fpu->x15.x[2] = SWAP_LONG(fpu->x15.x[2]);
        fpu->x15.x[3] = SWAP_LONG(fpu->x15.x[3]);
        fpu->x16.x[0] = SWAP_LONG(fpu->x16.x[0]);
        fpu->x16.x[1] = SWAP_LONG(fpu->x16.x[1]);
        fpu->x16.x[2] = SWAP_LONG(fpu->x16.x[2]);
        fpu->x16.x[3] = SWAP_LONG(fpu->x16.x[3]);
        fpu->x17.x[0] = SWAP_LONG(fpu->x17.x[0]);
        fpu->x17.x[1] = SWAP_LONG(fpu->x17.x[1]);
        fpu->x17.x[2] = SWAP_LONG(fpu->x17.x[2]);
        fpu->x17.x[3] = SWAP_LONG(fpu->x17.x[3]);
        fpu->x18.x[0] = SWAP_LONG(fpu->x18.x[0]);
        fpu->x18.x[1] = SWAP_LONG(fpu->x18.x[1]);
        fpu->x18.x[2] = SWAP_LONG(fpu->x18.x[2]);
        fpu->x18.x[3] = SWAP_LONG(fpu->x18.x[3]);
        fpu->x19.x[0] = SWAP_LONG(fpu->x19.x[0]);
        fpu->x19.x[1] = SWAP_LONG(fpu->x19.x[1]);
        fpu->x19.x[2] = SWAP_LONG(fpu->x19.x[2]);
        fpu->x19.x[3] = SWAP_LONG(fpu->x19.x[3]);
        fpu->x20.x[0] = SWAP_LONG(fpu->x20.x[0]);
        fpu->x20.x[1] = SWAP_LONG(fpu->x20.x[1]);
        fpu->x20.x[2] = SWAP_LONG(fpu->x20.x[2]);
        fpu->x20.x[3] = SWAP_LONG(fpu->x20.x[3]);
        fpu->x21.x[0] = SWAP_LONG(fpu->x21.x[0]);
        fpu->x21.x[1] = SWAP_LONG(fpu->x21.x[1]);
        fpu->x21.x[2] = SWAP_LONG(fpu->x21.x[2]);
        fpu->x21.x[3] = SWAP_LONG(fpu->x21.x[3]);
        fpu->x22.x[0] = SWAP_LONG(fpu->x22.x[0]);
        fpu->x22.x[1] = SWAP_LONG(fpu->x22.x[1]);
        fpu->x22.x[2] = SWAP_LONG(fpu->x22.x[2]);
        fpu->x22.x[3] = SWAP_LONG(fpu->x22.x[3]);
        fpu->x23.x[0] = SWAP_LONG(fpu->x23.x[0]);
        fpu->x23.x[1] = SWAP_LONG(fpu->x23.x[1]);
        fpu->x23.x[2] = SWAP_LONG(fpu->x23.x[2]);
        fpu->x23.x[3] = SWAP_LONG(fpu->x23.x[3]);
        fpu->x24.x[0] = SWAP_LONG(fpu->x24.x[0]);
        fpu->x24.x[1] = SWAP_LONG(fpu->x24.x[1]);
        fpu->x24.x[2] = SWAP_LONG(fpu->x24.x[2]);
        fpu->x24.x[3] = SWAP_LONG(fpu->x24.x[3]);
        fpu->x25.x[0] = SWAP_LONG(fpu->x25.x[0]);
        fpu->x25.x[1] = SWAP_LONG(fpu->x25.x[1]);
        fpu->x25.x[2] = SWAP_LONG(fpu->x25.x[2]);
        fpu->x25.x[3] = SWAP_LONG(fpu->x25.x[3]);
        fpu->x26.x[0] = SWAP_LONG(fpu->x26.x[0]);
        fpu->x26.x[1] = SWAP_LONG(fpu->x26.x[1]);
        fpu->x26.x[2] = SWAP_LONG(fpu->x26.x[2]);
        fpu->x26.x[3] = SWAP_LONG(fpu->x26.x[3]);
        fpu->x27.x[0] = SWAP_LONG(fpu->x27.x[0]);
        fpu->x27.x[1] = SWAP_LONG(fpu->x27.x[1]);
        fpu->x27.x[2] = SWAP_LONG(fpu->x27.x[2]);
        fpu->x27.x[3] = SWAP_LONG(fpu->x27.x[3]);
        fpu->x28.x[0] = SWAP_LONG(fpu->x28.x[0]);
        fpu->x28.x[1] = SWAP_LONG(fpu->x28.x[1]);
        fpu->x28.x[2] = SWAP_LONG(fpu->x28.x[2]);
        fpu->x28.x[3] = SWAP_LONG(fpu->x28.x[3]);
        fpu->x29.x[0] = SWAP_LONG(fpu->x29.x[0]);
        fpu->x29.x[1] = SWAP_LONG(fpu->x29.x[1]);
        fpu->x29.x[2] = SWAP_LONG(fpu->x29.x[2]);
        fpu->x29.x[3] = SWAP_LONG(fpu->x29.x[3]);
        fpu->x30.x[0] = SWAP_LONG(fpu->x30.x[0]);
        fpu->x30.x[1] = SWAP_LONG(fpu->x30.x[1]);
        fpu->x30.x[2] = SWAP_LONG(fpu->x30.x[2]);
        fpu->x30.x[3] = SWAP_LONG(fpu->x30.x[3]);
        fpu->x31.x[0] = SWAP_LONG(fpu->x31.x[0]);
        fpu->x31.x[1] = SWAP_LONG(fpu->x31.x[1]);
        fpu->x31.x[2] = SWAP_LONG(fpu->x31.x[2]);
        fpu->x31.x[3] = SWAP_LONG(fpu->x31.x[3]);

        if ( !mf ){
            memcpy(&ssr, &(fpu->fpsr), sizeof(struct swapped_m88k_fpsr));
            ssr.u.word = SWAP_LONG(ssr.u.word);
            fpu->fpsr.afinx = ssr.u.fields.afinx;
            fpu->fpsr.afovf = ssr.u.fields.afovf;
            fpu->fpsr.afunf = ssr.u.fields.afunf;
            fpu->fpsr.afdvz = ssr.u.fields.afdvz;
            fpu->fpsr.afinv = ssr.u.fields.afinv;
            fpu->fpsr.xmod = ssr.u.fields.xmod;

            memcpy(&scr, &(fpu->fpcr), sizeof(struct swapped_m88k_fpcr));
            scr.u.word = SWAP_LONG(scr.u.word);
            fpu->fpcr.efinx = scr.u.fields.efinx;
            fpu->fpcr.efovf = scr.u.fields.efovf;
            fpu->fpcr.efunf = scr.u.fields.efunf;
            fpu->fpcr.efdvz = scr.u.fields.efdvz;
            fpu->fpcr.efinv = scr.u.fields.efinv;
            fpu->fpcr.rm = scr.u.fields.rm;
        }
        else{
            ssr.u.fields.afinx = fpu->fpsr.afinx;
            ssr.u.fields.afovf = fpu->fpsr.afovf;
            ssr.u.fields.afunf = fpu->fpsr.afunf;
            ssr.u.fields.afdvz = fpu->fpsr.afdvz;
            ssr.u.fields.afinv = fpu->fpsr.afinv;
            ssr.u.fields.xmod = fpu->fpsr.xmod;
            ssr.u.word = SWAP_LONG(ssr.u.word);
            memcpy(&(fpu->fpsr), &ssr, sizeof(struct swapped_m88k_fpsr));

            scr.u.fields.efinx = fpu->fpcr.efinx;
            scr.u.fields.efovf = fpu->fpcr.efovf;
            scr.u.fields.efunf = fpu->fpcr.efunf;
            scr.u.fields.efdvz = fpu->fpcr.efdvz;
            scr.u.fields.efinv = fpu->fpcr.efinv;
            scr.u.fields.rm = fpu->fpcr.rm;
            scr.u.word = SWAP_LONG(scr.u.word);
            memcpy(&(fpu->fpcr), &scr, sizeof(struct swapped_m88k_fpcr));
        }
}

//--------------------------------------------------------------------------
local void swap_m88k_thread_state_user_t(m88k_thread_state_user_t *user)
{
        user->user = SWAP_LONG(user->user);
}

//--------------------------------------------------------------------------
local void swap_m88110_thread_state_impl_t(m88110_thread_state_impl_t *spu)
{
    uint32 i;

    struct swapped_m88110_bp_ctrl {
        union {
            struct {
                unsigned        v:BIT_WIDTH(0);
                m88110_match_t  addr_match:BITS_WIDTH(12,1);
                unsigned        :BITS_WIDTH(26,13);
                unsigned        rwm:BIT_WIDTH(27);
                unsigned        rw:BIT_WIDTH(28);
                unsigned        :BITS_WIDTH(31,29);
            } fields;
            uint32 word;
        } u;
    } sbpc;

    struct swap_m88110_psr {
        union {
            struct {
                unsigned        :BITS_WIDTH(1,0);
                unsigned        mxm_dis:BIT_WIDTH(2);
                unsigned        sfu1dis:BIT_WIDTH(3);
                unsigned        :BITS_WIDTH(22,4);
                unsigned        trace:BIT_WIDTH(23);
                unsigned        :BIT_WIDTH(24);
                unsigned        sm:BIT_WIDTH(25);
                unsigned        sgn_imd:BIT_WIDTH(26);
                unsigned        :BIT_WIDTH(27);
                unsigned        c:BIT_WIDTH(28);
                unsigned        se:BIT_WIDTH(29);
                unsigned        le:BIT_WIDTH(30);
                unsigned        supr:BIT_WIDTH(31);
            } fields;
            uint32 word;
        } u;
    } spsr;

    struct swapped_m88110_fp_trap_status {
        union {
            struct {
                unsigned        efinx:BIT_WIDTH(0);
                unsigned        efovf:BIT_WIDTH(1);
                unsigned        efunf:BIT_WIDTH(2);
                unsigned        efdvz:BIT_WIDTH(3);
                unsigned        efinv:BIT_WIDTH(4);
                unsigned        priv:BIT_WIDTH(5);
                unsigned        unimp:BIT_WIDTH(6);
                unsigned        int:BIT_WIDTH(7);
                unsigned        sfu1_disabled:BIT_WIDTH(8);
                unsigned        :BITS_WIDTH(13,9);
                m88110_iresult_size_t   iresult_size:BITS_WIDTH(15,14);
                unsigned        :BITS_WIDTH(31,16);
            } fields;
            uint32 word;
        } u;
    } sfps;

        if ( !mf ){
            for(i = 0; i < M88110_N_DATA_BP; i++){
                spu->data_bp[i].addr = SWAP_LONG(spu->data_bp[i].addr);
                memcpy(&sbpc, &(spu->data_bp[i].ctrl),
                       sizeof(struct swapped_m88110_bp_ctrl));
                sbpc.u.word = SWAP_LONG(sbpc.u.word);
                spu->data_bp[i].ctrl.v = sbpc.u.fields.v;
                spu->data_bp[i].ctrl.addr_match = sbpc.u.fields.addr_match;
                spu->data_bp[i].ctrl.rwm = sbpc.u.fields.rwm;
                spu->data_bp[i].ctrl.rw = sbpc.u.fields.rw;
            }

            memcpy(&spsr, &(spu->psr), sizeof(struct swap_m88110_psr));
            spsr.u.word = SWAP_LONG(spsr.u.word);
            spu->psr.mxm_dis = spsr.u.fields.mxm_dis;
            spu->psr.sfu1dis = spsr.u.fields.sfu1dis;
            spu->psr.trace = spsr.u.fields.trace;
            spu->psr.sm = spsr.u.fields.sm;
            spu->psr.sgn_imd = spsr.u.fields.sgn_imd;
            spu->psr.c = spsr.u.fields.c;
            spu->psr.se = spsr.u.fields.se;
            spu->psr.le = spsr.u.fields.le;
            spu->psr.supr = spsr.u.fields.supr;

            memcpy(&sfps, &(spu->fp_trap_status),
                   sizeof(struct swapped_m88110_fp_trap_status));
            sfps.u.word = SWAP_LONG(sfps.u.word);
            spu->fp_trap_status.efinx = sfps.u.fields.efinx;
            spu->fp_trap_status.efovf = sfps.u.fields.efovf;
            spu->fp_trap_status.efunf = sfps.u.fields.efunf;
            spu->fp_trap_status.efdvz = sfps.u.fields.efdvz;
            spu->fp_trap_status.efinv = sfps.u.fields.efinv;
            spu->fp_trap_status.priv = sfps.u.fields.priv;
            spu->fp_trap_status.unimp = sfps.u.fields.unimp;
            spu->fp_trap_status.sfu1_disabled = sfps.u.fields.sfu1_disabled;
            spu->fp_trap_status.iresult_size = sfps.u.fields.iresult_size;
        }
        else{
            for(i = 0; i < M88110_N_DATA_BP; i++){
                spu->data_bp[i].addr = SWAP_LONG(spu->data_bp[i].addr);
                sbpc.u.fields.v = spu->data_bp[i].ctrl.v;
                sbpc.u.fields.addr_match = spu->data_bp[i].ctrl.addr_match;
                sbpc.u.fields.rwm = spu->data_bp[i].ctrl.rwm;
                sbpc.u.fields.rw = spu->data_bp[i].ctrl.rw;
                sbpc.u.word = SWAP_LONG(sbpc.u.word);
                memcpy(&(spu->data_bp[i].ctrl), &sbpc,
                       sizeof(struct swapped_m88110_bp_ctrl));
            }

            spsr.u.fields.mxm_dis = spu->psr.mxm_dis;
            spsr.u.fields.sfu1dis = spu->psr.sfu1dis;
            spsr.u.fields.trace = spu->psr.trace;
            spsr.u.fields.sm = spu->psr.sm;
            spsr.u.fields.sgn_imd = spu->psr.sgn_imd;
            spsr.u.fields.c = spu->psr.c;
            spsr.u.fields.se = spu->psr.se;
            spsr.u.fields.le = spu->psr.le;
            spsr.u.fields.supr = spu->psr.supr;
            spsr.u.word = SWAP_LONG(spsr.u.word);
            memcpy(&(spu->psr), &spsr, sizeof(struct swap_m88110_psr));

            sfps.u.fields.efinx = spu->fp_trap_status.efinx;
            sfps.u.fields.efovf = spu->fp_trap_status.efovf;
            sfps.u.fields.efunf = spu->fp_trap_status.efunf;
            sfps.u.fields.efdvz = spu->fp_trap_status.efdvz;
            sfps.u.fields.efinv = spu->fp_trap_status.efinv;
            sfps.u.fields.priv = spu->fp_trap_status.priv;
            sfps.u.fields.unimp = spu->fp_trap_status.unimp;
            sfps.u.fields.sfu1_disabled = spu->fp_trap_status.sfu1_disabled;
            sfps.u.fields.iresult_size = spu->fp_trap_status.iresult_size;
            sfps.u.word = SWAP_LONG(sfps.u.word);
            memcpy(&(spu->fp_trap_status), &sfps,
                   sizeof(struct swapped_m88110_fp_trap_status));
        }
        spu->intermediate_result.x[0] =
            SWAP_LONG(spu->intermediate_result.x[0]);
        spu->intermediate_result.x[1] =
            SWAP_LONG(spu->intermediate_result.x[1]);
        spu->intermediate_result.x[2] =
            SWAP_LONG(spu->intermediate_result.x[2]);
        spu->intermediate_result.x[3] =
            SWAP_LONG(spu->intermediate_result.x[3]);
}

//--------------------------------------------------------------------------
local void swap_i860_thread_state_regs(struct i860_thread_state_regs *cpu)
{
    uint32 i;

        for(i = 0; i < 31; i++)
            cpu->ireg[i] = SWAP_LONG(cpu->ireg[i]);
        for(i = 0; i < 30; i++)
            cpu->freg[i] = SWAP_LONG(cpu->freg[i]);
        cpu->psr = SWAP_LONG(cpu->psr);
        cpu->epsr = SWAP_LONG(cpu->epsr);
        cpu->db = SWAP_LONG(cpu->db);
        cpu->pc = SWAP_LONG(cpu->pc);
        cpu->_padding_ = SWAP_LONG(cpu->_padding_);
        cpu->Mres3 = SWAP_DOUBLE(cpu->Mres3);
        cpu->Ares3 = SWAP_DOUBLE(cpu->Ares3);
        cpu->Mres2 = SWAP_DOUBLE(cpu->Mres2);
        cpu->Ares2 = SWAP_DOUBLE(cpu->Ares2);
        cpu->Mres1 = SWAP_DOUBLE(cpu->Mres1);
        cpu->Ares1 = SWAP_DOUBLE(cpu->Ares1);
        cpu->Ires1 = SWAP_DOUBLE(cpu->Ires1);
        cpu->Lres3m = SWAP_DOUBLE(cpu->Lres3m);
        cpu->Lres2m = SWAP_DOUBLE(cpu->Lres2m);
        cpu->Lres1m = SWAP_DOUBLE(cpu->Lres1m);
        cpu->KR = SWAP_DOUBLE(cpu->KR);
        cpu->KI = SWAP_DOUBLE(cpu->KI);
        cpu->T = SWAP_DOUBLE(cpu->T);
        cpu->Fsr3 = SWAP_LONG(cpu->Fsr3);
        cpu->Fsr2 = SWAP_LONG(cpu->Fsr2);
        cpu->Fsr1 = SWAP_LONG(cpu->Fsr1);
        cpu->Mergelo32 = SWAP_LONG(cpu->Mergelo32);
        cpu->Mergehi32 = SWAP_LONG(cpu->Mergehi32);
}
*/

#if defined(EFD_COMPILE) || defined(LOADER_COMPILE)
//--------------------------------------------------------------------------
local void swap_arm_thread_state(arm_thread_state_t *cpu)
{
        for(int i = 0; i < 13; i++)
            cpu->__r[i] = SWAP_LONG(cpu->__r[i]);
        cpu->__sp = SWAP_LONG(cpu->__sp);
        cpu->__lr = SWAP_LONG(cpu->__lr);
        cpu->__pc = SWAP_LONG(cpu->__pc);
        cpu->__cpsr = SWAP_LONG(cpu->__cpsr);
}

//--------------------------------------------------------------------------
local void swap_i386_thread_state(i386_thread_state_t *cpu)
{
  cpu->__eax = swap32(cpu->__eax);
  cpu->__ebx = swap32(cpu->__ebx);
  cpu->__ecx = swap32(cpu->__ecx);
  cpu->__edx = swap32(cpu->__edx);
  cpu->__edi = swap32(cpu->__edi);
  cpu->__esi = swap32(cpu->__esi);
  cpu->__ebp = swap32(cpu->__ebp);
  cpu->__esp = swap32(cpu->__esp);
  cpu->__ss = swap32(cpu->__ss);
  cpu->__eflags = swap32(cpu->__eflags);
  cpu->__eip = swap32(cpu->__eip);
  cpu->__cs = swap32(cpu->__cs);
  cpu->__ds = swap32(cpu->__ds);
  cpu->__es = swap32(cpu->__es);
  cpu->__fs = swap32(cpu->__fs);
  cpu->__gs = swap32(cpu->__gs);
}

//--------------------------------------------------------------------------
local void swap_x86_thread_state64( x86_thread_state64_t *cpu)
{
  cpu->__rax = swap64(cpu->__rax);
  cpu->__rbx = swap64(cpu->__rbx);
  cpu->__rcx = swap64(cpu->__rcx);
  cpu->__rdx = swap64(cpu->__rdx);
  cpu->__rdi = swap64(cpu->__rdi);
  cpu->__rsi = swap64(cpu->__rsi);
  cpu->__rbp = swap64(cpu->__rbp);
  cpu->__rsp = swap64(cpu->__rsp);
  cpu->__rflags = swap64(cpu->__rflags);
  cpu->__rip = swap64(cpu->__rip);
  cpu->__r8 = swap64(cpu->__r8);
  cpu->__r9 = swap64(cpu->__r9);
  cpu->__r10 = swap64(cpu->__r10);
  cpu->__r11 = swap64(cpu->__r11);
  cpu->__r12 = swap64(cpu->__r12);
  cpu->__r13 = swap64(cpu->__r13);
  cpu->__r14 = swap64(cpu->__r14);
  cpu->__r15 = swap64(cpu->__r15);
  cpu->__cs = swap64(cpu->__cs);
  cpu->__fs = swap64(cpu->__fs);
  cpu->__gs = swap64(cpu->__gs);
}
#endif

//--------------------------------------------------------------------------
#if 0 // !defined(EFD_COMPILE) && !defined(LOADER_COMPILE)
local void swap_x86_state_hdr(x86_state_hdr_t *hdr)
{
  hdr->flavor = swap32(hdr->flavor);
  hdr->count = swap32(hdr->count);
}

//--------------------------------------------------------------------------
local void swap_x86_float_state64(x86_float_state64_t *fpu)
{
    struct swapped_fp_control {
  union {
      struct {
    unsigned short
          :3,
        /*inf*/ :1,
        rc      :2,
        pc      :2,
          :2,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
  } u;
    } sfpc;

    struct swapped_fp_status {
  union {
      struct {
    unsigned short
        busy    :1,
        c3      :1,
        tos      :3,
        c2      :1,
        c1      :1,
        c0      :1,
        errsumm :1,
        stkflt  :1,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
  } u;
    } sfps;

  fpu->__fpu_reserved[0] = swap32(fpu->__fpu_reserved[0]);
  fpu->__fpu_reserved[1] = swap32(fpu->__fpu_reserved[1]);

  if ( !mf )
        {
      memcpy(&sfpc, &(fpu->__fpu_fcw),
       sizeof(struct swapped_fp_control));
      sfpc.u.half = swap16(sfpc.u.half);
      fpu->__fpu_fcw.__rc = sfpc.u.fields.rc;
      fpu->__fpu_fcw.__pc = sfpc.u.fields.pc;
      fpu->__fpu_fcw.__precis = sfpc.u.fields.precis;
      fpu->__fpu_fcw.__undfl = sfpc.u.fields.undfl;
      fpu->__fpu_fcw.__ovrfl = sfpc.u.fields.ovrfl;
      fpu->__fpu_fcw.__zdiv = sfpc.u.fields.zdiv;
      fpu->__fpu_fcw.__denorm = sfpc.u.fields.denorm;
      fpu->__fpu_fcw.__invalid = sfpc.u.fields.invalid;

      memcpy(&sfps, &(fpu->__fpu_fsw),
       sizeof(struct swapped_fp_status));
      sfps.u.half = swap16(sfps.u.half);
      fpu->__fpu_fsw.__busy = sfps.u.fields.busy;
      fpu->__fpu_fsw.__c3 = sfps.u.fields.c3;
      fpu->__fpu_fsw.__tos = sfps.u.fields.tos;
      fpu->__fpu_fsw.__c2 = sfps.u.fields.c2;
      fpu->__fpu_fsw.__c1 = sfps.u.fields.c1;
      fpu->__fpu_fsw.__c0 = sfps.u.fields.c0;
      fpu->__fpu_fsw.__errsumm = sfps.u.fields.errsumm;
      fpu->__fpu_fsw.__stkflt = sfps.u.fields.stkflt;
      fpu->__fpu_fsw.__precis = sfps.u.fields.precis;
      fpu->__fpu_fsw.__undfl = sfps.u.fields.undfl;
      fpu->__fpu_fsw.__ovrfl = sfps.u.fields.ovrfl;
      fpu->__fpu_fsw.__zdiv = sfps.u.fields.zdiv;
      fpu->__fpu_fsw.__denorm = sfps.u.fields.denorm;
      fpu->__fpu_fsw.__invalid = sfps.u.fields.invalid;
  }
  else{
      sfpc.u.fields.rc = fpu->__fpu_fcw.__rc;
      sfpc.u.fields.pc = fpu->__fpu_fcw.__pc;
      sfpc.u.fields.precis = fpu->__fpu_fcw.__precis;
      sfpc.u.fields.undfl = fpu->__fpu_fcw.__undfl;
      sfpc.u.fields.ovrfl = fpu->__fpu_fcw.__ovrfl;
      sfpc.u.fields.zdiv = fpu->__fpu_fcw.__zdiv;
      sfpc.u.fields.denorm = fpu->__fpu_fcw.__denorm;
      sfpc.u.fields.invalid = fpu->__fpu_fcw.__invalid;
      sfpc.u.half = swap16(sfpc.u.half);
      memcpy(&(fpu->__fpu_fcw), &sfpc,
       sizeof(struct swapped_fp_control));

      sfps.u.fields.busy = fpu->__fpu_fsw.__busy;
      sfps.u.fields.c3 = fpu->__fpu_fsw.__c3;
      sfps.u.fields.tos = fpu->__fpu_fsw.__tos;
      sfps.u.fields.c2 = fpu->__fpu_fsw.__c2;
      sfps.u.fields.c1 = fpu->__fpu_fsw.__c1;
      sfps.u.fields.c0 = fpu->__fpu_fsw.__c0;
      sfps.u.fields.errsumm = fpu->__fpu_fsw.__errsumm;
      sfps.u.fields.stkflt = fpu->__fpu_fsw.__stkflt;
      sfps.u.fields.precis = fpu->__fpu_fsw.__precis;
      sfps.u.fields.undfl = fpu->__fpu_fsw.__undfl;
      sfps.u.fields.ovrfl = fpu->__fpu_fsw.__ovrfl;
      sfps.u.fields.zdiv = fpu->__fpu_fsw.__zdiv;
      sfps.u.fields.denorm = fpu->__fpu_fsw.__denorm;
      sfps.u.fields.invalid = fpu->__fpu_fsw.__invalid;
      sfps.u.half = swap16(sfps.u.half);
      memcpy(&(fpu->__fpu_fsw), &sfps,
       sizeof(struct swapped_fp_status));
  }
  fpu->__fpu_fop = swap16(fpu->__fpu_fop);
  fpu->__fpu_ip = swap32(fpu->__fpu_ip);
  fpu->__fpu_cs = swap16(fpu->__fpu_cs);
  fpu->__fpu_rsrv2 = swap16(fpu->__fpu_rsrv2);
  fpu->__fpu_dp = swap32(fpu->__fpu_dp);
  fpu->__fpu_ds = swap16(fpu->__fpu_ds);
  fpu->__fpu_rsrv3 = swap16(fpu->__fpu_rsrv3);
  fpu->__fpu_mxcsr = swap32(fpu->__fpu_mxcsr);
  fpu->__fpu_mxcsrmask = swap32(fpu->__fpu_mxcsrmask);
  fpu->__fpu_reserved1 = swap32(fpu->__fpu_reserved1);
}

//--------------------------------------------------------------------------
local void
swap_x86_exception_state64(x86_exception_state64_t *exc)
{
  exc->__trapno = swap32(exc->__trapno);
  exc->__err = swap32(exc->__err);
      exc->__faultvaddr = swap64(exc->__faultvaddr);
}

//--------------------------------------------------------------------------
local void swap_x86_debug_state32(x86_debug_state32_t *debug)
{
  debug->__dr0 = swap32(debug->__dr0);
  debug->__dr1 = swap32(debug->__dr1);
  debug->__dr2 = swap32(debug->__dr2);
  debug->__dr3 = swap32(debug->__dr3);
  debug->__dr4 = swap32(debug->__dr4);
  debug->__dr5 = swap32(debug->__dr5);
  debug->__dr6 = swap32(debug->__dr6);
  debug->__dr7 = swap32(debug->__dr7);
}

//--------------------------------------------------------------------------
local void swap_x86_debug_state64(x86_debug_state64_t *debug)
{
  debug->__dr0 = swap64(debug->__dr0);
  debug->__dr1 = swap64(debug->__dr1);
  debug->__dr2 = swap64(debug->__dr2);
  debug->__dr3 = swap64(debug->__dr3);
  debug->__dr4 = swap64(debug->__dr4);
  debug->__dr5 = swap64(debug->__dr5);
  debug->__dr6 = swap64(debug->__dr6);
  debug->__dr7 = swap64(debug->__dr7);
}
#endif  // !EFD_COMPILE && !LOADER_COMPILE

/* current i386 thread states */
#if i386_THREAD_STATE == 1
void
swap_i386_float_state(i386_float_state_t *fpu)
{
#ifndef i386_EXCEPTION_STATE_COUNT
    /* this routine does nothing as their are currently no non-byte fields */
#else /* !defined(i386_EXCEPTION_STATE_COUNT) */
    struct swapped_fp_control {
  union {
      struct {
    unsigned short
          :3,
        /*inf*/ :1,
        rc      :2,
        pc      :2,
          :2,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
  } u;
    } sfpc;

    struct swapped_fp_status {
  union {
      struct {
    unsigned short
        busy    :1,
        c3      :1,
        tos      :3,
        c2      :1,
        c1      :1,
        c0      :1,
        errsumm :1,
        stkflt  :1,
        precis  :1,
        undfl   :1,
        ovrfl   :1,
        zdiv    :1,
        denorm  :1,
        invalid :1;
      } fields;
      unsigned short half;
  } u;
    } sfps;

//    enum NXByteOrder host_byte_sex;

  fpu->__fpu_reserved[0] = swap32(fpu->__fpu_reserved[0]);
  fpu->__fpu_reserved[1] = swap32(fpu->__fpu_reserved[1]);

  if( !mf ) {
      memcpy(&sfpc, &(fpu->__fpu_fcw),
       sizeof(struct swapped_fp_control));
      sfpc.u.half = swap16(sfpc.u.half);
      fpu->__fpu_fcw.__rc = sfpc.u.fields.rc;
      fpu->__fpu_fcw.__pc = sfpc.u.fields.pc;
      fpu->__fpu_fcw.__precis = sfpc.u.fields.precis;
      fpu->__fpu_fcw.__undfl = sfpc.u.fields.undfl;
      fpu->__fpu_fcw.__ovrfl = sfpc.u.fields.ovrfl;
      fpu->__fpu_fcw.__zdiv = sfpc.u.fields.zdiv;
      fpu->__fpu_fcw.__denorm = sfpc.u.fields.denorm;
      fpu->__fpu_fcw.__invalid = sfpc.u.fields.invalid;

      memcpy(&sfps, &(fpu->__fpu_fsw),
       sizeof(struct swapped_fp_status));
      sfps.u.half = swap16(sfps.u.half);
      fpu->__fpu_fsw.__busy = sfps.u.fields.busy;
      fpu->__fpu_fsw.__c3 = sfps.u.fields.c3;
      fpu->__fpu_fsw.__tos = sfps.u.fields.tos;
      fpu->__fpu_fsw.__c2 = sfps.u.fields.c2;
      fpu->__fpu_fsw.__c1 = sfps.u.fields.c1;
      fpu->__fpu_fsw.__c0 = sfps.u.fields.c0;
      fpu->__fpu_fsw.__errsumm = sfps.u.fields.errsumm;
      fpu->__fpu_fsw.__stkflt = sfps.u.fields.stkflt;
      fpu->__fpu_fsw.__precis = sfps.u.fields.precis;
      fpu->__fpu_fsw.__undfl = sfps.u.fields.undfl;
      fpu->__fpu_fsw.__ovrfl = sfps.u.fields.ovrfl;
      fpu->__fpu_fsw.__zdiv = sfps.u.fields.zdiv;
      fpu->__fpu_fsw.__denorm = sfps.u.fields.denorm;
      fpu->__fpu_fsw.__invalid = sfps.u.fields.invalid;
  }
  else{
      sfpc.u.fields.rc = fpu->__fpu_fcw.__rc;
      sfpc.u.fields.pc = fpu->__fpu_fcw.__pc;
      sfpc.u.fields.precis = fpu->__fpu_fcw.__precis;
      sfpc.u.fields.undfl = fpu->__fpu_fcw.__undfl;
      sfpc.u.fields.ovrfl = fpu->__fpu_fcw.__ovrfl;
      sfpc.u.fields.zdiv = fpu->__fpu_fcw.__zdiv;
      sfpc.u.fields.denorm = fpu->__fpu_fcw.__denorm;
      sfpc.u.fields.invalid = fpu->__fpu_fcw.__invalid;
      sfpc.u.half = swap16(sfpc.u.half);
      memcpy(&(fpu->__fpu_fcw), &sfpc,
       sizeof(struct swapped_fp_control));

      sfps.u.fields.busy = fpu->__fpu_fsw.__busy;
      sfps.u.fields.c3 = fpu->__fpu_fsw.__c3;
      sfps.u.fields.tos = fpu->__fpu_fsw.__tos;
      sfps.u.fields.c2 = fpu->__fpu_fsw.__c2;
      sfps.u.fields.c1 = fpu->__fpu_fsw.__c1;
      sfps.u.fields.c0 = fpu->__fpu_fsw.__c0;
      sfps.u.fields.errsumm = fpu->__fpu_fsw.__errsumm;
      sfps.u.fields.stkflt = fpu->__fpu_fsw.__stkflt;
      sfps.u.fields.precis = fpu->__fpu_fsw.__precis;
      sfps.u.fields.undfl = fpu->__fpu_fsw.__undfl;
      sfps.u.fields.ovrfl = fpu->__fpu_fsw.__ovrfl;
      sfps.u.fields.zdiv = fpu->__fpu_fsw.__zdiv;
      sfps.u.fields.denorm = fpu->__fpu_fsw.__denorm;
      sfps.u.fields.invalid = fpu->__fpu_fsw.__invalid;
      sfps.u.half = swap16(sfps.u.half);
      memcpy(&(fpu->__fpu_fsw), &sfps,
       sizeof(struct swapped_fp_status));
  }
  fpu->__fpu_fop = swap16(fpu->__fpu_fop);
  fpu->__fpu_ip = swap32(fpu->__fpu_ip);
  fpu->__fpu_cs = swap16(fpu->__fpu_cs);
  fpu->__fpu_rsrv2 = swap16(fpu->__fpu_rsrv2);
  fpu->__fpu_dp = swap32(fpu->__fpu_dp);
  fpu->__fpu_ds = swap16(fpu->__fpu_ds);
  fpu->__fpu_rsrv3 = swap16(fpu->__fpu_rsrv3);
  fpu->__fpu_mxcsr = swap32(fpu->__fpu_mxcsr);
  fpu->__fpu_mxcsrmask = swap32(fpu->__fpu_mxcsrmask);
  fpu->__fpu_reserved1 = swap32(fpu->__fpu_reserved1);

#endif /* !defined(i386_EXCEPTION_STATE_COUNT) */
}

void swap_i386_exception_state(i386_exception_state_t *exc)
{
  exc->__trapno = swap32(exc->__trapno);
  exc->__err = swap32(exc->__err);
      exc->__faultvaddr = swap32(exc->__faultvaddr);
}
#endif /* i386_THREAD_STATE == 1 */

//--------------------------------------------------------------------------
/*
local void swap_hppa_integer_thread_state(struct hp_pa_integer_thread_state *regs)
{
        regs->ts_gr1 = SWAP_LONG(regs->ts_gr1);
        regs->ts_gr2 = SWAP_LONG(regs->ts_gr2);
        regs->ts_gr3 = SWAP_LONG(regs->ts_gr3);
        regs->ts_gr4 = SWAP_LONG(regs->ts_gr4);
        regs->ts_gr5 = SWAP_LONG(regs->ts_gr5);
        regs->ts_gr6 = SWAP_LONG(regs->ts_gr6);
        regs->ts_gr7 = SWAP_LONG(regs->ts_gr7);
        regs->ts_gr8 = SWAP_LONG(regs->ts_gr8);
        regs->ts_gr9 = SWAP_LONG(regs->ts_gr9);
        regs->ts_gr10 = SWAP_LONG(regs->ts_gr10);
        regs->ts_gr11 = SWAP_LONG(regs->ts_gr11);
        regs->ts_gr12 = SWAP_LONG(regs->ts_gr12);
        regs->ts_gr13 = SWAP_LONG(regs->ts_gr13);
        regs->ts_gr14 = SWAP_LONG(regs->ts_gr14);
        regs->ts_gr15 = SWAP_LONG(regs->ts_gr15);
        regs->ts_gr16 = SWAP_LONG(regs->ts_gr16);
        regs->ts_gr17 = SWAP_LONG(regs->ts_gr17);
        regs->ts_gr18 = SWAP_LONG(regs->ts_gr18);
        regs->ts_gr19 = SWAP_LONG(regs->ts_gr19);
        regs->ts_gr20 = SWAP_LONG(regs->ts_gr20);
        regs->ts_gr21 = SWAP_LONG(regs->ts_gr21);
        regs->ts_gr22 = SWAP_LONG(regs->ts_gr22);
        regs->ts_gr23 = SWAP_LONG(regs->ts_gr23);
        regs->ts_gr24 = SWAP_LONG(regs->ts_gr24);
        regs->ts_gr25 = SWAP_LONG(regs->ts_gr25);
        regs->ts_gr26 = SWAP_LONG(regs->ts_gr26);
        regs->ts_gr27 = SWAP_LONG(regs->ts_gr27);
        regs->ts_gr28 = SWAP_LONG(regs->ts_gr28);
        regs->ts_gr29 = SWAP_LONG(regs->ts_gr29);
        regs->ts_gr30 = SWAP_LONG(regs->ts_gr30);
        regs->ts_gr31 = SWAP_LONG(regs->ts_gr31);
        regs->ts_sr0 = SWAP_LONG(regs->ts_sr0);
        regs->ts_sr1 = SWAP_LONG(regs->ts_sr1);
        regs->ts_sr2 = SWAP_LONG(regs->ts_sr2);
        regs->ts_sr3 = SWAP_LONG(regs->ts_sr3);
        regs->ts_sar = SWAP_LONG(regs->ts_sar);
}

//--------------------------------------------------------------------------
local void swap_hppa_frame_thread_state( struct hp_pa_frame_thread_state *frame){
        frame->ts_pcsq_front = SWAP_LONG(frame->ts_pcsq_front);
        frame->ts_pcsq_back = SWAP_LONG(frame->ts_pcsq_back);
        frame->ts_pcoq_front = SWAP_LONG(frame->ts_pcoq_front);
        frame->ts_pcoq_back = SWAP_LONG(frame->ts_pcoq_back);
        frame->ts_psw = SWAP_LONG(frame->ts_psw);
        frame->ts_unaligned_faults = SWAP_LONG(frame->ts_unaligned_faults);
        frame->ts_fault_address = SWAP_LONG(frame->ts_fault_address);
        frame->ts_step_range_start = SWAP_LONG(frame->ts_step_range_start);
        frame->ts_step_range_stop = SWAP_LONG(frame->ts_step_range_stop);
}

//--------------------------------------------------------------------------
local void swap_hppa_fp_thread_state( struct hp_pa_fp_thread_state *fp){
        fp->ts_fp0 = SWAP_DOUBLE(fp->ts_fp0);
        fp->ts_fp1 = SWAP_DOUBLE(fp->ts_fp1);
        fp->ts_fp2 = SWAP_DOUBLE(fp->ts_fp2);
        fp->ts_fp3 = SWAP_DOUBLE(fp->ts_fp3);
        fp->ts_fp4 = SWAP_DOUBLE(fp->ts_fp4);
        fp->ts_fp5 = SWAP_DOUBLE(fp->ts_fp5);
        fp->ts_fp6 = SWAP_DOUBLE(fp->ts_fp6);
        fp->ts_fp7 = SWAP_DOUBLE(fp->ts_fp7);
        fp->ts_fp8 = SWAP_DOUBLE(fp->ts_fp8);
        fp->ts_fp9 = SWAP_DOUBLE(fp->ts_fp9);
        fp->ts_fp10 = SWAP_DOUBLE(fp->ts_fp10);
        fp->ts_fp11 = SWAP_DOUBLE(fp->ts_fp11);
        fp->ts_fp12 = SWAP_DOUBLE(fp->ts_fp12);
        fp->ts_fp13 = SWAP_DOUBLE(fp->ts_fp13);
        fp->ts_fp14 = SWAP_DOUBLE(fp->ts_fp14);
        fp->ts_fp15 = SWAP_DOUBLE(fp->ts_fp15);
        fp->ts_fp16 = SWAP_DOUBLE(fp->ts_fp16);
        fp->ts_fp17 = SWAP_DOUBLE(fp->ts_fp17);
        fp->ts_fp18 = SWAP_DOUBLE(fp->ts_fp18);
        fp->ts_fp19 = SWAP_DOUBLE(fp->ts_fp19);
        fp->ts_fp20 = SWAP_DOUBLE(fp->ts_fp20);
        fp->ts_fp21 = SWAP_DOUBLE(fp->ts_fp21);
        fp->ts_fp22 = SWAP_DOUBLE(fp->ts_fp22);
        fp->ts_fp23 = SWAP_DOUBLE(fp->ts_fp23);
        fp->ts_fp24 = SWAP_DOUBLE(fp->ts_fp24);
        fp->ts_fp25 = SWAP_DOUBLE(fp->ts_fp25);
        fp->ts_fp26 = SWAP_DOUBLE(fp->ts_fp26);
        fp->ts_fp27 = SWAP_DOUBLE(fp->ts_fp27);
        fp->ts_fp28 = SWAP_DOUBLE(fp->ts_fp28);
        fp->ts_fp29 = SWAP_DOUBLE(fp->ts_fp29);
        fp->ts_fp30 = SWAP_DOUBLE(fp->ts_fp30);
        fp->ts_fp31 = SWAP_DOUBLE(fp->ts_fp31);
}

//--------------------------------------------------------------------------
local void swap_sparc_thread_state_regs(struct sparc_thread_state_regs *cpu)
{
    struct swapped_psr {
        union {
            struct {
                unsigned int
                cwp:BITS_WIDTH(4,0),
                et:BIT_WIDTH(5),
                ps:BIT_WIDTH(6),
                s:BIT_WIDTH(7),
                pil:BITS_WIDTH(11,8),
                ef:BIT_WIDTH(12),
                ec:BIT_WIDTH(13),
                reserved:BITS_WIDTH(19,14),
                icc:BITS_WIDTH(23,20),
                ver:BITS_WIDTH(27,24),
                impl:BITS_WIDTH(31,28);
            } fields;
            unsigned int word;
        } u;
    } spsr;
    struct p_status *pr_status;

        cpu->regs.r_pc = SWAP_LONG(cpu->regs.r_pc);
        cpu->regs.r_npc = SWAP_LONG(cpu->regs.r_npc);
        cpu->regs.r_y = SWAP_LONG(cpu->regs.r_y);
        cpu->regs.r_g1 = SWAP_LONG(cpu->regs.r_g1);
        cpu->regs.r_g2 = SWAP_LONG(cpu->regs.r_g2);
        cpu->regs.r_g3 = SWAP_LONG(cpu->regs.r_g3);
        cpu->regs.r_g4 = SWAP_LONG(cpu->regs.r_g4);
        cpu->regs.r_g5 = SWAP_LONG(cpu->regs.r_g5);
        cpu->regs.r_g6 = SWAP_LONG(cpu->regs.r_g6);
        cpu->regs.r_g7 = SWAP_LONG(cpu->regs.r_g7);
        cpu->regs.r_o0 = SWAP_LONG(cpu->regs.r_o0);
        cpu->regs.r_o1 = SWAP_LONG(cpu->regs.r_o1);
        cpu->regs.r_o2 = SWAP_LONG(cpu->regs.r_o2);
        cpu->regs.r_o3 = SWAP_LONG(cpu->regs.r_o3);
        cpu->regs.r_o4 = SWAP_LONG(cpu->regs.r_o4);
        cpu->regs.r_o5 = SWAP_LONG(cpu->regs.r_o5);
        cpu->regs.r_o6 = SWAP_LONG(cpu->regs.r_o6);
        cpu->regs.r_o7 = SWAP_LONG(cpu->regs.r_o7);

        pr_status = (struct p_status *) &(cpu->regs.r_psr);
        if ( !mf ){
            memcpy(&spsr, &(cpu->regs.r_psr), sizeof(struct swapped_psr));
            spsr.u.word = SWAP_LONG(spsr.u.word);
            pr_status->PSRREG.psr_bits.cwp = spsr.u.fields.cwp;
            pr_status->PSRREG.psr_bits.ps = spsr.u.fields.ps;
            pr_status->PSRREG.psr_bits.s = spsr.u.fields.s;
            pr_status->PSRREG.psr_bits.pil = spsr.u.fields.pil;
            pr_status->PSRREG.psr_bits.ef = spsr.u.fields.ef;
            pr_status->PSRREG.psr_bits.ec = spsr.u.fields.ec;
            pr_status->PSRREG.psr_bits.reserved = spsr.u.fields.reserved;
            pr_status->PSRREG.psr_bits.icc = spsr.u.fields.icc;
            pr_status->PSRREG.psr_bits.et = spsr.u.fields.ver;
            pr_status->PSRREG.psr_bits.impl = spsr.u.fields.impl;
        }
        else{
            spsr.u.fields.cwp = pr_status->PSRREG.psr_bits.cwp;
            spsr.u.fields.ps = pr_status->PSRREG.psr_bits.ps;
            spsr.u.fields.s = pr_status->PSRREG.psr_bits.s;
            spsr.u.fields.pil = pr_status->PSRREG.psr_bits.pil;
            spsr.u.fields.ef = pr_status->PSRREG.psr_bits.ef;
            spsr.u.fields.ec = pr_status->PSRREG.psr_bits.ec;
            spsr.u.fields.reserved = pr_status->PSRREG.psr_bits.reserved;
            spsr.u.fields.icc = pr_status->PSRREG.psr_bits.icc;
            spsr.u.fields.ver = pr_status->PSRREG.psr_bits.et;
            spsr.u.fields.impl = pr_status->PSRREG.psr_bits.impl;
            spsr.u.word = SWAP_LONG(spsr.u.word);
            memcpy(&(cpu->regs.r_psr), &spsr, sizeof(struct swapped_psr));
        }
}

//--------------------------------------------------------------------------
local void swap_sparc_thread_state_fpu(struct sparc_thread_state_fpu *fpu)
{
    struct swapped_fsr {
        union {
            struct {
                unsigned int
                cexc:BITS_WIDTH(4,0),
                aexc:BITS_WIDTH(9,5),
                fcc:BITS_WIDTH(11,10),
                pr:BIT_WIDTH(12),
                qne:BIT_WIDTH(13),
                ftt:BITS_WIDTH(16,14),
                res:BITS_WIDTH(22,17),
                tem:BITS_WIDTH(27,23),
                rp:BITS_WIDTH(29,28),
                rd:BITS_WIDTH(31,30);
            } fields;
            unsigned int word;
        } u;
    } sfsr;
    uint32 i;
    struct f_status *fpu_status;

        // floating point registers
        for(i = 0; i < 16; i++)         // 16 doubles
            fpu->fpu.fpu_fr.Fpu_dregs[i] =
                SWAP_DOUBLE(fpu->fpu.fpu_fr.Fpu_dregs[i]);

        fpu->fpu.Fpu_q[0].FQu.whole = SWAP_DOUBLE(fpu->fpu.Fpu_q[0].FQu.whole);
        fpu->fpu.Fpu_q[1].FQu.whole = SWAP_DOUBLE(fpu->fpu.Fpu_q[1].FQu.whole);
        fpu->fpu.Fpu_flags = SWAP_LONG(fpu->fpu.Fpu_flags);
        fpu->fpu.Fpu_extra = SWAP_LONG(fpu->fpu.Fpu_extra);
        fpu->fpu.Fpu_qcnt = SWAP_LONG(fpu->fpu.Fpu_qcnt);

        fpu_status = (struct f_status *) &(fpu->fpu.Fpu_fsr);
        if ( !mf ){
            memcpy(&sfsr, &(fpu->fpu.Fpu_fsr), sizeof(unsigned int));
            sfsr.u.word = SWAP_LONG(sfsr.u.word);
            fpu_status->FPUREG.Fpu_fsr_bits.rd = sfsr.u.fields.rd;
            fpu_status->FPUREG.Fpu_fsr_bits.rp = sfsr.u.fields.rp;
            fpu_status->FPUREG.Fpu_fsr_bits.tem = sfsr.u.fields.tem;
            fpu_status->FPUREG.Fpu_fsr_bits.res = sfsr.u.fields.res;
            fpu_status->FPUREG.Fpu_fsr_bits.ftt = sfsr.u.fields.ftt;
            fpu_status->FPUREG.Fpu_fsr_bits.qne = sfsr.u.fields.qne;
            fpu_status->FPUREG.Fpu_fsr_bits.pr = sfsr.u.fields.pr;
            fpu_status->FPUREG.Fpu_fsr_bits.fcc = sfsr.u.fields.fcc;
            fpu_status->FPUREG.Fpu_fsr_bits.aexc = sfsr.u.fields.aexc;
            fpu_status->FPUREG.Fpu_fsr_bits.cexc = sfsr.u.fields.cexc;
        }
        else{
            sfsr.u.fields.rd = fpu_status->FPUREG.Fpu_fsr_bits.rd;
            sfsr.u.fields.rp = fpu_status->FPUREG.Fpu_fsr_bits.rp;
            sfsr.u.fields.tem = fpu_status->FPUREG.Fpu_fsr_bits.tem;
            sfsr.u.fields.res = fpu_status->FPUREG.Fpu_fsr_bits.res;
            sfsr.u.fields.ftt = fpu_status->FPUREG.Fpu_fsr_bits.ftt;
            sfsr.u.fields.qne = fpu_status->FPUREG.Fpu_fsr_bits.qne;
            sfsr.u.fields.pr = fpu_status->FPUREG.Fpu_fsr_bits.pr;
            sfsr.u.fields.fcc = fpu_status->FPUREG.Fpu_fsr_bits.fcc;
            sfsr.u.fields.aexc = fpu_status->FPUREG.Fpu_fsr_bits.aexc;
            sfsr.u.fields.cexc = fpu_status->FPUREG.Fpu_fsr_bits.cexc;
            sfsr.u.word = SWAP_LONG(sfsr.u.word);
            memcpy(&(fpu->fpu.Fpu_fsr), &sfsr, sizeof(struct swapped_fsr));
        }
}
*/
//--------------------------------------------------------------------------
local void swap_ident_command(struct ident_command *id_cmd)
{
        id_cmd->cmd = SWAP_LONG(id_cmd->cmd);
        id_cmd->cmdsize = SWAP_LONG(id_cmd->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_routines_command(struct routines_command *r_cmd)
{
        r_cmd->cmd = SWAP_LONG(r_cmd->cmd);
        r_cmd->cmdsize = SWAP_LONG(r_cmd->cmdsize);
        r_cmd->init_address = SWAP_LONG(r_cmd->init_address);
        r_cmd->init_module = SWAP_LONG(r_cmd->init_module);
        r_cmd->reserved1 = SWAP_LONG(r_cmd->reserved1);
        r_cmd->reserved2 = SWAP_LONG(r_cmd->reserved2);
        r_cmd->reserved3 = SWAP_LONG(r_cmd->reserved3);
        r_cmd->reserved4 = SWAP_LONG(r_cmd->reserved4);
        r_cmd->reserved5 = SWAP_LONG(r_cmd->reserved5);
        r_cmd->reserved6 = SWAP_LONG(r_cmd->reserved6);
}

//--------------------------------------------------------------------------
local void swap_routines_command_64(struct routines_command_64 *r_cmd)
{
  r_cmd->cmd = SWAP_LONG(r_cmd->cmd);
  r_cmd->cmdsize = SWAP_LONG(r_cmd->cmdsize);
  r_cmd->init_address = SWAP_LONG_LONG(r_cmd->init_address);
  r_cmd->init_module = SWAP_LONG_LONG(r_cmd->init_module);
  r_cmd->reserved1 = SWAP_LONG_LONG(r_cmd->reserved1);
  r_cmd->reserved2 = SWAP_LONG_LONG(r_cmd->reserved2);
  r_cmd->reserved3 = SWAP_LONG_LONG(r_cmd->reserved3);
  r_cmd->reserved4 = SWAP_LONG_LONG(r_cmd->reserved4);
  r_cmd->reserved5 = SWAP_LONG_LONG(r_cmd->reserved5);
  r_cmd->reserved6 = SWAP_LONG_LONG(r_cmd->reserved6);
}
//--------------------------------------------------------------------------
local void swap_twolevel_hints_command(twolevel_hints_command *hints_cmd)
{
  hints_cmd->cmd = SWAP_LONG(hints_cmd->cmd);
  hints_cmd->cmdsize = SWAP_LONG(hints_cmd->cmdsize);
  hints_cmd->offset = SWAP_LONG(hints_cmd->offset);
  hints_cmd->nhints = SWAP_LONG(hints_cmd->nhints);
}

//--------------------------------------------------------------------------
local void swap_prebind_cksum_command(prebind_cksum_command *cksum_cmd)
{
  cksum_cmd->cmd = SWAP_LONG(cksum_cmd->cmd);
  cksum_cmd->cmdsize = SWAP_LONG(cksum_cmd->cmdsize);
  cksum_cmd->cksum = SWAP_LONG(cksum_cmd->cksum);
}


//----------------------------------------------------------------------
static void swap_uuid_command(struct uuid_command *uuid_cmd)
{
  uuid_cmd->cmd = swap32(uuid_cmd->cmd);
  uuid_cmd->cmdsize = swap32(uuid_cmd->cmdsize);
}

//--------------------------------------------------------------------------
local void swap_linkedit_data_command(struct linkedit_data_command *ld)
{
  ld->cmd = swap32(ld->cmd);
  ld->cmdsize = swap32(ld->cmdsize);
  ld->dataoff = swap32(ld->dataoff);
  ld->datasize = swap32(ld->datasize);
}

//--------------------------------------------------------------------------
local void swap_rpath_command(struct rpath_command *rpath_cmd)
{
  rpath_cmd->cmd = swap32(rpath_cmd->cmd);
  rpath_cmd->cmdsize = swap32(rpath_cmd->cmdsize);
  rpath_cmd->path.offset = swap32(rpath_cmd->path.offset);
}

//--------------------------------------------------------------------------
local void swap_encryption_info_command(struct encryption_info_command *ec)
{
  ec->cmd = swap32(ec->cmd);
  ec->cmdsize = swap32(ec->cmdsize);
  ec->cryptoff = swap32(ec->cryptoff);
  ec->cryptsize = swap32(ec->cryptsize);
  ec->cryptid = swap32(ec->cryptid);
}

//--------------------------------------------------------------------------
local void swap_dyld_info_command(struct dyld_info_command *ed)
{
  ed->cmd = swap32(ed->cmd);
  ed->cmdsize = swap32(ed->cmdsize);
  ed->rebase_off = swap32(ed->rebase_off);
  ed->rebase_size = swap32(ed->rebase_size);
  ed->bind_off = swap32(ed->bind_off);
  ed->bind_size = swap32(ed->bind_size);
  ed->weak_bind_off = swap32(ed->weak_bind_off);
  ed->weak_bind_size = swap32(ed->weak_bind_size);
  ed->lazy_bind_off = swap32(ed->lazy_bind_off);
  ed->lazy_bind_size = swap32(ed->lazy_bind_size);
  ed->export_off = swap32(ed->export_off);
  ed->export_size = swap32(ed->export_size);
}

//--------------------------------------------------------------------------
local void swap_nlist_64(struct nlist_64 *symbols_from, struct nlist_64 *symbols_to, uint32 nsymbols)
{
    uint32 i;
    for(i = 0; i < nsymbols; i++){
        symbols_to[i].n_un.n_strx = SWAP_LONG(symbols_from[i].n_un.n_strx);
        if ( symbols_to != symbols_from )
        {
          symbols_to[i].n_type = symbols_from[i].n_type;
          symbols_to[i].n_sect = symbols_from[i].n_sect;
        }
        symbols_to[i].n_desc = SWAP_SHORT(symbols_from[i].n_desc);
        symbols_to[i].n_value = SWAP_LONG_LONG(symbols_from[i].n_value);
    }
}

//--------------------------------------------------------------------------
local void nlist_to64(const struct nlist *symbols_from, struct nlist_64 *symbols_to, size_t nsymbols, bool swap)
{
  if ( swap )
  {
    for ( size_t i = 0; i < nsymbols; i++ )
    {
      symbols_to[i].n_un.n_strx = SWAP_LONG(symbols_from[i].n_un.n_strx);
      symbols_to[i].n_type      = symbols_from[i].n_type;
      symbols_to[i].n_sect      = symbols_from[i].n_sect;
      symbols_to[i].n_desc      = SWAP_SHORT(symbols_from[i].n_desc);
      symbols_to[i].n_value     = SWAP_LONG(symbols_from[i].n_value);
    }
  }
  else
  {
    for ( size_t i = 0; i < nsymbols; i++ )
    {
      symbols_to[i].n_un.n_strx = symbols_from[i].n_un.n_strx;
      symbols_to[i].n_type      = symbols_from[i].n_type;
      symbols_to[i].n_sect      = symbols_from[i].n_sect;
      symbols_to[i].n_desc      = symbols_from[i].n_desc;
      symbols_to[i].n_value     = symbols_from[i].n_value;
    }
  }
}

//--------------------------------------------------------------------------
local void swap_dylib_module_64(struct dylib_module_64 *mods, uint32 nmods)
{
    uint32 i;
        for(i = 0; i < nmods; i++){
            mods[i].module_name = SWAP_LONG(mods[i].module_name);
            mods[i].iextdefsym  = SWAP_LONG(mods[i].iextdefsym);
            mods[i].nextdefsym  = SWAP_LONG(mods[i].nextdefsym);
            mods[i].irefsym     = SWAP_LONG(mods[i].irefsym);
            mods[i].nrefsym     = SWAP_LONG(mods[i].nrefsym);
            mods[i].ilocalsym   = SWAP_LONG(mods[i].ilocalsym);
            mods[i].nlocalsym   = SWAP_LONG(mods[i].nlocalsym);
            mods[i].iextrel     = SWAP_LONG(mods[i].iextrel);
            mods[i].nextrel     = SWAP_LONG(mods[i].nextrel);
            mods[i].iinit_iterm = SWAP_LONG(mods[i].iinit_iterm);
            mods[i].ninit_nterm = SWAP_LONG(mods[i].ninit_nterm);
            mods[i].objc_module_info_size =
                                  SWAP_LONG(mods[i].objc_module_info_size);
            mods[i].objc_module_info_addr =
                                  SWAP_LONG_LONG(mods[i].objc_module_info_addr);
        }
}

//--------------------------------------------------------------------------
local void dylib_module_to64(const struct dylib_module *mods_from, struct dylib_module_64 *mods_to, size_t nmods, bool swap)
{
  if ( swap )
  {
    for ( size_t i = 0; i < nmods; i++ )
    {
      mods_to[i].module_name = SWAP_LONG(mods_from[i].module_name);
      mods_to[i].iextdefsym  = SWAP_LONG(mods_from[i].iextdefsym);
      mods_to[i].nextdefsym  = SWAP_LONG(mods_from[i].nextdefsym);
      mods_to[i].irefsym     = SWAP_LONG(mods_from[i].irefsym);
      mods_to[i].nrefsym     = SWAP_LONG(mods_from[i].nrefsym);
      mods_to[i].ilocalsym   = SWAP_LONG(mods_from[i].ilocalsym);
      mods_to[i].nlocalsym   = SWAP_LONG(mods_from[i].nlocalsym);
      mods_to[i].iextrel     = SWAP_LONG(mods_from[i].iextrel);
      mods_to[i].nextrel     = SWAP_LONG(mods_from[i].nextrel);
      mods_to[i].iinit_iterm = SWAP_LONG(mods_from[i].iinit_iterm);
      mods_to[i].ninit_nterm = SWAP_LONG(mods_from[i].ninit_nterm);
      mods_to[i].objc_module_info_size =
                            SWAP_LONG(mods_from[i].objc_module_info_size);
      mods_to[i].objc_module_info_addr =
                            SWAP_LONG(mods_from[i].objc_module_info_addr);
    }
  }
  else
  {
    for ( size_t i = 0; i < nmods; i++ )
    {
      mods_to[i].module_name = mods_from[i].module_name;
      mods_to[i].iextdefsym  = mods_from[i].iextdefsym;
      mods_to[i].nextdefsym  = mods_from[i].nextdefsym;
      mods_to[i].irefsym     = mods_from[i].irefsym;
      mods_to[i].nrefsym     = mods_from[i].nrefsym;
      mods_to[i].ilocalsym   = mods_from[i].ilocalsym;
      mods_to[i].nlocalsym   = mods_from[i].nlocalsym;
      mods_to[i].iextrel     = mods_from[i].iextrel;
      mods_to[i].nextrel     = mods_from[i].nextrel;
      mods_to[i].iinit_iterm = mods_from[i].iinit_iterm;
      mods_to[i].ninit_nterm = mods_from[i].ninit_nterm;
      mods_to[i].objc_module_info_size =
                            mods_from[i].objc_module_info_size;
      mods_to[i].objc_module_info_addr =
                            mods_from[i].objc_module_info_addr;
    }
  }
}

//--------------------------------------------------------------------------
local void swap_dylib_table_of_contents(struct dylib_table_of_contents *tocs,
                                         uint32 ntocs)
{
    uint32 i;
        for(i = 0; i < ntocs; i++){
            tocs[i].symbol_index = SWAP_LONG(tocs[i].symbol_index);
            tocs[i].module_index = SWAP_LONG(tocs[i].module_index);
        }
}

//--------------------------------------------------------------------------
local void swap_dylib_reference(struct dylib_reference *refs, uint32 nrefs)
{
    struct swapped_dylib_reference {
        union {
            struct {
                uint32
                    flags:8,
                    isym:24;
            } fields;
            uint32 word;
        } u;
    } sref;

    uint32 i;

        for(i = 0; i < nrefs; i++){
            if ( !mf ){
                memcpy(&sref, refs + i, sizeof(struct swapped_dylib_reference));
                sref.u.word = SWAP_LONG(sref.u.word);
                refs[i].flags = sref.u.fields.flags;
                refs[i].isym = sref.u.fields.isym;
            }
            else{
                sref.u.fields.isym = refs[i].isym;
                sref.u.fields.flags = refs[i].flags;
                sref.u.word = SWAP_LONG(sref.u.word);
                memcpy(refs + i, &sref, sizeof(struct swapped_dylib_reference));
            }
        }

}

//--------------------------------------------------------------------------
local void swap_indirect_symbols(uint32 *indirect_symbols,
                                  uint32 nindirect_symbols)
{
    uint32 i;
        for(i = 0; i < nindirect_symbols; i++)
            indirect_symbols[i] = SWAP_LONG(indirect_symbols[i]);
}

//--------------------------------------------------------------------------
local void swap_relocation_info(struct relocation_info *relocs,
                                 uint32 nrelocs)
{
    uint32 i;
    bool to_host_byte_sex, scattered;

    struct swapped_relocation_info {
        int32    r_address;
        union {
            struct {
                unsigned int
                    r_type:4,
                    r_extern:1,
                    r_length:2,
                    r_pcrel:1,
                    r_symbolnum:24;
            } fields;
            uint32 word;
        } u;
    } sr;

    struct swapped_scattered_relocation_info {
        uint32 word;
        int32    r_value;
    } *ssr;

        to_host_byte_sex = mf;

        for(i = 0; i < nrelocs; i++){
            if ( to_host_byte_sex )
                scattered = (bool)(
                        (SWAP_LONG(relocs[i].r_address) & R_SCATTERED) != 0);
            else
                scattered = (bool)
                        (((relocs[i].r_address) & R_SCATTERED) != 0);
            if ( scattered == FALSE ){
                if ( to_host_byte_sex ){
                    memcpy(&sr, relocs + i, sizeof(struct relocation_info));
                    sr.r_address = SWAP_LONG(sr.r_address);
                    sr.u.word = SWAP_LONG(sr.u.word);
                    relocs[i].r_address = sr.r_address;
                    relocs[i].r_symbolnum = sr.u.fields.r_symbolnum;
                    relocs[i].r_pcrel = sr.u.fields.r_pcrel;
                    relocs[i].r_length = sr.u.fields.r_length;
                    relocs[i].r_extern = sr.u.fields.r_extern;
                    relocs[i].r_type = sr.u.fields.r_type;
                }
                else{
                    sr.r_address = relocs[i].r_address;
                    sr.u.fields.r_symbolnum = relocs[i].r_symbolnum;
                    sr.u.fields.r_length = relocs[i].r_length;
                    sr.u.fields.r_pcrel = relocs[i].r_pcrel;
                    sr.u.fields.r_extern = relocs[i].r_extern;
                    sr.u.fields.r_type = relocs[i].r_type;
                    sr.r_address = SWAP_LONG(sr.r_address);
                    sr.u.word = SWAP_LONG(sr.u.word);
                    memcpy(relocs + i, &sr, sizeof(struct relocation_info));
                }
            }
            else{
                ssr = (struct swapped_scattered_relocation_info *)(relocs + i);
                ssr->word = SWAP_LONG(ssr->word);
                ssr->r_value = SWAP_LONG(ssr->r_value);
            }
        }
}

//--------------------------------------------------------------------------
local void swap_fat_header(fat_header *fh)
{
  fh->magic     = swap32(fh->magic);
  fh->nfat_arch = swap32(fh->nfat_arch);
}

//--------------------------------------------------------------------------
local void swap_fat_arch(fat_arch *fa)
{
  fa->cputype    = swap32(fa->cputype);
  fa->cpusubtype = swap32(fa->cpusubtype);
  fa->offset     = swap32(fa->offset);
  fa->size       = swap32(fa->size);
  fa->align      = swap32(fa->align);
}

#define is_magic(a) ( ((a) == MH_MAGIC) || ((a) == MH_MAGIC_64) )
#define is_cigam(a) ( ((a) == MH_CIGAM) || ((a) == MH_CIGAM_64) )

struct segment_command_64 segment_to64(const struct segment_command& sg)
{
  struct segment_command_64 res;
  res.cmd = sg.cmd;
  res.cmdsize = sg.cmdsize;
  memcpy(res.segname, sg.segname, 16);
  res.vmaddr = sg.vmaddr;
  res.vmsize = sg.vmsize;
  res.fileoff = sg.fileoff;
  res.filesize = sg.filesize;
  res.maxprot = sg.maxprot;
  res.initprot = sg.initprot;
  res.nsects = sg.nsects;
  res.flags = sg.flags;
  return res;
}

struct section_64 section_to64(const struct section& sec)
{
  struct section_64 res;
  memcpy(res.sectname, sec.sectname, 16);
  memcpy(res.segname, sec.segname, 16);
  res.addr = sec.addr;
  res.size = sec.size;
  res.offset = sec.offset;
  res.align = sec.align;
  res.reloff = sec.reloff;
  res.nreloc = sec.nreloc;
  res.flags = sec.flags;
  res.reserved1 = sec.reserved1;
  res.reserved2 = sec.reserved2;
  res.reserved3 = 0;
  return res;
}

#ifdef LOADER_COMPILE
//--------------------------------------------------------------------------
static size_t get_cpu_name(cpu_type_t cputype, cpu_subtype_t subtype, char *buf, size_t bufsize)
{
  const char *name;
  const char *subname = "";
  switch ( cputype & ~CPU_ARCH_ABI64 )
  {
    case CPU_TYPE_VAX:     name = "VAX";     break;
    case CPU_TYPE_ROMP:    name = "ROMP";    break;
    case CPU_TYPE_NS32032: name = "NS32032"; break;
    case CPU_TYPE_NS32332: name = "NS32332"; break;
    case CPU_TYPE_VEO:     name = "VEO";     break;
    case CPU_TYPE_MC680x0: name = "MC680x0"; break;
    case CPU_TYPE_MC88000: name = "MC88000"; break;
    case CPU_TYPE_I860:    name = "I860";    break;
    case CPU_TYPE_I386:    name = "I386";    break;
    case CPU_TYPE_POWERPC: name = "POWERPC"; break;
    case CPU_TYPE_HPPA:    name = "HPPA";    break;
    case CPU_TYPE_SPARC:   name = "SPARC";   break;
    case CPU_TYPE_ARM:     name = "ARM";
      switch ( subtype )
      {
        case CPU_SUBTYPE_ARM_A500_ARCH:
        case CPU_SUBTYPE_ARM_A500:
          subname = "500";
          break;
        case CPU_SUBTYPE_ARM_A440:
          subname = "440";
          break;
        case CPU_SUBTYPE_ARM_M4:
          subname = " M4";
          break;
        case CPU_SUBTYPE_ARM_V4T:
          subname = "v4T";
          break;
        case CPU_SUBTYPE_ARM_V6:
          subname = "v6";
          break;
        case CPU_SUBTYPE_ARM_V5TEJ:
          subname = "v5TEJ";
          break;
        case CPU_SUBTYPE_ARM_XSCALE:
          subname = " XScale";
          break;
        case CPU_SUBTYPE_ARM_V7:
          subname = "v7";
          break;
      }
      break;
    default:
      return qsnprintf(buf, bufsize, "%d", cputype);
  }
  if ( cputype & CPU_ARCH_ABI64 )
  {
    switch ( cputype )
    {
      case CPU_TYPE_X86_64:
        name = "X86_64";    break;
      case CPU_TYPE_POWERPC64:
        name = "POWERPC64"; break;
      default:
        return qsnprintf(buf, bufsize, "%s64", name);
    }
  }
  return qsnprintf(buf, bufsize, "%s%s", name, subname);
}
#endif

//--------------------------------------------------------------------------
bool macho_file_t::parse_header()
{
  qlseek(li, start_offset);
  uint32 magic;
  if ( qlread(li, &magic, sizeof(magic)) != sizeof(magic) )
    return false;
  if ( magic == FAT_MAGIC || magic == FAT_CIGAM )
    return parse_fat_header();
  else
    return is_magic(magic) || is_cigam(magic);
}

//--------------------------------------------------------------------------
bool macho_file_t::parse_fat_header()
{
  qlseek(li, start_offset);
  if ( qlread(li, &fheader, sizeof(fheader)) != sizeof(fheader) )
    return false;
  int code = (fheader.magic == FAT_MAGIC);
  if ( fheader.magic == FAT_CIGAM )
  {
    swap_fat_header(&fheader);
    code = 2;
  }
  if ( code == 0 || fheader.nfat_arch > 16 )
    return false;

  uint32 fsize = qlsize(li);
  uint32 archs_size = fheader.nfat_arch*sizeof(fat_arch);
  if ( sizeof(fat_header) + archs_size >= fsize )
    return false;

  fat_archs.resize(fheader.nfat_arch);

  if ( qlread(li, &fat_archs[0], archs_size) != archs_size )
  {
    fat_archs.clear();
    return false;
  }

  for ( uint32_t i=0; i < fheader.nfat_arch; i++ )
  {
    fat_arch *parch = &fat_archs[i];
    if ( code == 2 )
      swap_fat_arch(parch);
    if ( parch->size <= sizeof(mach_header) ||
         parch->size >= fsize ||
         parch->offset < sizeof(fat_header) + archs_size ||
         parch->offset + parch->size > fsize )
    {
      fat_archs.clear();
      return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::get_fat_header(fat_header* fh)
{
  if ( fat_archs.empty() )
    return false;
  *fh = fheader;
  return true;
}
//--------------------------------------------------------------------------
bool macho_file_t::get_fat_arch(uint n, fat_arch *fa)
{
  if ( n >= fat_archs.size() )
  {
    memset(fa, 0, sizeof(*fa));
    return false;
  }
  *fa = fat_archs[n];
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::set_subfile(uint n)
{
  int32 fsize = qlsize(li);
  if ( fsize <= 0 )
    return false;

  if ( n == 0 && fat_archs.size() == 0 )
  {
    mach_offset = 0;
    mach_size   = size_t(fsize);
  }
  else if ( n < fat_archs.size() )
  {
    mach_offset = fat_archs[n].offset;
    mach_size   = fat_archs[n].size;
    if ( mach_offset >= size_t(fsize) )
    {
      msg("Fat subfile %i is outside the file\n", n);
      return false;
    }
    if ( mach_offset + mach_size > size_t(fsize) )
    {
      msg("Fat subfile %i is truncated\n", n);
      mach_size = qlsize(li) - mach_offset;
    }
  }
  else
  {
    return false;
  }

  // clear various cached tables
  mach_header_data.clear();
  load_commands.clear();
  mach_segcmds.clear();
  mach_sections.clear();
  mach_dylibs.clear();
  mach_modtable.clear();
  mach_toc.clear();
  mach_reftable.clear();
  parsed_section_info = false;
  base_addr = BADADDR;

  qlseek(li, mach_offset + start_offset);

  uint32_t magic;
  if ( qlread(li, &magic, sizeof(magic)) != sizeof(magic) )
    return false;

  qlseek(li, -(ssize_t)sizeof(magic), SEEK_CUR);
  mf = is_cigam(magic);
  if ( magic == MH_CIGAM || magic == MH_MAGIC )
  {
    // 32-bit file
    const size_t mh_len = sizeof(mach_header);
    mach_header_data.resize(mh_len);
    if ( qlread(li, &mach_header_data[0], mh_len) != mh_len )
      return false;

    mach_header tmp;
    memcpy(&tmp, &mach_header_data[0], mh_len);
    if ( mf )
      swap_mach_header(&tmp);
    size_t size = mh_len + tmp.sizeofcmds;
    if ( size > mach_size || size < mh_len ) // overflow?
      return false;
    mach_header_data.resize(size);
    if ( qlread(li, &mach_header_data[mh_len], tmp.sizeofcmds) != tmp.sizeofcmds )
    {
      mach_header_data.clear();
      return false;
    }
    memcpy(&mh, &tmp, mh_len);
    mh.reserved = 0;
    m64 = false;
  }
  else if ( magic == MH_CIGAM_64 || magic == MH_MAGIC_64 )
  {
    // 64-bit file
    const size_t mh_len = sizeof(mach_header_64 );
    mach_header_data.resize(mh_len);
    if ( qlread(li, &mach_header_data[0], mh_len) != mh_len )
      return false;

    memcpy(&mh, &mach_header_data[0], mh_len);
    if ( mf )
      swap_mach_header_64(&mh);
    size_t size = mh_len + mh.sizeofcmds;
    if ( size > mach_size || size < mh_len ) // overflow?
      return false;
    mach_header_data.resize(size);
    if ( qlread(li, &mach_header_data[mh_len], mh.sizeofcmds) != mh.sizeofcmds )
    {
      mach_header_data.clear();
      return false;
    }
    m64 = true;
  }
  else
    return false;

  return parse_load_commands();
}

//--------------------------------------------------------------------------
bool macho_file_t::select_subfile(cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
  if ( fat_archs.empty() && set_subfile(0) )
  {
    // single file; check if it matches what we need
    if ( mh.cputype == cputype && (mh.cpusubtype == cpusubtype || cpusubtype == 0) )
      return true;
  }
  for ( size_t i = 0; i < fat_archs.size(); i++ )
  {
    // fat file; enumerate architectures
    const fat_arch &fa = fat_archs[i];
    if ( fa.cputype == cputype
      && (fa.cpusubtype == cpusubtype || cpusubtype == 0)
      && set_subfile(i) )
    {
      if ( mh.cputype == cputype && (mh.cpusubtype == cpusubtype || cpusubtype == 0) )
        return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
const mach_header_64& macho_file_t::get_mach_header()
{
  if ( mach_offset == -1 )
  {
    deb(IDA_DEBUG_LDR, "macho_file_t::get_mach_header: set_subfile() must be called first\n");
    INTERR(20005);
  }
  return mh;
}

//--------------------------------------------------------------------------
bool macho_file_t::parse_load_commands()
{
  struct load_command l;
  const char *begin, *end, *commands_end;
  begin = (const char*)&mach_header_data[0];
  const struct load_command *lc;
  if ( m64 )
    lc = (load_command *)(begin + sizeof(mach_header_64));
  else
    lc = (load_command *)(begin + sizeof(mach_header));

  commands_end = begin + mach_header_data.size();
  begin = (const char*)lc;
  load_commands.clear();
  for ( uint32 i = 0 ; i < mh.ncmds; i++ )
  {
    if ( begin >= commands_end )
    {
      warning("Inconsistent mh.ncmds\n");
      break;
    }
    safecopy(begin, commands_end, &l);
    if ( mf )
      swap_load_command(&l);
    if ( l.cmdsize % sizeof(int32) != 0 )
      msg("load command %u size not a multiple of 4\n", i);
    begin = (const char *)lc;
    end = begin + l.cmdsize;
    if ( end > commands_end )
      msg("load command %u extends past end of load "
          "commands\n", i);
    if ( begin > end )
    {
      warning("load command %u: cmdsize overflow\n", i);
      break;
    }
    if ( l.cmdsize == 0 )
    {
      warning("load command %u size zero (can't advance to next "
             "load commands)\n", i);
      break;
    }
    load_commands.push_back(lc);
    begin = end;
    lc = (struct load_command *)begin;
  }
  if ( commands_end != begin )
    warning("Inconsistent mh.sizeofcmds\n");

  parsed_section_info = false;
  return !load_commands.empty();
}

//--------------------------------------------------------------------------
#define HANDLE_SIMPLE_COMMAND(name)                        \
  {                                                        \
    name##_command cmd##name;                            \
    safecopy(begin, end, &cmd##name );                      \
    if ( mf )                                              \
      swap_##name##_command(&cmd##name );                   \
    result = v.visit_##name (&cmd##name , cmd_begin, end);  \
  }

//--------------------------------------------------------------------------
bool macho_file_t::visit_load_commands(macho_lc_visitor_t &v)
{
  struct load_command l;
  int result = 0;
  const char *begin = (const char*)&mach_header_data[0], *end;
  const char *commands_end = begin + mach_header_data.size();

  for ( size_t i=0; result == 0 && i < load_commands.size(); i++ )
  {
    const struct load_command *lc = load_commands[i];
    l = *lc;
    if ( mf )
      swap_load_command(&l);
    begin = (const char*)lc;
    const char *cmd_begin = begin;
    end = begin + l.cmdsize;
    if ( end > commands_end )
      end = commands_end;
    if ( begin >= end )
    {
      warning("Inconsistency in load commands");
      break;
    }
    result = v.visit_any_load_command(&l, cmd_begin, end);
    if ( result == 2 )
    {
      // don't call specific callback and continue
      result = 0;
      continue;
    }
    else if ( result != 0 )
    {
      // stop enumeration
      break;
    }
    switch ( l.cmd )
    {
      case LC_SEGMENT:
        {
          struct segment_command sg;
          safecopy(begin, end, &sg);
          if ( mf )
            swap_segment_command(&sg);
          result = v.visit_segment(&sg, cmd_begin, end);
          if ( result == 0 && sg.nsects )
          {
            section s;
            for ( size_t j=0; result == 0 && j < sg.nsects; j++ )
            {
              if ( begin >= end )
              {
                warning("Inconsistent number of sections in segment");
                break;
              }
              cmd_begin = begin;
              safecopy(begin, end, &s);
              if ( mf )
                swap_section(&s, 1);
              // ignore sections outside of the segment
              result = v.visit_section(&s, cmd_begin, end);
            }
          }
        }
        break;
      case LC_SEGMENT_64:
        {
          struct segment_command_64 sg;
          safecopy(begin, end, &sg);
          if ( mf )
            swap_segment_command_64(&sg);
          result = v.visit_segment_64(&sg, cmd_begin, end);
          if ( result == 0 && sg.nsects )
          {
            section_64 s;
            for ( size_t j=0; result == 0 && j < sg.nsects; j++ )
            {
              if ( begin >= end )
              {
                warning("Inconsistent number of sections in segment");
                break;
              }
              cmd_begin = begin;
              safecopy(begin, end, &s);
              if ( mf )
                swap_section_64(&s, 1);
              // ignore sections outside of the segment
              result = v.visit_section_64(&s, cmd_begin, end);
            }
          }
        }
        break;
      case LC_SYMTAB:
        HANDLE_SIMPLE_COMMAND(symtab);
        break;
      case LC_SYMSEG:
        HANDLE_SIMPLE_COMMAND(symseg);
        break;
      case LC_THREAD:
      case LC_UNIXTHREAD:
        HANDLE_SIMPLE_COMMAND(thread);
        break;
      case LC_IDFVMLIB:
      case LC_LOADFVMLIB:
        HANDLE_SIMPLE_COMMAND(fvmlib);
        break;
      case LC_IDENT:
        HANDLE_SIMPLE_COMMAND(ident);
        break;
      case LC_FVMFILE:
        HANDLE_SIMPLE_COMMAND(fvmfile);
        break;
      case LC_DYSYMTAB:
        HANDLE_SIMPLE_COMMAND(dysymtab);
        break;
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_ID_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LAZY_LOAD_DYLIB:
        HANDLE_SIMPLE_COMMAND(dylib);
        break;
      case LC_ID_DYLINKER:
      case LC_LOAD_DYLINKER:
        HANDLE_SIMPLE_COMMAND(dylinker);
        break;
      case LC_PREBOUND_DYLIB:
        HANDLE_SIMPLE_COMMAND(prebound_dylib);
        break;
      case LC_ROUTINES:
        HANDLE_SIMPLE_COMMAND(routines);
        break;
      case LC_SUB_FRAMEWORK:
        HANDLE_SIMPLE_COMMAND(sub_framework);
        break;
      case LC_SUB_UMBRELLA:
        HANDLE_SIMPLE_COMMAND(sub_umbrella);
        break;
      case LC_SUB_CLIENT:
        HANDLE_SIMPLE_COMMAND(sub_client);
        break;
      case LC_SUB_LIBRARY:
        HANDLE_SIMPLE_COMMAND(sub_library);
        break;
      case LC_TWOLEVEL_HINTS:
        HANDLE_SIMPLE_COMMAND(twolevel_hints);
        break;
      case LC_PREBIND_CKSUM:
        HANDLE_SIMPLE_COMMAND(prebind_cksum);
        break;
      case LC_ROUTINES_64:
        {
          routines_command_64 rc;
          safecopy(begin, end, &rc);
          if ( mf )
            swap_routines_command_64(&rc);
          result = v.visit_routines_64(&rc, cmd_begin, end);
        }
        break;
      case LC_UUID:
        HANDLE_SIMPLE_COMMAND(uuid);
        break;
      case LC_RPATH:
        HANDLE_SIMPLE_COMMAND(rpath);
        break;
      case LC_CODE_SIGNATURE:
      case LC_SEGMENT_SPLIT_INFO:
        HANDLE_SIMPLE_COMMAND(linkedit_data);
        break;
      case LC_ENCRYPTION_INFO:
        HANDLE_SIMPLE_COMMAND(encryption_info);
        break;
      case LC_DYLD_INFO:
      case LC_DYLD_INFO_ONLY:
        HANDLE_SIMPLE_COMMAND(dyld_info);
        break;
      default:
        result = v.visit_unknown_load_command(&l, cmd_begin, end);
        break;
    }
  }
  return result != 0;
}

//--------------------------------------------------------------------------
void macho_file_t::get_thread_state(const char *&begin, const char *&end)
{
  struct myvisitor: macho_lc_visitor_t
  {
    const char *begin, *end;

    myvisitor(): begin(NULL), end(NULL) {};

    virtual int visit_thread(const struct thread_command *, const char *_begin, const char *_end)
    {
      safeskip(_begin, _end, sizeof(thread_command));
      if ( _begin >= _end )
      {
        // bad command, try to continue
        return 0;
      }
      begin = _begin;
      end = _end;
      // stop enumeration
      return 1;
    }
  };

  myvisitor v;
  visit_load_commands(v);
  begin = v.begin;
  end = v.end;
}

//--------------------------------------------------------------------------
void macho_file_t::parse_section_info()
{
  /*
   * Create an array of section structures in the host byte sex so it
   * can be processed and indexed into directly.
   */

  struct myvisitor: macho_lc_visitor_t
  {
    secvec_t &sections;
    segcmdvec_t &segcmds;
    intvec_t &seg2section;
    bool m64;

    myvisitor(secvec_t &_sections, segcmdvec_t &_segcmds, intvec_t &seg2section_, bool _m64) :
      sections(_sections), segcmds(_segcmds), seg2section(seg2section_), m64(_m64) {};

    virtual int visit_segment(const struct segment_command *sg, const char *, const char *)
    {
      if ( m64 )
        warning("Found a 32-bit segment in 64-bit program, ignoring it");
      else
      {
        segcmds.push_back(segment_to64(*sg));
        seg2section.push_back(sections.size());
      }
      return 0;
    };

    virtual int visit_segment_64(const struct segment_command_64 *sg, const char *, const char *)
    {
      if ( !m64 )
        warning("Found a 64-bit segment in 32-bit program, ignoring it");
      else
      {
        segcmds.push_back(*sg);
        seg2section.push_back(sections.size());
      }
      return 0;
    };

    virtual int visit_section(const struct section *s, const char *, const char *)
    {
      sections.push_back(section_to64(*s));
      return 0;
    };

    virtual int visit_section_64(const struct section_64 *s, const char *, const char *)
    {
      sections.push_back(*s);
      return 0;
    };
  };

  if ( !parsed_section_info )
  {
    mach_sections.clear();
    mach_segcmds.clear();
    seg2section.clear();
    myvisitor v(mach_sections, mach_segcmds, seg2section, m64);
    visit_load_commands(v);
    parsed_section_info = true;
    for ( size_t i = 0; i < mach_segcmds.size(); i++ )
    {
      const segment_command_64 &sg64 = mach_segcmds[i];
      if ( base_addr == BADADDR && sg64.fileoff == 0 && sg64.filesize != 0 )
      {
        base_addr = sg64.vmaddr;
        break;
      }
    }
  }
}

//--------------------------------------------------------------------------
const segcmdvec_t& macho_file_t::get_segcmds()
{
  parse_section_info();
  return mach_segcmds;
}

//--------------------------------------------------------------------------
const secvec_t&    macho_file_t::get_sections()
{
  parse_section_info();
  return mach_sections;
}

// get segment by index
bool macho_file_t::get_segment(size_t segIndex, segment_command_64 *pseg)
{
  parse_section_info();
  if ( segIndex < mach_segcmds.size() )
  {
    if ( pseg != NULL )
      *pseg = mach_segcmds[segIndex];
    return true;
  }
  return false;
}

// get section by segment index and virtual address inside section
bool macho_file_t::get_section(size_t segIndex, uint64_t vaddr, section_64 *psect)
{
  if ( segIndex < seg2section.size() )
  {
    const segment_command_64& seg = mach_segcmds[segIndex];
    for ( size_t i = seg2section[segIndex]; i < seg2section[segIndex] + seg.nsects; i++ )
    {
      const section_64& sect = mach_sections[i];
      if ( (sect.addr <= vaddr) && (vaddr< (sect.addr + sect.size)) )
      {
        if ( psect != NULL )
          *psect = sect;
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
const dyliblist_t& macho_file_t::get_dylib_list()
{
  /*
   * Create an array of section structures in the host byte sex so it
   * can be processed and indexed into directly.
   */

  struct myvisitor: macho_lc_visitor_t
  {
    dyliblist_t &dylibs;

    myvisitor(dyliblist_t &_dylibs): dylibs(_dylibs){};

    virtual int visit_dylib(const struct dylib_command *d, const char *begin, const char *end)
    {
      switch ( d->cmd )
      {
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
        case LC_LAZY_LOAD_DYLIB:
          {
            //sanity check
            int off = d->dylib.name.offset;
            if ( (off < sizeof(*d)) || (off >= end - begin) )
            {
               dylibs.push_back("<bad library name>");
              break;
            }
            qstring dlname(begin+off, end-(begin+off));
            dylibs.push_back(dlname);
          }
          break;
      }
      // continue enumeration
      return 0;
    }
  };

  if ( mach_dylibs.empty() )
  {
    myvisitor v(mach_dylibs);
    visit_load_commands(v);
  }
  return mach_dylibs;
}

//--------------------------------------------------------------------------
const mod_table_t& macho_file_t::get_module_table()
{
  struct dysymtab_command dyst;

  if ( mach_modtable.empty() && get_dyst(&dyst) )
  {
    if ( dyst.modtaboff >= mach_size )
    {
      msg("module table offset is past end of file\n");
    }
    else
    {
      size_t entrysize = (m64 ? sizeof(struct dylib_module_64) : sizeof(struct dylib_module));
      size_t nmods = dyst.nmodtab;
      size_t size = nmods * entrysize;
      if ( dyst.modtaboff + size > mach_size )
      {
        msg("module table extends past end of file\n");
        size = mach_size - dyst.modtaboff;
        nmods = size / entrysize;
      }
      qlseek(li, start_offset + mach_offset + dyst.modtaboff);
      mach_modtable.resize(nmods);
      if ( m64 )
      {
        qlread(li, &mach_modtable[0], size);
        if ( mf )
          swap_dylib_module_64(&mach_modtable[0], nmods);
      }
      else
      {
        qvector<struct dylib_module> mods32;
        mods32.resize(nmods);
        qlread(li, &mods32[0], size);
        dylib_module_to64(&mods32[0], &mach_modtable[0], nmods, mf);
      }
    }
  }
  return mach_modtable;
}

//--------------------------------------------------------------------------
const tocvec_t& macho_file_t::get_toc()
{
  struct dysymtab_command dyst;

  if ( mach_toc.empty() && get_dyst(&dyst) )
  {
    if ( dyst.tocoff >= mach_size )
    {
      msg("table of contents offset is past end of file\n");
    }
    else
    {
      size_t entrysize = sizeof(struct dylib_table_of_contents);
      size_t ntocs = dyst.ntoc;
      size_t size = ntocs * entrysize;
      if ( dyst.tocoff + size > mach_size )
      {
        msg("table of contents table extends past end of file\n");
        size = mach_size - dyst.tocoff;
        ntocs = size / entrysize;
      }
      qlseek(li, start_offset + mach_offset + dyst.tocoff);
      mach_toc.resize(ntocs);
      qlread(li, &mach_toc[0], size);
      if ( mf )
        swap_dylib_table_of_contents(&mach_toc[0], ntocs);
    }
  }
  return mach_toc;
}

//--------------------------------------------------------------------------
const refvec_t& macho_file_t::get_ref_table()
{
  struct dysymtab_command dyst;

  if ( mach_reftable.empty() && get_dyst(&dyst) )
  {
    if ( dyst.extrefsymoff >= mach_size )
    {
      msg("reference table offset is past end of file\n");
    }
    else
    {
      size_t entrysize = sizeof(struct dylib_reference);
      size_t nrefs = dyst.nextrefsyms;
      size_t size = nrefs * entrysize;
      if ( dyst.extrefsymoff + size > mach_size )
      {
        msg("table of contents table extends past end of file\n");
        size = mach_size - dyst.extrefsymoff;
        nrefs = size / entrysize;
      }
      qlseek(li, start_offset + mach_offset + dyst.extrefsymoff);
      mach_reftable.resize(nrefs);
      qlread(li, &mach_reftable[0], size);
      if ( mf )
        swap_dylib_reference(&mach_reftable[0], nrefs);
    }
  }
  return mach_reftable;
}

//--------------------------------------------------------------------------
inline bool is_zeropage(const segment_command_64 &sg)
{
  return sg.vmaddr == 0 && sg.fileoff == 0 && sg.initprot == 0;
}

//--------------------------------------------------------------------------
inline bool is_text_segment(const segment_command_64 &sg)
{
  if ( is_zeropage(sg) )
    return false;
  const char *name = sg.segname;
  for ( int i=0; i < sizeof(sg.segname); i++, name++ )
    if ( *name != '_' )
      break;
  return strnicmp(name, "TEXT", 4) == 0;
}

//--------------------------------------------------------------------------
inline bool is_linkedit_segment(const segment_command_64 &sg)
{
  return strnicmp(sg.segname, SEG_LINKEDIT, sizeof(SEG_LINKEDIT)-1) == 0;
}

//load chunk of data from the linkedit section
bool macho_file_t::load_linkedit_data(uint32 offset, size_t *size, void *buffer, bool in_mem)
{
  if ( *size == 0 )
    return true;

  sval_t linkedit_shift = 0;
  if ( in_mem )
  {
    // calculate shift between linkedit's segment file offset and memory address
    // so that we will seek to the correct address in memory
    for ( size_t i = 0; i < mach_segcmds.size(); i++ )
    {
      const segment_command_64 &sg64 = mach_segcmds[i];
      if ( base_addr == BADADDR && sg64.fileoff == 0 && sg64.filesize != 0 )
        base_addr = sg64.vmaddr;
      else if ( is_linkedit_segment(sg64) && linkedit_shift == 0 )
        linkedit_shift = sval_t(sg64.vmaddr - base_addr - sg64.fileoff);
    }
  }
  if ( offset >= mach_size )
  {
    // outside file
    return false;
  }
  if ( offset + *size > mach_size )
    *size = mach_size - offset;
  if ( *size == 0 )
    return false;
  qlseek(li, start_offset + mach_offset + linkedit_shift + offset);
  *size = qlread(li, buffer, *size);
  return true;
}

//--------------------------------------------------------------------------
void macho_file_t::get_symbol_table_info(nlistvec_t &symbols, qstring &strings, bool in_mem)
{
  struct myvisitor: macho_lc_visitor_t
  {
    struct symtab_command& st;

    myvisitor(struct symtab_command& st_): st(st_) {}

    virtual int visit_symtab(const struct symtab_command *s, const char *, const char *)
    {
      st = *s;
      return 1;
    }
  };

  struct symtab_command st = {0};
  symbols.clear();
  strings.clear();

  myvisitor v(st);
  if ( visit_load_commands(v) )
  {
    if ( st.symoff >= mach_size )
    {
        msg("symbol table offset is past end of file\n");
    }
    else
    {
      size_t size = st.nsyms * (m64 ? sizeof(struct nlist_64) : sizeof(struct nlist));
      size_t nsymbols;
      if ( st.symoff + st.nsyms * sizeof(struct nlist) > mach_size )
      {
        msg("symbol table extends past end of file\n");
        size = mach_size - st.symoff;
        nsymbols = size / (m64 ? sizeof(struct nlist_64) : sizeof(struct nlist));
      }
      else
        nsymbols = st.nsyms;

      symbols.resize(nsymbols);
      if ( m64 )
      {
        load_linkedit_data(st.symoff, &size, &symbols[0], in_mem);
        if ( mf )
          swap_nlist_64(&symbols[0], &symbols[0], nsymbols);
      }
      else
      {
        qvector<struct nlist> syms32;
        syms32.resize(nsymbols);
        load_linkedit_data(st.symoff, &size, &syms32[0], in_mem);
        nlist_to64(&syms32[0], &symbols[0], nsymbols, mf);
      }
    }

    if ( st.stroff >= mach_size )
    {
      msg("string table offset is past end of file\n");
    }
    else
    {
      size_t strings_size;
      if ( st.stroff + st.strsize > mach_size )
      {
        msg("string table extends past end of file\n");
        strings_size = mach_size - st.symoff;
      }
      else
        strings_size = st.strsize;

      strings.resize(strings_size);
      load_linkedit_data(st.stroff, &strings_size, &strings[0]);
    }
  }
}

//--------------------------------------------------------------------------
bool macho_file_t::get_dyst(struct dysymtab_command *dyst)
{
  struct myvisitor: macho_lc_visitor_t
  {
    struct dysymtab_command* dyst;

    myvisitor(struct dysymtab_command* dyst_): dyst(dyst_)
    {
      dyst->cmd = 0;
    };

    virtual int visit_dysymtab(const struct dysymtab_command *s, const char *, const char *)
    {
      *dyst = *s;
      return 1;
    }
  };

  myvisitor v(dyst);
  return visit_load_commands(v);
}

//--------------------------------------------------------------------------
/*
 * get_indirect_symbol_table_info() returns a pointer and the size of the
 * indirect symbol table.  This routine handles the problems related to the
 * file being truncated and only returns valid pointers and sizes that can be
 * used.  This routine will return pointers that are misaligned and it is up to
 * the caller to deal with alignment issues.
 */
void macho_file_t::get_indirect_symbol_table_info(qvector<uint32> &indirect_symbols)
{
  struct dysymtab_command dyst;

  indirect_symbols.clear();

  if ( !get_dyst(&dyst) )
    return;

  if ( dyst.indirectsymoff >= mach_size )
  {
    msg("indirect symbol table offset is past end of file\n");
  }
  else
  {
    size_t size = dyst.nindirectsyms * sizeof(uint32);
    size_t nindirect_symbols = dyst.nindirectsyms;
    if ( dyst.indirectsymoff + size > mach_size )
    {
      msg("indirect symbol table extends past end of file\n");
      size = mach_size - dyst.indirectsymoff;
      nindirect_symbols = size / sizeof(uint32);
    }
    indirect_symbols.resize(nindirect_symbols);
    qlseek(li, start_offset + mach_offset + dyst.indirectsymoff);
    qlread(li, &indirect_symbols[0], size);
    if ( mf )
      swap_indirect_symbols(&indirect_symbols[0], nindirect_symbols);
  }
}

//load array of relocs from file with range checking and endianness swapping
bool macho_file_t::load_relocs(uint32 reloff, uint32 nreloc, relocvec_t &relocs, const char *descr)
{
  relocs.clear();
  if ( nreloc == 0 )
    return false;

  if ( reloff > mach_size )
  {
    warning("offset to %s relocations extends past the end of the file", descr);
    return false;
  }
  size_t size = (nreloc)*sizeof(struct relocation_info);
  if ( reloff + size > mach_size )
  {
    msg("%s relocations extend past the end of file\n", descr);
    size = mach_size - (mach_offset+reloff);
    nreloc = size / sizeof(struct relocation_info);
  }
  relocs.resize(nreloc);
  qlseek(li, start_offset + mach_offset + reloff);
  if ( qlread(li, &relocs[0], size) != size )
  {
    relocs.clear();
    return false;
  }
  if ( mf )
    swap_relocation_info(&relocs[0], nreloc);
  return true;
}

//--------------------------------------------------------------------------
void macho_file_t::visit_relocs(macho_reloc_visitor_t &v)
{

  if ( getenv("IDA_NORELOC") != NULL )
    return;

  struct dysymtab_command dyst;
  ea_t baseea = 0;
/*
  (from Mach-O spec)
 r_address
  In images used by the dynamic linker, this is an offset from the virtual memory address of the
  data of the first segment_command (page 20) that appears in the file (not necessarily the one
  with the lowest address). For images with the MH_SPLIT_SEGS flag set, this is an offset from
  the virtual memory address of data of the first read/write segment_command (page 20).
*/

  //we check for first writable segment if MH_SPLIT_SEGS is set
  //it also seems that x64 uses first-segment base even without that flag set
  bool need_writable = false;
  if ( (mh.flags & MH_SPLIT_SEGS) || mh.cputype == CPU_TYPE_X86_64 )
    need_writable = true;
  for ( size_t i=0; i < mach_segcmds.size(); i++ )
  {
    if ( !need_writable
      || (mach_segcmds[i].initprot & (VM_PROT_WRITE|VM_PROT_READ)) == (VM_PROT_WRITE|VM_PROT_READ) )
    {
      baseea = (ea_t)mach_segcmds[i].vmaddr;
      break;
    }
  }

  relocvec_t relocs;
  uint32 nrelocs;
  if ( get_dyst(&dyst) && dyst.cmd != 0 )
  {
    // External relocation information
    nrelocs = dyst.nextrel;
    if ( nrelocs && load_relocs(dyst.extreloff, nrelocs, relocs, "dynamic external") )
    {
      v.visit_relocs(baseea, relocs, macho_reloc_visitor_t::mach_reloc_external);
    }
    // Local relocation information
    nrelocs = dyst.nlocrel;
    if ( nrelocs && load_relocs(dyst.locreloff, nrelocs, relocs, "dynamic local") )
    {
      v.visit_relocs(baseea, relocs, macho_reloc_visitor_t::mach_reloc_local);
    }
  }

  // Section relocation information
  for ( size_t i = 0 ; i < mach_sections.size(); i++ )
  {
    if ( mach_sections[i].nreloc == 0 )
      continue;

    char name[40];
    qsnprintf(name, sizeof(name), "(%.16s,%.16s)", mach_sections[i].segname, mach_sections[i].sectname);
    nrelocs = mach_sections[i].nreloc;
    if ( nrelocs && load_relocs(mach_sections[i].reloff, nrelocs, relocs, name) )
    {
      v.visit_relocs((ea_t)mach_sections[i].addr, relocs, i);
    }
  }
}

//--------------------------------------------------------------------------
uint64_t macho_file_t::segStartAddress(int segIndex)
{
  segment_command_64 seg;
  if ( !get_segment(segIndex, &seg) )
    return -1;
  return seg.vmaddr;
}

//--------------------------------------------------------------------------
bool macho_file_t::visit_rebase_opcodes(const bytevec_t &data, dyld_info_visitor_t &v)
{
  const uchar *begin = &data[0];
  const uchar *end = begin + data.size();
  const uchar *p = begin;
  bool done = false;
  uint64_t ulebv, ulebv2;
  const int ptrsize = is64() ? 8 : 4;

  int segIndex;
  uint64_t segOffset = 0;
  uchar type = REBASE_TYPE_POINTER;
  uint64_t segStartAddr = BADADDR;

  while ( !done && p < end )
  {
    uchar opcode = *p & REBASE_OPCODE_MASK;
    uchar imm    = *p & REBASE_IMMEDIATE_MASK;
    p++;
    switch ( opcode )
    {
      case REBASE_OPCODE_DONE:
        done = true;
        break;
      case REBASE_OPCODE_SET_TYPE_IMM:
        type = imm;
        break;
      case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        ulebv = unpack_uleb128(&p, end);
        segIndex = imm;
        segOffset = ulebv;
        segStartAddr = segStartAddress(segIndex);
        break;
      case REBASE_OPCODE_ADD_ADDR_ULEB:
        segOffset += unpack_uleb128(&p, end);
        break;
      case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        segOffset += imm * ptrsize;
        break;
      case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        for ( int i = 0; i < imm; i++ )
        {
          v.visit_rebase(uint64_t(segStartAddr + segOffset), type);
          segOffset += ptrsize;
        }
        break;
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        ulebv = unpack_uleb128(&p, end);
        for ( size_t i = 0; i < ulebv; i++ )
        {
          v.visit_rebase(uint64_t(segStartAddr + segOffset), type);
          segOffset += ptrsize;
        }
        break;
      case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        ulebv = unpack_uleb128(&p, end);
        v.visit_rebase(uint64_t(segStartAddr + segOffset), type);
        segOffset += ulebv + ptrsize;
        break;
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        ulebv = unpack_uleb128(&p, end);
        ulebv2 = unpack_uleb128(&p, end);
        for ( size_t i = 0; i < ulebv; i++ )
        {
          v.visit_rebase(uint64_t(segStartAddr + segOffset), type);
          segOffset += ptrsize + ulebv2;
        }
        break;
      default:
        deb(IDA_DEBUG_LDR, "bad opcode %02X in rebase info!\n", opcode);
        return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::visit_bind_opcodes(dyld_info_visitor_t::bind_kind_t bind_kind, const bytevec_t &data, dyld_info_visitor_t &v)
{
  const uchar *begin = &data[0];
  const uchar *end = begin + data.size();
  const uchar *p = begin;
  bool done = false;
  uint64_t skip, count;
  const int ptrsize = is64() ? 8 : 4;

  int segIndex;
  uint64_t segOffset = 0;
  uchar type = BIND_TYPE_POINTER;
  uchar flags = 0;
  int64_t libOrdinal = BIND_SPECIAL_DYLIB_SELF;
  int64_t addend = 0;
  const char *symbolName = NULL;
  uint64_t segStartAddr = BADADDR;

  while ( !done && p < end )
  {
    uchar opcode = *p & BIND_OPCODE_MASK;
    uchar imm    = *p & BIND_IMMEDIATE_MASK;
    p++;
    switch ( opcode )
    {
      case BIND_OPCODE_DONE:
        if ( bind_kind != dyld_info_visitor_t::bind_kind_lazy )
          done = true;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        libOrdinal = imm;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        libOrdinal = unpack_uleb128(&p, end);
        break;
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        // the special ordinals are negative numbers
        if ( imm == 0 )
          libOrdinal = 0;
        else {
          int8_t signExtended = BIND_OPCODE_MASK | imm;
          libOrdinal = signExtended;
        }
        break;
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        flags = imm;
        symbolName = (const char*)p;
        while ( *p != '\0' )
          ++p;
        ++p;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        type = imm;
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        addend = unpack_sleb128(&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        segIndex = imm;
        segOffset = unpack_uleb128(&p, end);
        segStartAddr = segStartAddress(segIndex);
        break;
      case BIND_OPCODE_ADD_ADDR_ULEB:
        skip = unpack_uleb128(&p, end);
        segOffset += skip;
        break;
      case BIND_OPCODE_DO_BIND:
        v.visit_bind(bind_kind, uint64_t(segStartAddr + segOffset), type, flags, libOrdinal, addend, symbolName);
        segOffset += ptrsize;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        skip = unpack_uleb128(&p, end);
        v.visit_bind(bind_kind, uint64_t(segStartAddr + segOffset), type, flags, libOrdinal, addend, symbolName);
        segOffset += skip + ptrsize;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        skip = imm*ptrsize + ptrsize;
        v.visit_bind(bind_kind, uint64_t(segStartAddr + segOffset), type, flags, libOrdinal, addend, symbolName);
        segOffset += skip;
        break;
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        count = unpack_uleb128(&p, end);
        skip = unpack_uleb128(&p, end);
        for ( int i = 0; i < count; i++ )
        {
          v.visit_bind(bind_kind, uint64_t(segStartAddr + segOffset), type, flags, libOrdinal, addend, symbolName);
          segOffset += skip + ptrsize;
        }
        break;
      default:
        printf(": bad opcode!\n");
        return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::processExportNode(const uchar *start, const uchar *p, const uchar *end, char *symname, int symnameoff, size_t symnamelen, dyld_info_visitor_t &v)
{
  if ( symnameoff >= symnamelen || p >= end || p < start )
    return false;
  const uchar terminalSize = unpack_db(&p, end);
  const uchar *children = p + terminalSize;
  if ( terminalSize != 0 )
  {
    uint64_t flags = unpack_uleb128(&p, end);
    uint64_t address = unpack_uleb128(&p, end);
    if ( base_addr != BADADDR )
      address += base_addr;
    v.visit_export(address, uint32(flags), symname);
  }
  const uchar childrenCount = unpack_db(&children, end);
  const uchar* s = children;
  for ( int i=0; i < childrenCount && s < end; ++i )
  {
    int edgeStrLen = 0;
    for ( uchar c = unpack_db(&s, end); c != '\0'; ++edgeStrLen, c = unpack_db(&s, end) )
    {
      if ( symnameoff+edgeStrLen < symnamelen )
        symname[symnameoff+edgeStrLen] = c;
      else
        return false;
    }
    symname[symnameoff+edgeStrLen] = '\0';
    uint32_t childNodeOffset = (uint32_t)unpack_uleb128(&s, end);
    if ( !processExportNode(start, start+childNodeOffset, end, symname, symnameoff+edgeStrLen, symnamelen, v) )
      return false;
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::visit_export_info(const bytevec_t &data, dyld_info_visitor_t &v)
{
  char symname[MAXSTR*2];
  const uchar *begin = &data[0];
  const uchar *end = begin + data.size();
  if ( !processExportNode(begin, begin, end, symname, 0, sizeof(symname), v) )
  {
    warning("Bad information in exports, it will be ignored.");
    return false;
  }
  return true;
}


//--------------------------------------------------------------------------
void macho_file_t::visit_dyld_info(dyld_info_visitor_t &v)
{
  struct myvisitor: macho_lc_visitor_t
  {
    struct dyld_info_command* di;

    myvisitor(struct dyld_info_command *di_): di(di_)
    {
      di->cmd = 0;
    };

    virtual int visit_dyld_info(const struct dyld_info_command *lc, const char *, const char *)
    {
      *di = *lc;
      return 1;
    }
  };

  dyld_info_command di;
  myvisitor vdi(&di);
  if ( visit_load_commands(vdi) )
  {
    bytevec_t data;
    if ( di.rebase_size != 0 )
    {
      data.resize(di.rebase_size);
      size_t newsize = di.rebase_size;
      if ( load_linkedit_data(di.rebase_off, &newsize, &data[0]) && newsize != 0 )
        visit_rebase_opcodes(data, v);
      else
        msg("Error loading dyld rebase info\n");
    }
    if ( di.bind_size != 0 )
    {
      data.resize(di.bind_size);
      size_t newsize = di.bind_size;
      if ( load_linkedit_data(di.bind_off, &newsize, &data[0]) && newsize != 0 )
        visit_bind_opcodes(dyld_info_visitor_t::bind_kind_normal, data, v);
      else
        msg("Error loading dyld bind info\n");
    }
    if ( di.weak_bind_size != 0 )
    {
      data.resize(di.weak_bind_size);
      size_t newsize = di.weak_bind_size;
      if ( load_linkedit_data(di.weak_bind_off, &newsize, &data[0]) && newsize != 0 )
        visit_bind_opcodes(dyld_info_visitor_t::bind_kind_weak, data, v);
      else
        msg("Error loading dyld weak bind info\n");
    }
    if ( di.lazy_bind_size != 0 )
    {
      data.resize(di.lazy_bind_size);
      size_t newsize = di.lazy_bind_size;
      if ( load_linkedit_data(di.lazy_bind_off, &newsize, &data[0]) && newsize != 0 )
        visit_bind_opcodes(dyld_info_visitor_t::bind_kind_lazy, data, v);
      else
        msg("Error loading dyld lazy bind info\n");
    }
    if ( di.export_size != 0 )
    {
      data.resize(di.export_size);
      size_t newsize = di.export_size;
      if ( load_linkedit_data(di.export_off, &newsize, &data[0]) && newsize != 0 )
        visit_export_info(data, v);
      else
        msg("Error loading dyld export info\n");
    }
  }
}

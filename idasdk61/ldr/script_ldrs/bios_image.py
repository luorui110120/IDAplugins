import idaapi
from idc import *

# -----------------------------------------------------------------------
def accept_file(li, n):
    if n > 0:
        return 0

    # we support max 64K images
    if li.size() > 0x10000:    
        return 0

    li.seek(-16, idaapi.SEEK_END);
    if li.get_char() != '\xEA': # jmp?
        return 0;

    li.seek(-2, idaapi.SEEK_END)
    if (ord(li.get_char()) & 0xF0) != 0xF0: # reasonable computer type?
        return 0

    li.seek(-11, idaapi.SEEK_END);
    buf = li.read(9);
    # 06/03/08
    if buf[2] != "/" or buf[5] != "/" or buf[8] != "\x00":
        return 0

    # accept the file
    return {'format': "BIOS Image", 'options': 1}

# -----------------------------------------------------------------------
def load_file(li, neflags, format):
    base  = 0xF000
    start = base << 4;
    size  = li.size();

    AddSeg(start, start+size, base, 0, idaapi.saRelPara, idaapi.scPub);

    # copy bytes to the database
    li.file2base(0, start, start+size, 0)

    # set the entry registers
    SetLongPrm(INF_START_IP, size-16);
    SetLongPrm(INF_START_CS, base);

    return 1

# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    Warning("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
    return 0
from idaapi import *

TYPE_R = 0
TYPE_I = 1

CODE_DEFAULT_BASE = 0x00000
STACK_DEFAULT_BASE = 0xf0000
ERRORS = -1

FL_INDIRECT = 0x000000800  # This is an indirect access (not immediate value)
FL_ABSOLUTE = 1  # absolute: &addr
class DecodingError(Exception):
    pass

class Inst:
    command = 0
    oprand1 = 0
    oprand2 = 0
    oprand3 = 0

class RssbProcessor(processor_t):
    id = 0x8000 + 8888
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    author = "invano"
    psnames = ["rsb"]
    plnames = ["Rssb"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "RSSB",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = ['sp', 'CS', 'DS']

    instruc = instrs = [
        {'name': 'rssb', 'feature': CF_USE1},
        {'name': 'clracc', 'feature': 0},
        {'name': 'clrmem', 'feature': CF_USE1 | CF_CHG1},
        {'name': 'nop', 'feature': 0},
        {'name': 'jmp', 'feature': CF_USE1 | CF_JUMP},
        {'name': 'jmpi', 'feature': CF_USE1 | CF_JUMP},
        {'name': 'jge', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP},
        {'name': 'mov', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'mov_deref_src', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'mov_deref_dst', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'add', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'sub', 'feature': CF_USE1 | CF_USE2 | CF_CHG2 },
        {'name': 'inc', 'feature': CF_USE1 | CF_CHG1 },
        {'name': 'dec', 'feature': CF_USE1 | CF_CHG1 },
    ]

    instruc_end = len(instruc)
    curInst = Inst()
    
    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            print(idx, ins)
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.reg_first_sreg = self.reg_code_sreg = self.reg_ids["CS"]
        self.reg_last_sreg = self.reg_data_sreg = self.reg_ids["DS"]

    def _set_insn_type(self, insn, typ, dtyp):
        insn.type = typ
        insn.dtyp = dtyp

    def _set_insn_near(self, insn, dtyp, addr):
        self._set_insn_type(insn, o_near, dtyp)
        insn.addr = addr

    def _set_insn_mem(self, insn, dtyp, value):
        self._set_insn_type(insn, o_mem, dtyp)
        insn.addr = value
    
    def _set_insn_imm(self, insn, dtyp, value):
        self._set_insn_type(insn, o_imm, dtyp)
        insn.value = value

    def _twos_ca(self, val):
        if val & (1 << 15):
            val = val - (1 << 16)
        return val

    def _read_rssb_op(self, addr):
        a = get_full_word(addr)
        return a
    
    def _read_jmp_ops(self, addr):
        a = get_full_word(addr+2)
        a = self._twos_ca(get_full_word(a*2))*2 + addr + 2*5
        return a
    
    def _read_jmpi_ops(self, addr):
        a = get_full_word(addr+2)
        return a
    
    def _read_mov_ops(self, addr):
        a = get_full_word(addr + 20)
        b = get_full_word(addr + 2)
        return a*2, b*2
    
    def _read_add_ops(self, addr):
        a = get_full_word(addr + 2)
        b = get_full_word(addr + 8)
        return a*2, b*2
    
    def _read_sub_ops(self, addr):
        a = get_full_word(addr + 2)
        b = get_full_word(addr + 14)
        return a*2, b*2
    
    def _read_inc_ops(self, addr):
        a = get_full_word(addr + 8)
        return a*2
    
    def _read_dec_ops(self, addr):
        a = get_full_word(addr + 14)
        return a*2
    
    def _read_mov_deref_dst_ops(self, addr):
        a, b = self._read_add_ops(addr + 2*15*3 + 14)
        return a, b
    
    def _read_mov_deref_src_ops(self, addr):
        a, b = self._read_add_ops(addr + 2*9 + 2*15)
        return a, b
    
    def _read_clrmem_ops(self, addr):
        a = get_full_word(addr + 2)
        return a*2

    def _read_jge_ops(self, addr):
        a = get_full_word(addr + 38)
        b = addr + 2*231 + self._twos_ca(get_full_word(addr+2*95))*2 + 2
        c = addr + 2*217 + self._twos_ca(get_full_word(addr+2*96))*2 + 2
        return a*2, b, c

    NO_LIFT = 0
    LIFT_EASY = 1
    LIFT_HARD = 2
    DO_LIFT = LIFT_EASY

    def _rssb_is_mov(self, addr):
        a1 = self._read_rssb_op(addr)
        a2 = self._read_rssb_op(addr+2)
        a3 = self._read_rssb_op(addr+4)
        a4 = self._read_rssb_op(addr+6)
        a5 = self._read_rssb_op(addr+8)
        a6 = self._read_rssb_op(addr+10)
        a7 = self._read_rssb_op(addr+12)
        a8 = self._read_rssb_op(addr+14)
        a9 = self._read_rssb_op(addr+16)
        a10 = self._read_rssb_op(addr+18)
        a11 = self._read_rssb_op(addr+20)
        a12 = self._read_rssb_op(addr+22)
        a13 = self._read_rssb_op(addr+24)
        a14 = self._read_rssb_op(addr+26)
        a15 = self._read_rssb_op(addr+28)
    
        if a1 == a10 == a15 == 1 and \
           a2 == a8 == a14 and \
           a3 == a5 == a7 == a9 == 0xffff and \
           a4 == a6 == a12 == a13 == 2:
            return True
        return False

    def _rssb_is_add(self, addr):
        a1 = self._read_rssb_op(addr)
        a2 = self._read_rssb_op(addr+2)
        a3 = self._read_rssb_op(addr+4)
        a4 = self._read_rssb_op(addr+6)
        a5 = self._read_rssb_op(addr+8)
        a6 = self._read_rssb_op(addr+10)

        if a1 == a6 == 1 and \
           a3 == a4 == 2 and \
           a2 != a5:
            return True
        return False
    
    def _rssb_is_sub(self, addr):
        a1 = self._read_rssb_op(addr)
        a2 = self._read_rssb_op(addr+2)
        a3 = self._read_rssb_op(addr+4)
        a4 = self._read_rssb_op(addr+6)
        a5 = self._read_rssb_op(addr+8)
        a6 = self._read_rssb_op(addr+10)
        a7 = self._read_rssb_op(addr+12)
        a8 = self._read_rssb_op(addr+14)
        a9 = self._read_rssb_op(addr+16)
        
        if a1 == 1 and \
           a3 == a5 == a7 == a9 and \
           a4 == a6:
            return True
        return False

    
    def _rssb_is_clrmem(self, addr):
        if self._rssb_is_sub(addr):
            a1, b1 = self._read_sub_ops(addr)
            if a1 == b1:
                return True
        return False
    
    def _rssb_is_inc(self, addr):
        if self._rssb_is_add(addr):
            a1, b1 = self._read_add_ops(addr)
            if get_full_word(a1) == 1:
                return True
        return False
    
    def _rssb_is_dec(self, addr):
        if self._rssb_is_sub(addr):
            a1, b1 = self._read_sub_ops(addr)
            if get_full_word(a1) == 1:
                return True
        return False

    def _rssb_is_mov_deref_dst(self, addr):
        if self._rssb_is_mov(addr) and \
           self._rssb_is_mov(addr + 2*15) and \
           self._rssb_is_mov(addr + 2*15*2 + 2*7) and \
           self._rssb_is_add(addr + 2*15*3 + 2*7):
            a1, b1 = self._read_mov_ops(addr)
            a2, b2 = self._read_mov_ops(addr + 2*15)
            a3 = self._read_rssb_op(addr + 2*15*2)
            a4 = self._read_rssb_op(addr + 2*15*2 + 2)
            a5 = self._read_rssb_op(addr + 2*15*2 + 4)
            a6 = self._read_rssb_op(addr + 2*15*2 + 6)
            a7 = self._read_rssb_op(addr + 2*15*2 + 8)
            a8 = self._read_rssb_op(addr + 2*15*2 + 10)
            a9 = self._read_rssb_op(addr + 2*15*2 + 12)
            a10, b10 = self._read_mov_ops(addr + 2*15*2 + 14)
            a11, b11 = self._read_add_ops(addr + 2*15*3 + 14)

            if a1 == a2 == a4*2 == a8*2 == a10 == b11 and \
               b1 == addr+2*15*2+2 and \
               b2 == addr+2*15*2+2*5 and \
               b10 == addr+2*15*3+2*7+8 and \
               a3 == a9 == 1 and \
               a5 == a6 == a7 == 2:
                return True
        return False

    def _rssb_is_mov_deref_src(self, addr):
        if self._rssb_is_mov(addr + 2*9) and \
           self._rssb_is_add(addr + 2*9 + 2*15):
            a1 = self._read_rssb_op(addr)
            a2 = self._read_rssb_op(addr+2)
            a3 = self._read_rssb_op(addr+4)
            a4 = self._read_rssb_op(addr+6)
            a5 = self._read_rssb_op(addr+8)
            a6 = self._read_rssb_op(addr+10)
            a7 = self._read_rssb_op(addr+12)
            a8 = self._read_rssb_op(addr+14)
            a9 = self._read_rssb_op(addr+16)
            a10, b10 = self._read_mov_ops(addr + 18)
            a11, b11 = self._read_add_ops(addr + 18 + 2*15)

            if a1 == 1 and \
               a2*2 == a8*2 == b11 and \
               a3 == a5 == a7 == a9 == 0xffff and \
               a4 == a6 == 2 and \
               a10 == a11 and \
               b10 == addr+2*9+2*15+2:
                return True
        return False
    
    def _rssb_is_jmpi_target(self, addr):
        a1 = self._read_rssb_op(addr)
        a2 = self._read_rssb_op(addr+2)
        a3 = self._read_rssb_op(addr+4)
        a4 = self._read_rssb_op(addr+6)
        a5 = self._read_rssb_op(addr+8)
       
        if a1 == 1 and a3 == 2 and a4 == 2 and a5 == 0:
            return True
        return False

    def _rssb_is_jmpi(self, addr):
        if self._rssb_is_jmpi_target(addr):
            a = self._read_jmp_ops(addr)
            if a == addr+2*5:
                return True
        return False

    def _rssb_is_jmp(self, addr):
        a1 = self._read_rssb_op(addr)
        a2 = self._read_rssb_op(addr+2)
        a3 = self._read_rssb_op(addr+4)
        a4 = self._read_rssb_op(addr+6)
        a5 = self._read_rssb_op(addr+8)
       
        if a1 == 1 and a2*2 == addr+10 and a3 == 2 and a4 == 2 and a5 == 0:
            return True
        return False

    ## Very very very very very fragile. quick&dirty.
    def _rssb_is_jge(self, addr):
        if self._rssb_is_clrmem(addr) and \
           self._rssb_is_clrmem(addr+2*9) and \
           self._rssb_is_dec(addr+2*67) and \
           self._rssb_is_inc(addr+2*102):
            adds = 0
            while True:
                if not self._rssb_is_add(addr+2*115+adds*2*6):
                    break
                adds += 1
            if adds == 15:
                return True
        return False
                    
    def rssb_ana_lift(self, insn):
        if self._rssb_is_jge(insn.ea):
            insn.itype = self.inames["jge"]
            a, b, c = self._read_jge_ops(insn.ea)
            if c != 0xffff:
                self._set_insn_near(insn[2], dt_word, c)
            else:
                self._set_insn_imm(insn[2], dt_word, c)
            if b != 0xffff:
                self._set_insn_near(insn[1], dt_word, b)
            else:
                self._set_insn_imm(insn[1], dt_word, b)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*232
        elif self._rssb_is_mov_deref_dst(insn.ea):
            insn.itype = self.inames["mov_deref_dst"]
            a, b = self._read_mov_deref_dst_ops(insn.ea)
            self._set_insn_mem(insn[1], dt_word, b)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*15*3+14+12 
        elif self._rssb_is_mov_deref_src(insn.ea):
            insn.itype = self.inames["mov_deref_src"]
            a, b = self._read_mov_deref_src_ops(insn.ea)
            self._set_insn_mem(insn[1], dt_word, b)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*9+2*15+2*6
        elif self._rssb_is_mov(insn.ea):
            insn.itype = self.inames["mov"]
            a, b = self._read_mov_ops(insn.ea)
            self._set_insn_mem(insn[1], dt_word, b)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*15
        elif self._rssb_is_inc(insn.ea):
            insn.itype = self.inames["inc"]
            a = self._read_inc_ops(insn.ea)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*6
        elif self._rssb_is_add(insn.ea):
            insn.itype = self.inames["add"]
            a, b = self._read_add_ops(insn.ea)
            self._set_insn_mem(insn[1], dt_word, b)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*6
        elif self._rssb_is_dec(insn.ea):
            insn.itype = self.inames["dec"]
            a = self._read_dec_ops(insn.ea)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*9
        elif self._rssb_is_clrmem(insn.ea):
            insn.itype = self.inames["clrmem"]
            a = self._read_clrmem_ops(insn.ea)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*9
        elif self._rssb_is_sub(insn.ea):
            insn.itype = self.inames["sub"]
            a, b = self._read_sub_ops(insn.ea)
            self._set_insn_mem(insn[1], dt_word, b)
            self._set_insn_mem(insn[0], dt_word, a)
            insn.size = 2*9
        elif self._rssb_is_jmp(insn.ea):
            insn.itype = self.inames["jmp"]
            a = self._read_jmp_ops(insn.ea)
            self._set_insn_near(insn[0], dt_word, a)
            insn.size = 2*5
        elif self._rssb_is_jmpi(insn.ea):
            insn.itype = self.inames["jmpi"]
            print hex(insn.ea), "JUMPI"
            self._set_insn_mem(insn[0], dt_word, 0xffff)
            insn.size = 2*5
        elif self._rssb_is_jmpi_target(insn.ea):
            insn.itype = self.inames["jmpi"]
            print hex(insn.ea), "JUMPI_TARGET"
            a = self._read_jmpi_ops(insn.ea)
            self._set_insn_near(insn[0], dt_word, a)
            insn.size = 2*5
        else:
            self.rssb_ana_nolift(insn)
        return insn.size

    def rssb_ana_nolift(self, insn):
        a = self._read_rssb_op(insn.ea)
        
        if a == 1:
            insn.itype = self.inames["clracc"]
        elif a == 0xffff:
            insn.itype = self.inames["nop"]
        else:
            insn.itype = self.inames["rssb"]
            self._set_insn_mem(insn[0], dt_word, a * 2)
        insn.size = 2
        return insn.size

    def notify_ana(self, insn):
        if self.DO_LIFT == self.LIFT_EASY:
            return self.rssb_ana_lift(insn)
        elif self.DO_LIFT == self.LIFT_HARD:
            return self.rssb_ana_lift_hard(insn)
        else:
            return self.rssb_ana_nolift(insn)

    def _emu_operand(self,op,insn):
        if op.type == o_mem:
            # insn.create_op_data(op.addr, 0, op.dtyp)
            insn.add_dref(op.addr, 0, dr_O| XREF_USER)
        elif op.type == o_near:
            insn.add_cref(op.addr, 0, fl_JN)

    def rssb_emu_lift(self, insn):
        ft = insn.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(insn[0], insn)
        if ft & CF_USE2:
            self._emu_operand(insn[1], insn)
        if ft & CF_USE3:
            self._emu_operand(insn[2], insn)
        if ft & CF_USE4:
            self._emu_operand(insn[3], insn)
        if not ft & CF_STOP and insn.itype != self.inames["jmp"] and \
                                insn.itype != self.inames["jmpi"] and \
                                insn.itype != self.inames["jge"]:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        return True

    def rssb_emu_nolift(self, insn):
        ft = insn.get_canon_feature()
        a = insn[0].addr
        b = insn[1].addr
        if insn[2].type == o_mem:
            c = insn[2].addr
        else:
            c = insn[2].value

        insn.add_dref(a, 0, dr_O | XREF_USER)
        insn.add_dref(b, 0, dr_O | XREF_USER)
        if c != 0:
            if b == a:
                insn.add_cref(c, 0, fl_JN)
            else:
                insn.add_cref(c, 0, fl_JN)
                insn.add_cref(insn.ea + insn.size, 0, fl_F)
        else:
            if not ft & CF_STOP:
                insn.add_cref(insn.ea + insn.size, 0, fl_F)
        return True

    def notify_emu(self, insn):
        if self.DO_LIFT:
            return self.rssb_emu_lift(insn)
        else:
            return self.rssb_emu_nolift(insn)
    
    def notify_out_operand(self, outctx, op):
        if op.type == o_imm:
            outctx.out_value(op, OOFW_IMM)
        elif op.type in [o_near, o_mem]:
            ok = outctx.out_name_expr(op, op.addr, BADADDR)
            if not ok:
                outctx.out_tagon(COLOR_ERROR)
                outctx.out_long(op.addr, 16)
                outctx.out_tagoff(COLOR_ERROR)
        else:
            return False
        return True

    def notify_out_insn(self,outctx):
        insn=outctx.insn
        ft = insn.get_canon_feature()
        outctx.out_mnem()
        if ft & CF_USE1:
            outctx.out_one_operand(0)
        if ft & CF_USE2:
            outctx.out_char(',')
            outctx.out_char(' ')
            outctx.out_one_operand(1)
        if ft & CF_USE3:
            outctx.out_char(',')
            outctx.out_char(' ')
            outctx.out_one_operand(2)
        outctx.flush_outbuf()
        cvar.gl_comm = 1

def PROCESSOR_ENTRY():
    return RssbProcessor()

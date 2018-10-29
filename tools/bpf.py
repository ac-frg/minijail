#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc
import collections
import struct

# The following fields were copied from <linux/bpf_common.h>:

# Instruction classes
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

# LD/LDX fields.
# Size
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10
# Mode
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0

# JMP fields.
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40

# Source
BPF_K = 0x00
BPF_X = 0x08

BPF_MAXINSNS = 4096

# The following fields were copied from <linux/seccomp.h>:

SECCOMP_RET_ALLOW = 0x7fff0000
SECCOMP_RET_KILL = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_TRACE = 0x7ff00000
SECCOMP_RET_MASK = 0xffff0000


def arg_index(index, hi=False):
    offsetof_args = 4 + 4 + 8
    arg_width = 8
    return offsetof_args + arg_width * index + (arg_width // 2) * hi


class SockFilter(
        collections.namedtuple('SockFilter', ['code', 'jt', 'jf', 'k'])):
    """A representation of struct sock_filter."""

    __slots__ = ()

    def encode(self):
        """Return an encoded version of the SockFilter."""
        return struct.pack('HBBI', self.code, self.jt, self.jf, self.k)


class AbstractBlock(abc.ABC):
    """A class that implements the visitor pattern."""

    def __init__(self):
        super().__init__()
        self.offset = None

    @abc.abstractmethod
    def accept(self, visitor):
        pass


class BasicBlock(AbstractBlock):
    """A concrete implementation of AbstractBlock that has been compiled."""

    def __init__(self, instructions):
        super().__init__()
        self._instructions = instructions

    def accept(self, visitor):
        if self.offset is not None:
            return
        self.offset = visitor.visit(self._instructions)

    @property
    def instructions(self):
        return self._instructions

    @property
    def opcodes(self):
        return b''.join(i.encode() for i in self._instructions)

    def simulate(self, arch, syscall_number, *args):
        """Simulate a BPF program with the given arguments."""
        args = (args + (0, ) * (6 - len(args)))[:6]
        input_memory = struct.pack('IIQQQQQQQ', syscall_number, arch, 0, *args)

        register = 0
        program_counter = 0
        cost = 0
        while program_counter < len(self._instructions):
            ins = self._instructions[program_counter]
            program_counter += 1
            cost += 1
            if ins.code == BPF_LD | BPF_W | BPF_ABS:
                register = struct.unpack('I', input_memory[ins.k:ins.k + 4])[0]
            elif ins.code == BPF_JMP | BPF_JA | BPF_K:
                program_counter += ins.k
            elif ins.code == BPF_JMP | BPF_JEQ | BPF_K:
                if register == ins.k:
                    program_counter += ins.jt
                else:
                    program_counter += ins.jf
            elif ins.code == BPF_JMP | BPF_JGT | BPF_K:
                if register > ins.k:
                    program_counter += ins.jt
                else:
                    program_counter += ins.jf
            elif ins.code == BPF_JMP | BPF_JGE | BPF_K:
                if register >= ins.k:
                    program_counter += ins.jt
                else:
                    program_counter += ins.jf
            elif ins.code == BPF_JMP | BPF_JSET | BPF_K:
                if register & ins.k != 0:
                    program_counter += ins.jt
                else:
                    program_counter += ins.jf
            elif ins.code == BPF_RET:
                if ins.k == SECCOMP_RET_KILL:
                    return (cost, 'KILL')
                elif ins.k == SECCOMP_RET_TRAP:
                    return (cost, 'TRAP')
                elif (ins.k & SECCOMP_RET_MASK) == SECCOMP_RET_ERRNO:
                    return (cost, 'ERRNO', ins.k & 0xffff)
                elif ins.k == SECCOMP_RET_TRACE:
                    return (cost, 'TRACE')
                elif ins.k == SECCOMP_RET_ALLOW:
                    return (cost, 'ALLOW')
                else:
                    raise Exception('unknown return %#x' % ins.k)
            else:
                raise Exception('unknown instruction %r' % (ins, ))
        raise Exception('out-of-bounds')


class Allow(BasicBlock):
    """A BasicBlock that unconditionally returns ALLOW."""

    def __init__(self):
        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_ALLOW)])


class Kill(BasicBlock):
    """A BasicBlock that unconditionally returns KILL."""

    def __init__(self):
        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_KILL)])


class Trap(BasicBlock):
    """A BasicBlock that unconditionally returns TRAP."""

    def __init__(self):
        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_TRAP)])


class ReturnErrno(BasicBlock):
    """A BasicBlock that unconditionally returns the specified errno."""

    def __init__(self, errno):
        super().__init__(
            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_ERRNO | errno)])


class ValidateArch(AbstractBlock):
    """An AbstractBlock that validates the architecture."""

    def __init__(self, arch, next_block):
        super().__init__()
        self._arch = arch
        self._next_block = next_block

    def accept(self, visitor):
        if self.offset is not None:
            return
        self._next_block.accept(visitor)
        next_block_distance = visitor.distance(self._next_block)
        instructions = [
            SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
            SockFilter(BPF_JMP | BPF_JEQ | BPF_K, next_block_distance + 1, 0,
                       self._arch),
            SockFilter(BPF_RET, 0, 0, SECCOMP_RET_KILL),
            SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
        ]
        self.offset = visitor.visit(instructions)


class SyscallEntry(AbstractBlock):
    """An abstract block that represents a syscall comparison in a DAG."""

    def __init__(self, syscall_number, jt, jf, *, op=BPF_JEQ):
        super().__init__()
        self._op = op
        self._syscall_number = syscall_number
        self._jt = jt
        self._jf = jf

    def accept(self, visitor):
        if self.offset is not None:
            return

        self._jf.accept(visitor)
        self._jt.accept(visitor)
        jt_distance = visitor.distance(self._jt)
        jf_distance = visitor.distance(self._jf)

        instructions = visitor.jmp_op_32(self._op, self._syscall_number,
                                         jt_distance, jf_distance)
        self.offset = visitor.visit(instructions)


class Atom(AbstractBlock):
    """A BasicBlock that represents an atom (a simple comparison operation)."""

    def __init__(self, arg_index, op, value, jt, jf, *, arch):
        super().__init__()
        if op == '==':
            op = BPF_JEQ
        elif op == '!=':
            op = BPF_JEQ
            jt, jf = jf, jt
        elif op == '>':
            op = BPF_JGT
        elif op == '<=':
            op = BPF_JGT
            jt, jf = jf, jt
        elif op == '>=':
            op = BPF_JGE
        elif op == '<':
            op = BPF_JGE
            jt, jf = jf, jt
        elif op == '&':
            op = BPF_JSET
        elif op == 'in':
            op = BPF_JSET
            # The mask is negated, so the comparison will be true when the
            # argument includes a flag that wasn't listed in the original
            # (non-negated) mask. This would be the failure case, so we switch
            # |jt| and |jf|.
            value = (~value) & ((1 << arch.bits) - 1)
            jt, jf = jf, jt
        else:
            raise Exception('Unknown operator %s' % op)

        self.arg_index = arg_index
        self._op = op
        self._jt = jt
        self._jf = jf
        self._value = value & ((1 << arch.bits) - 1)

    def accept(self, visitor):
        if self.offset is not None:
            return

        self._jf.accept(visitor)
        self._jt.accept(visitor)
        jt_distance = visitor.distance(self._jt)
        jf_distance = visitor.distance(self._jf)

        instructions = visitor.jmp_op(self.arg_index, self._op, self._value,
                                      jt_distance, jf_distance)
        self.offset = visitor.visit(instructions)


class Flattener(object):
    """A visitor that flattens a DAG of Block objects."""

    def __init__(self, *, arch):
        self._bits = arch.bits
        self._instructions = []

    @property
    def result(self):
        return BasicBlock(self._instructions)

    def distance(self, block):
        distance = block.offset + len(self._instructions)
        assert distance >= 0
        return distance

    def load_arg_32(self, index):
        return [
            SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4 + 4 + 8 + 8 * index)
        ]

    def load_arg_64(self, index, hi):
        return [
            SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0,
                       4 + 4 + 8 + 8 * index + 4 * hi)
        ]

    def jmp_op_32(self, op, value, jt_distance, jf_distance):
        if jt_distance < 0x100 and jf_distance < 0x100:
            return [
                SockFilter(BPF_JMP | op | BPF_K, jt_distance, jf_distance,
                           value),
            ]
        if jt_distance + 1 < 0x100:
            return [
                SockFilter(BPF_JMP | op | BPF_K, jt_distance + 1, 0, value),
                SockFilter(BPF_JMP | BPF_JA, 0, 0, jf_distance),
            ]
        if jf_distance + 1 < 0x100:
            return [
                SockFilter(BPF_JMP | op | BPF_K, 0, jf_distance + 1, value),
                SockFilter(BPF_JMP | BPF_JA, 0, 0, jt_distance),
            ]
        return [
            SockFilter(BPF_JMP | op | BPF_K, 0, 1, value),
            SockFilter(BPF_JMP | BPF_JA, 0, 0, jt_distance + 1),
            SockFilter(BPF_JMP | BPF_JA, 0, 0, jf_distance),
        ]

    def jmp_op(self, arg_index, op, value, jt_distance, jf_distance):
        lo = value & 0xFFFFFFFF
        hi = (value >> 32) & 0xFFFFFFFF

        if self._bits == 32:
            return (self.load_arg_32(arg_index) + self.jmp_op_32(
                op, value, jt_distance, jf_distance))
        # Generate the latter part of the instruction in case we need a wide
        # jump target.
        lo_instructions = (self.load_arg_64(arg_index, False) + self.jmp_op_32(
            op, lo, jt_distance, jf_distance))
        if op in (BPF_JGE, BPF_JGT):
            if hi == 0:
                # For > and >=, there is one potential optimization when |hi|
                # is zero.
                return (self.load_arg_64(arg_index, True) + self.jmp_op_32(
                    BPF_JGT, hi, jt_distance + len(lo_instructions), 0) +
                        lo_instructions)
            else:
                lo_instructions = (self.jmp_op_32(
                    BPF_JEQ, hi, 0, jf_distance + len(lo_instructions)) +
                                   lo_instructions)
                return (self.load_arg_64(arg_index, True) + self.jmp_op_32(
                    BPF_JGT, hi, jt_distance + len(lo_instructions), 0) +
                        lo_instructions)
        elif op == BPF_JSET:
            if hi == 0:
                # Special case: |A & 0| will never be True, so jump directly
                # into the |lo| case.
                return lo_instructions
            else:
                return (self.load_arg_64(arg_index, True) + self.jmp_op_32(
                    BPF_JSET, hi, jt_distance + len(lo_instructions), 0) +
                        lo_instructions)
        assert op == BPF_JEQ, op
        return (self.load_arg_64(arg_index, True) + self.jmp_op_32(
            op, hi, 0, jf_distance + len(lo_instructions)) + lo_instructions)

    def visit(self, instructions):
        self._instructions = instructions + self._instructions
        return -len(self._instructions)

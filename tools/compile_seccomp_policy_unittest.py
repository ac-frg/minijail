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
"""Unittests for the compile_seccomp_policy module."""

from __future__ import print_function

import os.path
import shutil
import tempfile
import unittest

import arch
import bpf
import compile_seccomp_policy

ARCH_64 = arch.Arch(
    arch_nr=0xDEADBEEF,
    bits=64,
    syscalls={
        'read': 0,
        'write': 1,
    },
    constants={
        'O_RDONLY': 0,
        'PROT_WRITE': 2,
        'PROT_EXEC': 4,
    },
)


class ParseConstantTests(unittest.TestCase):
    """Tests for PolicyCompiler.parse_constant."""

    def setUp(self):
        self.arch = ARCH_64
        self.compiler = compile_seccomp_policy.PolicyCompiler(self.arch)

    def test_parse_constant_unsigned(self):
        """Accept reasonably-sized unsigned constants."""
        self.assertEqual(
            self.compiler.parse_constant(['0x80000000']), 0x80000000)
        if self.arch.bits == 64:
            self.assertEqual(
                self.compiler.parse_constant(['0x8000000000000000']),
                0x8000000000000000)

    def test_parse_constant_unsigned_too_big(self):
        """Reject unreasonably-sized unsigned constants."""
        if self.arch.bits == 32:
            with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                        'unsigned overflow'):
                self.compiler.parse_constant(['0x100000000'])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'unsigned overflow'):
            self.compiler.parse_constant(['0x10000000000000000'])

    def test_parse_constant_signed(self):
        """Accept reasonably-sized signed constants."""
        self.assertEqual(
            self.compiler.parse_constant(['-1']), ((1 << self.arch.bits) - 1))

    def test_parse_constant_signed_too_negative(self):
        """Reject unreasonably-sized signed constants."""
        if self.arch.bits == 32:
            with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                        'signed underflow'):
                self.compiler.parse_constant(['-0x800000001'])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'signed underflow'):
            self.compiler.parse_constant(['-0x8000000000000001'])

    def test_parse_mask(self):
        """Accept parsing a mask value."""
        self.assertEqual(
            self.compiler.parse_constant(
                ['0x1', '|', '0x2', '|', '0x4', '|', '0x8']), 0xf)

    def test_parse_negation(self):
        """Accept negating constants."""
        self.assertEqual(
            self.compiler.parse_constant(['~', '0']),
            ((1 << self.arch.bits) - 1))
        self.assertEqual(
            self.compiler.parse_constant(['~', '0', '|', '~', '0']),
            ((1 << self.arch.bits) - 1))

    def test_parse_double_negation(self):
        """Reject double-negating constants."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'double negation'):
            self.compiler.parse_constant(['~', '~', '0'])

    def test_parse_empty_negation(self):
        """Reject negating nothing."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'empty negation'):
            self.compiler.parse_constant(['0', '|', '~'])

    def test_parse_named_constant(self):
        """Accept parsing a named constant."""
        self.assertEqual(self.compiler.parse_constant(['O_RDONLY']), 0)

    def test_parse_empty_constant(self):
        """Reject parsing nothing."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'empty constant'):
            self.compiler.parse_constant([])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'empty constant'):
            self.compiler.parse_constant(['0', '|'])

    def test_parse_constant_with_trailing_tokens(self):
        """Reject parsing constants with trailing garbage."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'extra tokens after constant: "0"'):
            self.compiler.parse_constant(['0', '0'])


class ParsePolicyLineTests(unittest.TestCase):
    """Tests for PolicyCompiler.parse_policy_line."""

    def setUp(self):
        self.arch = ARCH_64
        self.compiler = compile_seccomp_policy.PolicyCompiler(self.arch)

    def test_parse_empty_line(self):
        """Reject empty / malformed lines."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'malformed policy line, missing ":"'):
            self.compiler.parse_policy_line([])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'malformed policy line, missing ":"'):
            self.compiler.parse_policy_line(['read'])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'empty policy line'):
            self.compiler.parse_policy_line(['read', ':'])

    def test_nonexistent_syscall_name(self):
        """Reject nonexistent syscall names."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'nonexistent syscall'):
            self.compiler.parse_policy_line(['nonexistent', ':', '1'])

    def test_no_comparison(self):
        """Reject lines with no comparison."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid atom'):
            self.compiler.parse_policy_line(['read', ':', 'arg0'])

    def test_no_constant(self):
        """Reject lines with no constant."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid atom'):
            self.compiler.parse_policy_line(['read', ':', 'arg0', '=='])

    def test_invalid_arg_token(self):
        """Reject lines with a bad arg token."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid argument token: "org0"'):
            self.compiler.parse_policy_line(['read', ':', 'org0', '==', '0'])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid argument index: "nn"'):
            self.compiler.parse_policy_line(['read', ':', 'argnn', '==', '0'])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid argument index: "0n"'):
            self.compiler.parse_policy_line(['read', ':', 'arg0n', '==', '0'])

    def test_invalid_operator(self):
        """Reject lines with a bad operator."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid operator: "invalidop"'):
            self.compiler.parse_policy_line(
                ['read', ':', 'arg0', 'invalidop', '0'])

    def test_invalid_constant(self):
        """Reject lines with a bad constant."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid constant: "INVALIDCONSTANT"'):
            self.compiler.parse_policy_line(
                ['read', ':', 'arg0', '==', 'INVALIDCONSTANT'])

    def test_extra_tokens(self):
        """Reject lines with extra tokens."""
        with self.assertRaisesRegex(
                compile_seccomp_policy.ParseException,
                'extra tokens after constant: "EXTRATOKEN"'):
            self.compiler.parse_policy_line(
                ['read', ':', 'arg0', '==', '0', 'EXTRATOKEN'])

    def test_allow(self):
        """Accept lines where the syscall is accepted unconditionally."""
        block = self.compiler.parse_policy_line(['read', ':', '1'])
        self.assertEqual(block.filter, None)
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1], 'ALLOW')

    def test_arg0_eq_generated_code(self):
        """Accept lines with an argument filter with ==."""
        block = self.compiler.parse_policy_line(
            ['read', ':', 'arg0', '==', '0x100'])
        # It might be a bit brittle to check the generated code in each test
        # case instead of just the behavior, but there should be at least one
        # test where this happens.
        self.assertEqual(
            block.filter.instructions,
            [
                bpf.SockFilter(bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS, 0, 0,
                               bpf.arg_index(0, True)),
                # Jump to KILL if the high word does not match.
                bpf.SockFilter(bpf.BPF_JMP | bpf.BPF_JEQ | bpf.BPF_K, 0, 2, 0),
                bpf.SockFilter(bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS, 0, 0,
                               bpf.arg_index(0, False)),
                # Jump to KILL if the low word does not match.
                bpf.SockFilter(bpf.BPF_JMP | bpf.BPF_JEQ | bpf.BPF_K, 1, 0,
                               0x100),
                bpf.SockFilter(bpf.BPF_RET, 0, 0, bpf.SECCOMP_RET_KILL),
                bpf.SockFilter(bpf.BPF_RET, 0, 0, bpf.SECCOMP_RET_ALLOW),
            ])

    def test_arg0_comparison_operators(self):
        """Accept lines with an argument filter with comparison operators."""
        biases = (-1, 0, 1)
        # For each operator, store the expectations of simulating the program
        # against the constant plus each entry from the |biases| array.
        cases = (
            ('==', ('KILL', 'ALLOW', 'KILL')),
            ('!=', ('ALLOW', 'KILL', 'ALLOW')),
            ('<', ('ALLOW', 'KILL', 'KILL')),
            ('<=', ('ALLOW', 'ALLOW', 'KILL')),
            ('>', ('KILL', 'KILL', 'ALLOW')),
            ('>=', ('KILL', 'ALLOW', 'ALLOW')),
        )
        for operator, expectations in cases:
            block = self.compiler.parse_policy_line(
                ['read', ':', 'arg0', operator, '0x100'])

            # Check the filter's behavior.
            for bias, expectation in zip(biases, expectations):
                self.assertEqual(
                    block.simulate(self.arch.arch_nr,
                                   self.arch.syscalls['read'],
                                   0x100 + bias)[1], expectation)

    def test_arg0_mask_operator(self):
        """Accept lines with an argument filter with &."""
        block = self.compiler.parse_policy_line(
            ['read', ':', 'arg0', '&', '0x3'])

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'KILL')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           2)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           3)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           4)[1], 'KILL')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           5)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           6)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           7)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           8)[1], 'KILL')

    def test_arg0_in_operator(self):
        """Accept lines with an argument filter with in."""
        block = self.compiler.parse_policy_line(
            ['read', ':', 'arg0', 'in', '0x3'])

        # The 'in' operator only ensures that no bits outside the mask are set,
        # which means that 0 is always allowed.
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           2)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           3)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           4)[1], 'KILL')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           5)[1], 'KILL')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           6)[1], 'KILL')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           7)[1], 'KILL')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           8)[1], 'KILL')

    def test_arg0_short_gt_ge_comparisons(self):
        """Ensure that the short comparison optimization kicks in."""
        if self.arch.bits == 32:
            return
        short_constant_str = '0xdeadbeef'
        short_constant = int(short_constant_str, base=0)
        long_constant_str = '0xbadc0ffee0ddf00d'
        long_constant = int(long_constant_str, base=0)
        biases = (-1, 0, 1)
        # For each operator, store the expectations of simulating the program
        # against the constant plus each entry from the |biases| array.
        cases = (
            ('<', ('ALLOW', 'KILL', 'KILL')),
            ('<=', ('ALLOW', 'ALLOW', 'KILL')),
            ('>', ('KILL', 'KILL', 'ALLOW')),
            ('>=', ('KILL', 'ALLOW', 'ALLOW')),
        )
        for operator, expectations in cases:
            short_block = self.compiler.parse_policy_line(
                ['read', ':', 'arg0', operator, short_constant_str])
            long_block = self.compiler.parse_policy_line(
                ['read', ':', 'arg0', operator, long_constant_str])

            # Check that the emitted code is shorter when the high word of the
            # constant is zero.
            self.assertLess(
                len(short_block.filter.instructions),
                len(long_block.filter.instructions))

            # Check the filter's behavior.
            for bias, expectation in zip(biases, expectations):
                self.assertEqual(
                    long_block.simulate(self.arch.arch_nr,
                                        self.arch.syscalls['read'],
                                        long_constant + bias)[1], expectation)
                self.assertEqual(
                    short_block.simulate(
                        self.arch.arch_nr, self.arch.syscalls['read'],
                        short_constant + bias)[1], expectation)

    def test_and_or(self):
        """Accept lines with a complex expression in DNF."""
        block = self.compiler.parse_policy_line([
            'read', ':', 'arg0', '==', '0', '&&', 'arg1', '==', '0', '||',
            'arg0', '==', '1'
        ])

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 0,
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 0,
                           1)[1], 'KILL')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 1,
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 1,
                           1)[1], 'ALLOW')

    def test_ret_errno(self):
        """Accept lines that return errno."""
        block = self.compiler.parse_policy_line([
            'read', ':', 'arg0', '==', '0', '||', 'arg0', '==', '1', ';',
            'return', '1'
        ])

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1:], ('ERRNO', 1))
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1:], ('ERRNO', 1))
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           2)[1], 'KILL')

    def test_ret_errno_unconditionally(self):
        """Accept lines that return errno unconditionally."""
        block = self.compiler.parse_policy_line(['read', ':', 'return', '1'])

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1:], ('ERRNO', 1))

    def test_invalid_errno(self):
        """Reject lines with an invalid errno value."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid constant: "errno"'):
            self.compiler.parse_policy_line(['read', ':', 'return', 'errno'])

    def test_missing_errno(self):
        """Reject lines with a missing errno value."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'empty constant'):
            self.compiler.parse_policy_line(['read', ':', 'return'])

    def test_empty_attributes(self):
        """Reject lines with empty metadata."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'empty attribute'):
            self.compiler.parse_policy_line(['read', ':', '1', '[', ']'])

    def test_unclosed_attributes(self):
        """Reject lines with unclosed metadata."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'unclosed attribute'):
            self.compiler.parse_policy_line(['read', ':', '1', '['])

    def test_missing_attribute_value(self):
        """Reject lines with missing metadata value."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'missing attribute value for "frequency"'):
            self.compiler.parse_policy_line(
                ['read', ':', '1', '[', 'frequency', '=', ']'])
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'missing attribute value for "frequency"'):
            self.compiler.parse_policy_line(
                ['read', ':', '1', '[', 'frequency', ']'])

    def test_invalid_attributes(self):
        """Reject lines with invalid metadata attribute."""
        with self.assertRaisesRegex(compile_seccomp_policy.ParseException,
                                    'invalid metadata attribute: "invalid"'):
            self.compiler.parse_policy_line(
                ['read', ':', '1', '[', 'invalid', '=', '0', ']'])

    def test_frequency_attribute(self):
        """Accept lines with frequency metadata attribute."""
        block = self.compiler.parse_policy_line(
            ['read', ':', '1', '[', 'frequency', '=', '2', ']'])
        self.assertEqual(block.frequency, 2)

    def test_mmap_write_xor_exec(self):
        """Accept the idiomatic filter for mmap."""
        block = self.compiler.parse_policy_line([
            'read', ':', 'arg0', 'in', '~', 'PROT_WRITE', '||', 'arg0', 'in',
            '~', 'PROT_EXEC'
        ])

        prot_exec_and_write = 6
        for prot in range(0, 0xf):
            if (prot & prot_exec_and_write) == prot_exec_and_write:
                self.assertEqual(
                    block.simulate(self.arch.arch_nr,
                                   self.arch.syscalls['read'], prot)[1],
                    'KILL')
            else:
                self.assertEqual(
                    block.simulate(self.arch.arch_nr,
                                   self.arch.syscalls['read'], prot)[1],
                    'ALLOW')


class CompileFileTests(unittest.TestCase):
    """Tests for PolicyCompiler.compile_file."""

    def setUp(self):
        self.arch = ARCH_64
        self.compiler = compile_seccomp_policy.PolicyCompiler(self.arch)
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_file(self, filename, contents):
        """Helper to write out a file for testing."""
        path = os.path.join(self.tempdir, filename)
        with open(path, 'w') as outf:
            outf.write(contents)
        return path

    def test_compile_linear(self):
        """Reject empty / malformed lines."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            read: 1 [frequency=1]
            write: 1 [frequency=10]
        """)

        program = self.compiler.compile_file(
            path, compile_seccomp_policy.OptimizationStrategy.LINEAR)
        self.assertGreater(
            program.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                             0)[0],
            program.simulate(self.arch.arch_nr, self.arch.syscalls['write'],
                             0)[0],
        )

    def test_compile_bst(self):
        """Reject empty / malformed lines."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            read: 1 [frequency=1]
            write: 1 [frequency=10]
        """)

        program = self.compiler.compile_file(
            path, compile_seccomp_policy.OptimizationStrategy.BST)
        # BST for very few syscalls does not make a lot of sense and does
        # introduce some overhead, so there will be no checking for cost.
        self.assertEqual(
            program.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                             0)[1], 'ALLOW')
        self.assertEqual(
            program.simulate(self.arch.arch_nr, self.arch.syscalls['write'],
                             0)[1], 'ALLOW')


if __name__ == '__main__':
    unittest.main()

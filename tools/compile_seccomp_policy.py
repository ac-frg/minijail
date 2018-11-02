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
"""Helper tool to compile a BPF program from a minijail seccomp filter.

This script will take a Minijail seccomp policy file and compile it into a
BPF program suitable for use with Minijail in the current architecture.
"""

from __future__ import print_function

import argparse
import enum
import re
import sys

import arch
import bpf

# A regex that can tokenizes a Minijail policy file line.
_TOKEN_RE = re.compile(r'(#.*$|@include|[a-zA-Z_0-9./]+|[:;,~()\[\]]|'
                       r'\|\||\||&&|&|==|!=|<|<=|>|>=|=|\w+)')


def split_list(iterable, sep):
    """Return a list of slices of the iterable, using _sep_ as delimiter.

    This behaves like str.split().
    """
    start_index = 0
    for i, element in enumerate(iterable):
        if element == sep:
            yield iterable[start_index:i]
            start_index = i + 1
    yield iterable[start_index:]


class OptimizationStrategy(enum.Enum):
    """The available optimization strategies."""

    # Generate a linear chain of syscall number checks. Works best for policies
    # with very few syscalls.
    LINEAR = 'linear'

    # Generate a binary search tree for the syscalls. Works best for policies
    # with a lot of syscalls, where no one syscall dominates.
    BST = 'bst'

    def __str__(self):
        return self.value


def _convert_to_ranges(entries):
    entries = list(sorted(entries, key=lambda r: r.number))
    lower = 0
    while lower < len(entries):
        upper = lower + 1
        while upper < len(entries):
            if entries[upper - 1].filter != entries[upper].filter:
                break
            if entries[upper - 1].number + 1 != entries[upper].number:
                break
            upper += 1
        yield SyscallPolicyRange(*entries[lower:upper])
        lower = upper


def _compile_single_range(entry,
                          accept_action,
                          reject_action,
                          lower_bound=0,
                          upper_bound=1e99):
    action = accept_action
    if entry.filter:
        action = entry.filter
    if entry.numbers[1] - entry.numbers[0] == 1:
        # Single syscall.
        # Accept if |X == nr|.
        return (1,
                bpf.SyscallEntry(
                    entry.numbers[0], action, reject_action, op=bpf.BPF_JEQ))
    elif entry.numbers[0] == lower_bound:
        # Syscall range aligned with the lower bound.
        # Accept if |X < nr[1]|.
        return (1,
                bpf.SyscallEntry(
                    entry.numbers[1], reject_action, action, op=bpf.BPF_JGE))
    elif entry.numbers[1] == upper_bound:
        # Syscall range aligned with the upper bound.
        # Accept if |X >= nr[0]|.
        return (1,
                bpf.SyscallEntry(
                    entry.numbers[0], action, reject_action, op=bpf.BPF_JGE))
    # Syscall range in the middle.
    # Accept if |nr[0] <= X < nr[1]|.
    upper_entry = bpf.SyscallEntry(
        entry.numbers[1], reject_action, action, op=bpf.BPF_JGE)
    return (2,
            bpf.SyscallEntry(
                entry.numbers[0], upper_entry, reject_action, op=bpf.BPF_JGE))


def _compile_ranges_linear(ranges, accept_action, reject_action):
    # Compiles the list of ranges into a simple linear list of comparisons. In
    # order to make the generated code a bit more efficient, we sort the
    # ranges by frequency, so that the most frequently-called syscalls appear
    # earlier in the chain.
    cost = 0
    accumulated_frequencies = 0
    next_action = reject_action
    for entry in sorted(ranges, key=lambda r: r.frequency):
        current_cost, next_action = _compile_single_range(
            entry, accept_action, next_action)
        accumulated_frequencies += entry.frequency
        cost += accumulated_frequencies * current_cost
    return (cost, next_action)


def _compile_entries_linear(entries, accept_action, reject_action):
    return _compile_ranges_linear(
        _convert_to_ranges(entries), accept_action, reject_action)[1]


def _compile_entries_bst(entries, accept_action, reject_action):
    # Instead of generating a linear list of comparisons, this method generates
    # a binary search tree, where some of the leaves can be linear chains of
    # comparisons.
    #
    # Even though we are going to perform a binary search over the syscall
    # number, we would still like to rotate some of the internal nodes of the
    # binary search tree so that more frequently-used syscalls can be accessed
    # more cheaply (i.e. fewer internal nodes need to be traversed to reach
    # them).
    #
    # This uses Dynamic Programming to generate all possible BSTs efficiently
    # (in O(n^3)) so that we can get the absolute minimum-cost tree that matches
    # all syscall entries. It does so by considering all of the O(n^2) possible
    # sub-intervals, and for each one of those try all of the O(n) partitions of
    # that sub-interval. At each step, it considers putting the remaining
    # entries in a linear comparison chain as well as another BST, and chooses
    # the option that minimizes the total overall cost.
    ranges = list(_convert_to_ranges(entries))

    accumulated = 0
    for entry in ranges:
        accumulated += entry.frequency
        entry.accumulated = accumulated

    # Memoization cache to build the DP table top-down, which is easier to
    # understand.
    memoized_costs = {}

    def _generate_syscall_bst(ranges, indices, bounds=(0, 2**64 - 1)):
        assert bounds[0] <= ranges[indices[0]].numbers[0], (indices, bounds)
        assert ranges[indices[1] - 1].numbers[1] <= bounds[1], (indices,
                                                                bounds)

        if bounds in memoized_costs:
            return memoized_costs[bounds]
        if indices[1] - indices[0] == 1:
            if bounds == ranges[indices[0]].numbers:
                # If bounds are tight around the syscall, it costs nothing.
                memoized_costs[bounds] = (0, ranges[indices[0]].filter
                                          or accept_action)
                return memoized_costs[bounds]
            result = _compile_single_range(ranges[indices[0]], accept_action,
                                           reject_action)
            memoized_costs[bounds] = (result[0] * ranges[indices[0]].frequency,
                                      result[1])
            return memoized_costs[bounds]

        # Try the linear model first and use that as the best estimate so far.
        best_cost = _compile_ranges_linear(ranges[slice(*indices)],
                                           accept_action, reject_action)

        # Now recursively go through all possible partitions of the interval
        # currently being considered.
        previous_accumulated = ranges[indices[0]].accumulated - ranges[indices[0]].frequency
        bst_comparison_cost = (
            ranges[indices[1] - 1].accumulated - previous_accumulated)
        for i, entry in enumerate(ranges[slice(*indices)]):
            candidates = [entry.numbers[0]]
            if i:
                candidates.append(ranges[i - 1 + indices[0]].numbers[1])
            for cutoff_bound in candidates:
                if not bounds[0] < cutoff_bound < bounds[1]:
                    continue
                if not indices[0] < i + indices[0] < indices[1]:
                    continue
                left_subtree = _generate_syscall_bst(
                    ranges, (indices[0], i + indices[0]),
                    (bounds[0], cutoff_bound))
                right_subtree = _generate_syscall_bst(
                    ranges, (i + indices[0], indices[1]),
                    (cutoff_bound, bounds[1]))
                best_cost = min(
                    best_cost,
                    (bst_comparison_cost + left_subtree[0] + right_subtree[0],
                     bpf.SyscallEntry(
                         cutoff_bound,
                         right_subtree[1],
                         left_subtree[1],
                         op=bpf.BPF_JGE)))

        memoized_costs[bounds] = best_cost
        return memoized_costs[bounds]

    return _generate_syscall_bst(ranges, (0, len(ranges)))[1]


class ParseException(Exception):
    """An exception that is raised when parsing fails."""
    pass


class SyscallPolicyEntry:
    """The parsed version of a seccomp policy line."""

    def __init__(self, name, number, frequency):
        self.name = name
        self.number = number
        self.frequency = frequency
        self.filter = None

    def __repr__(self):
        return 'SyscallPolicyEntry<name: %s, number: %d, frequency: %d, filter: %r>' % (
            self.name, self.number, self.frequency, self.filter.instructions
            if self.filter else None)

    def simulate(self, arch, syscall_number, *args):
        """Simulate the policy with the given arguments."""
        if not self.filter:
            return (0, 'ALLOW')
        return self.filter.simulate(arch, syscall_number, *args)


class SyscallPolicyRange:
    """A contiguous range of SyscallPolicyEntries that have the same action."""

    def __init__(self, *entries):
        self.numbers = (entries[0].number, entries[-1].number + 1)
        self.frequency = sum(e.frequency for e in entries)
        self.accumulated = 0
        self.filter = entries[0].filter

    def __repr__(self):
        return 'SyscallPolicyRange<numbers: %r, frequency: %d, filter: %r>' % (
            self.numbers, self.frequency, self.filter.instructions
            if self.filter else None)

    def simulate(self, arch, syscall_number, *args):
        """Simulate the policy with the given arguments."""
        if not self.filter:
            return (0, 'ALLOW')
        return self.filter.simulate(arch, syscall_number, *args)


class ParserState:
    """Stores the state of the Parser to provide better diagnostics."""

    def __init__(self, filename):
        self._filename = filename
        self._line = ''
        self._line_number = 0

    @property
    def line(self):
        """Return the current line being processed."""
        return self._line

    def set_line(self, line):
        """Update the current line being processed."""
        self._line = line
        self._line_number += 1

    def error(self, fmt, *args):
        """Raise a ParserException with the provided message."""
        raise ParseException(
            ('%s(%d): ' + fmt) % ((self._filename, self._line_number) + args))


class PolicyCompiler:
    """A parser for the Minijail seccomp policy file format."""

    def __init__(self, arch):
        self._parser_states = [ParserState("<memory>")]
        self._arch = arch

    @property
    def _parser_state(self):
        return self._parser_states[-1]

    def _parse_include_statement(self, tokens, level):
        if tokens[0] != '@include':
            self._parser_state.error('invalid statement "%s"',
                                     self._parser_state.line)
        if level != 0:
            self._parser_state.error('@include statement nested too deep')
        if len(tokens) != 2:
            self._parser_state.error('invalid include statement "%s"',
                                     self._parser_state.line)
        return self._parse_file(tokens[1], level + 1)

    def _parse_attributes(self, tokens):
        try:
            index = tokens.index('[')
        except ValueError:
            return {}
        if tokens[-1] != ']':
            self._parser_state.error('unclosed attribute expression')
        attribute_tokens = tokens[index + 1:-1]
        del tokens[index:]

        attributes = {}
        for attribute in split_list(attribute_tokens, ';'):
            if not attribute:
                self._parser_state.error('empty attribute')
            if len(attribute) < 3 or attribute[1] != '=':
                self._parser_state.error('missing attribute value for "%s"',
                                         attribute[0])
            if attribute[0] == 'frequency':
                attributes['frequency'] = int(attribute[2])
            else:
                self._parser_state.error('invalid metadata attribute: "%s"',
                                         attribute[0])

        return attributes

    def _parse_single_value(self, token):
        if token in self._arch.constants:
            single_value = self._arch.constants[token]
        else:
            try:
                single_value = int(token, base=0)
            except ValueError:
                self._parser_state.error('invalid constant: "%s"', token)
        if single_value >= (1 << self._arch.bits):
            self._parser_state.error('unsigned overflow: "%s"', token)
        if single_value < 0:
            if single_value < -(1 << (self._arch.bits - 1)):
                self._parser_state.error('signed underflow: "%s"', token)
            single_value &= ((1 << self._arch.bits) - 1)
        return single_value

    def _parse_parenthesized_expression(self, tokens):
        assert tokens[0] == '('
        parens = 1
        tokens.pop(0)
        for i, token in enumerate(tokens):
            if token == '(':
                parens += 1
            elif token == ')':
                parens -= 1
                if parens == 0:
                    paren_slice = tokens[:i]
                    del tokens[:i]
                    return self.parse_constant(paren_slice)

        self._parser_state.error('unclosed parenthesis: "%s"', ''.join(tokens))

    def parse_constant(self, tokens):
        """Try to parse constants separated by pipes.

        Constants can be:

        - A number that can be parsed with int(..., base=0)
        - A named constant expression.
        - A parenthesized, valid constant expression.
        - A valid constant expression prefixed with the unary bitwise
          complement operator ~.
        - A series of valid constant expressions separated by pipes.  Note
          that since |constant_str| is an atom, there can be no spaces
          between the constant and the pipe.

        If there is an error parsing any of the constants, the whole process
        fails.

        |tokens| will have the constants consumed."""

        value = 0
        while tokens:
            negate = False
            if tokens[0] == '~':
                negate = True
                tokens.pop(0)
                if not tokens:
                    self._parser_state.error('empty complement')
                if tokens[0] == '~':
                    self._parser_state.error('invalid double complement')
            if tokens[0] == '(':
                single_value = self._parse_parenthesized_expression(tokens)
            else:
                single_value = self._parse_single_value(tokens[0])
            tokens.pop(0)
            if negate:
                single_value = (~single_value) & ((1 << self._arch.bits) - 1)
            value |= single_value
            if not tokens:
                break
            if tokens[0] != '|':
                self._parser_state.error('extra tokens after constant: "%s"',
                                         ' '.join(tokens))
            tokens.pop(0)
        else:
            self._parser_state.error('empty constant')
        return value

    def _parse_return_statement(self, filter_tokens):
        if filter_tokens.count(';') > 1:
            self._parser_state.error('too many statements in line "%s"',
                                     self._parser_state.line)

        errno_tokens = list(split_list(filter_tokens, ';'))
        if errno_tokens[-1] and errno_tokens[-1][0] == 'return':
            if len(errno_tokens) == 1:
                filter_tokens = []
            else:
                filter_tokens = errno_tokens.pop(0)
            errno = self.parse_constant(errno_tokens[0][1:])
            return bpf.ReturnErrno(errno), filter_tokens
        elif len(errno_tokens) > 1:
            self._parser_state.error(
                'too many non-return statements in line "%s"',
                self._parser_state.line)
        return bpf.Allow(), errno_tokens[0]

    def _parse_dnf_policy_expression(self, filter_tokens, accept_action,
                                     reject_action):
        # The filter policy is already in Disjunctive Normal Form. Since BPF
        # disallows back jumps, we build the basic blocks in reverse order so
        # that all the jump targets are known by the time we need to reference
        # them.

        # The actions taken by the very last comparison.
        false_block = reject_action
        true_block = accept_action
        for conjunctions in list(split_list(filter_tokens, '||'))[::-1]:
            # Once again, this is the jump target of the very last comparison
            # in the conjunction. Given that any conjunction that succeeds
            # should make the whole expression succeed, make the very last
            # comparison jump to the accept action if it succeeds.
            true_block = accept_action
            for atom in list(split_list(conjunctions, '&&'))[::-1]:
                # Each one of the atoms is a list of tokens in the form:
                #
                #  argX <op> <constant>
                if len(atom) < 3:
                    self._parser_state.error('invalid atom: "%s"',
                                             ' '.join(atom))
                if not atom[0].startswith('arg'):
                    self._parser_state.error('invalid argument token: "%s"',
                                             atom[0])
                arg_index = atom[0][3:]
                try:
                    arg_index = int(arg_index)
                except ValueError:
                    self._parser_state.error('invalid argument index: "%s"',
                                             arg_index)
                operator = atom[1]
                if operator not in ('==', '!=', '<', '<=', '>', '>=', '&',
                                    'in'):
                    self._parser_state.error('invalid operator: "%s"',
                                             operator)
                constant = self.parse_constant(atom[2:])
                block = bpf.Atom(arg_index, operator, constant, true_block,
                                 false_block)
                true_block = block
            # The previous list of conjunctions will jump into the head of the
            # current list of disjunctions if any of them fail instead of
            # failing the whole operation.
            false_block = true_block

        # |false_block| should now point to the very first atom. That means
        # that if it still points to |reject_action|, something went terribly,
        # horribly wrong.
        assert false_block != reject_action
        return false_block

    def parse_policy_line(self, tokens):
        """Return a SyscallPolicyEntry from a tokenized line."""
        if len(tokens) < 2 or tokens[1] != ':':
            self._parser_state.error('malformed policy line, missing ":"')
        if len(tokens) < 3:
            self._parser_state.error('empty policy line')

        if tokens[0] not in self._arch.syscalls:
            self._parser_state.error('nonexistent syscall "%s"', tokens[0])

        # Parse and remove attributes from |tokens|.
        attributes = self._parse_attributes(tokens)

        policy_entry = SyscallPolicyEntry(tokens[0],
                                          self._arch.syscalls[tokens[0]],
                                          attributes.get('frequency', 1))

        # Trim the syscall name and colon and just leave the filter part.
        filter_tokens = tokens[2:]

        # Check whether we're unconditionally allowing this syscall.
        if filter_tokens[0] == '1':
            return policy_entry

        # Check whether there's an optional "return <errno>" part.
        accept_action, filter_tokens = self._parse_return_statement(
            filter_tokens)

        if filter_tokens:
            reject_action = bpf.Kill()
            policy_filter = self._parse_dnf_policy_expression(
                filter_tokens, accept_action, reject_action)

            # Lower all Atoms into WideAtoms.
            lowering_visitor = bpf.LoweringVisitor(arch=self._arch)
            policy_filter = lowering_visitor.process(policy_filter)

            # Flatten the IR DAG into a single BasicBlock.
            flattening_visitor = bpf.FlatteningVisitor(arch=self._arch)
            policy_filter.accept(flattening_visitor)
            policy_entry.filter = flattening_visitor.result
        else:
            assert isinstance(accept_action, bpf.BasicBlock)
            policy_entry.filter = accept_action

        return policy_entry

    def _parse_file(self, policy_filename, level):
        self._parser_states.append(ParserState(policy_filename))
        entries = []
        with open(policy_filename) as policy_file:
            for line in policy_file:
                self._parser_state.set_line(line.strip())

                # Split the string into tokens and remove all comments.
                tokens = [
                    token for token in _TOKEN_RE.findall(line)
                    if not token.startswith('#')
                ]

                # Allow empty lines.
                if not tokens:
                    continue

                # Allow @include statements.
                if tokens[0] == '@include':
                    entries.extend(
                        self._parse_include_statement(tokens, level))
                    continue

                # If it's not a comment, or an empty line, or an @include
                # statement, treat |line| as a regular policy line.
                entries.append(self.parse_policy_line(tokens))
        self._parser_states.pop()
        return entries

    def compile_file(self, policy_filename, optimization_strategy):
        """Return a compiled BPF program from the provided policy file."""
        entries = self._parse_file(policy_filename, 0)

        visitor = bpf.FlatteningVisitor(arch=self._arch)
        accept_action = bpf.Allow()
        reject_action = bpf.Kill()
        if optimization_strategy == OptimizationStrategy.BST:
            next_action = _compile_entries_bst(entries, accept_action,
                                               reject_action)
        else:
            next_action = _compile_entries_linear(entries, accept_action,
                                                  reject_action)
        next_action.accept(bpf.ArgFilterForwardingVisitor(visitor))
        reject_action.accept(visitor)
        accept_action.accept(visitor)
        bpf.ValidateArch(next_action).accept(visitor)
        return visitor.result


def parse_args(argv):
    """Return the parsed CLI arguments for this tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--optimization-strategy',
        default=OptimizationStrategy.BST,
        type=OptimizationStrategy,
        choices=list(OptimizationStrategy))
    parser.add_argument('--arch-json', default='constants.json')
    parser.add_argument(
        'policy', help='The seccomp policy.', type=argparse.FileType('r'))
    parser.add_argument(
        'output', help='The BPF program.', type=argparse.FileType('wb'))
    return parser.parse_args(argv)


def main(argv):
    """Main entrypoint."""
    opts = parse_args(argv)
    policy_compiler = PolicyCompiler(arch.load_from_json(opts.arch_json))
    with opts.output as outf:
        outf.write(
            policy_compiler.compile_file(opts.policy.name,
                                         opts.optimization_strategy).opcodes)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

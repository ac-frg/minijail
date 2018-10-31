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
_TOKEN_RE = re.compile(r'(#.*$|@include|[a-zA-Z_0-9./]+|[:;,~\[\]]|'
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


def _compile_entries_linear(entries, accept_action, reject_action, visitor):
    # Compiles the list of entries into a simple linear list of comparisons. In
    # order to make the generated code a bit more efficient, we sort the
    # entries by frequency, so that the most frequently-called syscalls appear
    # earlier in the chain.
    next_action = reject_action
    entries.sort(key=lambda e: -e.frequency)
    for entry in entries[::-1]:
        if entry.filter:
            next_action = bpf.SyscallEntry(entry.number, entry.filter,
                                           next_action)
            entry.filter.accept(visitor)
        else:
            next_action = bpf.SyscallEntry(entry.number, accept_action,
                                           next_action)
    return next_action


def _compile_entries_bst(entries, accept_action, reject_action, visitor):
    # Instead of generating a linear list of comparisons, this method generates
    # a binary search tree.
    #
    # Even though we are going to perform a binary search over the syscall
    # number, we would still like to rotate some of the internal nodes of the
    # binary search tree so that more frequently-used syscalls can be accessed
    # more cheaply (i.e. fewer internal nodes need to be traversed to reach
    # them).
    #
    # The overall idea then is to, at any step, instead of naively partitioning
    # the list of syscalls by the midpoint of the interval, we choose a
    # midpoint that minimizes the difference of the sum of all frequencies
    # between the left and right subtrees. For that, we need to sort the
    # entries by syscall number and keep track of the accumulated frequency of
    # all entries prior to the current one so that we can compue the midpoint
    # efficiently.
    #
    # TODO(lhchavez): There is one further possible optimization, which is to
    # hoist any syscalls that are more frequent than all other syscalls in the
    # BST combined into a linear chain before entering the BST.
    entries.sort(key=lambda e: e.number)
    accumulated = 0
    for entry in entries:
        accumulated += entry.frequency
        entry.accumulated = accumulated

    # Recursively create the internal nodes.
    def _generate_syscall_bst(entries, lower_bound=0, upper_bound=2**64 - 1):
        assert entries
        if len(entries) == 1:
            # This is a single entry, but the interval we are currently
            # considering contains other syscalls that we want to reject. So
            # instead of an internal node, create a leaf node with an equality
            # comparison.
            assert lower_bound < upper_bound
            if entries[0].filter:
                entries[0].filter.accept(visitor)
                return bpf.SyscallEntry(
                    entries[0].number,
                    entries[0].filter,
                    reject_action,
                    op=bpf.BPF_JEQ)
            return bpf.SyscallEntry(
                entries[0].number,
                accept_action,
                reject_action,
                op=bpf.BPF_JEQ)

        # Find the midpoint that minimizes the difference between accumulated
        # costs in the left and right subtrees.
        previous_accumulated = entries[0].accumulated - entries[0].frequency
        last_accumulated = entries[-1].accumulated - previous_accumulated
        best = (1e99, -1)
        for i, entry in enumerate(entries):
            if not i:
                continue
            left_accumulated = entry.accumulated - previous_accumulated
            right_accumulated = last_accumulated - left_accumulated
            best = min(best, (abs(left_accumulated - right_accumulated), i))
        midpoint = best[1]
        assert midpoint >= 1, best

        # Now we build the right and left subtrees independently. If any of the
        # subtrees consist of a single entry _and_ the bounds are tight around
        # that entry (that is, the bounds contain _only_ the syscall we are
        # going to consider), we can avoid emitting a leaf node and instead
        # have the comparison jump directly into the action that would be taken
        # by the entry.
        if entries[midpoint].number == upper_bound:
            if entries[midpoint].filter:
                entries[midpoint].filter.accept(visitor)
                right_subtree = entries[midpoint].filter
            else:
                right_subtree = accept_action
        else:
            right_subtree = _generate_syscall_bst(
                entries[midpoint:], entries[midpoint].number, upper_bound)

        if lower_bound == entries[midpoint].number - 1:
            assert entries[midpoint - 1].number == lower_bound
            if entries[midpoint - 1].filter:
                entries[midpoint - 1].filter.accept(visitor)
                left_subtree = entries[midpoint - 1].filter
            else:
                left_subtree = accept_action
        else:
            left_subtree = _generate_syscall_bst(
                entries[:midpoint], lower_bound, entries[midpoint].number - 1)

        # Finally, now that both subtrees have been generated, we can create
        # the internal node of the binary search tree.
        return bpf.SyscallEntry(
            entries[midpoint].number,
            right_subtree,
            left_subtree,
            op=bpf.BPF_JGE)

    return _generate_syscall_bst(entries)


class ParseException(Exception):
    """An exception that is raised when parsing fails."""
    pass


class SyscallPolicyEntry:
    """The parsed version of a seccomp policy line."""

    def __init__(self, name, number, frequency):
        self.name = name
        self.number = number
        self.frequency = frequency
        self.accumulated = 0
        self.filter = None

    def __repr__(self):
        return '<name: %s, number: %d, frequency: %d, filter: %r>' % (
            self.name, self.number, self.frequency,
            self.filter.instructions if self.filter else None)

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

    def parse_constant(self, tokens):
        """Try to parse constants separated by pipes.

        Constants can be either a named constant defined in the constants
        section of constants.json or a number parsed with int().

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
                    self._parser_state.error('empty negation')
                if tokens[0] == '~':
                    self._parser_state.error('invalid double negation')
            single_value = self._parse_single_value(tokens[0])
            if negate:
                single_value = (~single_value) & ((1 << self._arch.bits) - 1)
            value |= single_value
            tokens.pop(0)
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
                                               reject_action, visitor)
        else:
            next_action = _compile_entries_linear(entries, accept_action,
                                                  reject_action, visitor)
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

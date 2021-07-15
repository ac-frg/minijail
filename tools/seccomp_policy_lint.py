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
"""A linter for the Minijail seccomp policy file."""

import argparse
import re
import sys

def parse_args(argv):
    """Return the parsed CLI arguments for this tool."""
    arg_parser = argparse.ArgumentParser(description=__doc__)
    arg_parser.add_argument(
        '--denylist',
        action='store_true',
        help='Check as a denylist policy rather than the default allowlist.')
    arg_parser.add_argument('policy',
                            help='The seccomp policy.',
                            type=argparse.FileType('r'))
    return arg_parser.parse_args(argv), arg_parser

def check_seccomp_policy(check_file):
    """Fail if the seccomp policy files have dangerous, undocumented syscalls."""
    # The syscalls we have determined are more dangerous and need justification
    # for inclusion in a policy
    DANGEROUS_SYSCALLS = [
          'clone',
          'mount',
          'setns',
          'kill',
          # All types of exec are dangerous
          'exec',
          'bpf',
          'socket',
          'ptrace',
          # TODO(b/193169195): Add argument granularity for the below syscalls
          'prctl',
          'ioctl',
          'mmap',
          'mprotect',
          'mmap2',
    ]

    errors = []
    contains_dangerous_syscall = False
    prev_line_comment = False

    for line_num, line in enumerate(check_file):
        if line[0] == '#':
            prev_line_comment = True
        else:
            for syscall in DANGEROUS_SYSCALLS:
                if re.match('^' + syscall, line):
                    # Dangerous syscalls must be preceded with a comment.
                    contains_dangerous_syscall = True
                    if not prev_line_comment:
                        errors.append('%s, line %s, %s syscall requires a '
                                      'comment on the preceding line' %
                                      (check_file.name, line_num, syscall))
            prev_line_comment = False
            if len(errors) == 5:  # Just show the first 5 errors.
                break
    if contains_dangerous_syscall:
        print('seccomp: %s  contains dangerous syscalls, so requires '
              'review from chromeos-security@' % (check_file.name))
    else:
        print('seccomp: %s does not contain any dangerous syscalls, so '
              'does not require review from chromeos-security@' %
              (check_file.name))

    if errors:
        msg = ('Dangerous syscalls must be preceded by a comment explaining why'
               ' they are necessary:')
        return (msg, errors)

    return None

def main(argv=None):
    """Main entrypoint."""

    if argv is None:
        argv = sys.argv[1:]

    opts, arg_parser = parse_args(argv)

    print("Running seccomp linter on %s" % (opts.policy.name))
    ret = check_seccomp_policy(opts.policy)

    if ret:
        (msg, errors) = ret
        item_prefix = '\n    * '
        formatted_items = item_prefix + item_prefix.join(errors)
        print('* ' + msg + formatted_items)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

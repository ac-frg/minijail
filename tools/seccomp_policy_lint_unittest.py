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
"""Unittests for the seccomp policy linter module."""

import os
import shutil
import tempfile
import unittest

from seccomp_policy_lint import check_seccomp_policy

class CheckSeccompPolicyTests(unittest.TestCase):
    """Tests for check_seccomp_policy."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_file(self, filename, contents):
        """Helper to write out a file for testing."""
        path = os.path.join(self.tempdir, filename)
        with open(path, 'w') as outf:
            outf.write(contents)
        return path

    def test_check_simple(self):
        """Allow simple policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.\n
            read: 0\n
            write: 0\n
        """)


        test_file = open(path, 'r')
        self.assertEqual(check_seccomp_policy(test_file), None)
        test_file.close()

    def test_check_dangerous_comment(self):
        """Allow simple policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.\nclone: 0\n
            write: 0\n
        """)

        test_file = open(path, 'r')
        self.assertEqual(check_seccomp_policy(test_file), None)
        test_file.close()

    def test_check_dangerous_no_comment(self):
        """Allow simple policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.\nmount: 0\n
            clone: 0\n
        """)

        test_file = open(path, 'r')
        exp_out = ('Dangerous syscalls must be preceded by a comment explaining'
                   ' why they are necessary:',
                   ['%s, line 4, clone syscall requires a comment on '
                   'the preceding line' % (test_file.name)])
        self.assertEqual(check_seccomp_policy(test_file), exp_out)
        test_file.close()


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 The Android Open Source Project
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
"""A file that specifies how to install minijail's python-based tool(s)."""

from setuptools import setup

setup(name='minijail',
      version='0.12',
      description='A set of tools for libminijail',
      license='BSD',
      long_description='Tools for use with libminijail',
      author='Minijail Developers',
      author_email='minijail-dev@google.com',
      url='https://google.github.io/minijail/',
      packages=['minijail'],
      package_dir={'minijail': 'tools'},
      entry_points={
          'console_scripts': [
              'compile_seccomp_policy = minijail.compile_seccomp_policy:main',
          ],
      },
)

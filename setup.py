#!/usr/bin/env python3

from setuptools import setup

setup(name='minijail',
      version='0.12',
      description='A set of tools for libminijail',
      license="BSD",
      long_description="Tools for use with libminijail",
      author='Minijail Developers',
      author_email='minijail-dev@google.com',
      url='https://android.googlesource.com/platform/external/minijail/',
      packages=['minijail'],
      package_dir={'minijail': 'tools'},
      entry_points={
          'console_scripts': [
              'compile_seccomp_policy = minijail.compile_seccomp_policy:main',
          ],
      },
)

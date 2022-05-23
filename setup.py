# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""A setuptools based setup module.

See:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
https://github.com/pypa/sampleproject
"""
import setuptools

setuptools.setup(
    python_requires='>=3.10',
    entry_points={
        'console_scripts': [
            'oscg=oscg.cli:main',
        ],
    },
)

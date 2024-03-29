# Copyright 2024 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test suite for linting the project modules and the unit test modules."""
import contextlib
import io
import pathlib
import unittest

import pycodestyle
import pydocstyle
import pyflakes.api

exclude_paths = {'venv'}
max_line_length = 120
pydocstyle_ignore = ['D104', 'D107', 'D203', 'D213']


class BaseTest(unittest.TestCase):
    """Bass class for all test cases."""

    def setUp(self):
        """Set path object to package directory and build list of Python files."""
        self.package_dir = pathlib.Path(__file__).parent.parent

        self.to_check = list()
        for path in self.package_dir.rglob('*.py'):
            if not exclude_paths.intersection(set(path.parts)):
                self.to_check.append(path)


class TestPyCodeStyle(BaseTest):
    """Check formatting of code using pycodestyle linter."""

    def setUp(self):
        """Initialize the test fixture."""
        super().setUp()
        self.style = pycodestyle.StyleGuide(show_source=True, max_line_length=max_line_length)

    def test_pycodestyle(self):
        """Test that code conforms to PEP-8."""
        for path in self.to_check:
            with self.subTest(file=path.relative_to(self.package_dir).as_posix()):
                with contextlib.redirect_stdout(io.StringIO()) as f:
                    errors = self.style.input_file(str(path))
                msg = f.getvalue()

                self.assertIs(errors, 0, f'\n{msg}')


class TestPyDocStyle(BaseTest):
    """Check documentation strings using pydocstyle linter."""

    def setUp(self):
        """Initialize the test fixture."""
        super().setUp()
        self.cc = pydocstyle.checker.ConventionChecker()

    def test_pydocstyle(self):
        """Test that docstrings conform to PEP-257."""
        for path in self.to_check:
            relative_path = path.relative_to(self.package_dir).as_posix()
            with self.subTest(file=relative_path):
                msg = str()
                source = path.read_text()
                try:
                    for error in self.cc.check_source(source, path.name):
                        if error.code not in pydocstyle_ignore:
                            msg += f'\n{error}'
                except pydocstyle.parser.ParseError:
                    self.skipTest(f'Cannot parse file: {relative_path}')

                self.assertFalse(any(msg), msg)


class TestPyflakes(BaseTest):
    """Check source code files for errors using pyflakes linter."""

    def test_pyflakes(self):
        """Test source files for errors."""
        for path in self.to_check:
            with self.subTest(file=path.relative_to(self.package_dir).as_posix()):
                source = path.read_text()
                with contextlib.redirect_stdout(io.StringIO()) as fo:
                    with contextlib.redirect_stderr(io.StringIO()) as fe:
                        errors = pyflakes.api.check(source, path.name)
                msg = fo.getvalue()
                msg += fe.getvalue()

                self.assertIs(errors, 0, f'\n{msg}')


if __name__ == '__main__':
    unittest.main(verbosity=2)

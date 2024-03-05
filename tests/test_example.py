# Copyright 2024 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test for example configuration generator module."""
import base64
import configparser
import io
import pathlib
import unittest

import oscg.example

THIS_DIR = pathlib.Path(__file__).parent


class TestExample(unittest.TestCase):
    """Check the example configuration produced by example.py."""

    def setUp(self):
        """Generate the ConfigParser object."""
        self.oscg_config = oscg.example.generate()

    def test_dict_equal(self):
        """Test that the configutation object returned matches the expected."""
        reference_path = THIS_DIR.joinpath('data').joinpath('ini_example.txt')
        reference_config = configparser.ConfigParser()
        reference_config.read(reference_path)

        self.oscg_config = oscg.example.generate()

        self.assertDictEqual(reference_config._sections, self.oscg_config._sections, 'Dictionaries do not match.')

    def test_files_equal(self):
        """Test that the configutation file written by the ConfigParser object match the expected."""
        reference_path = THIS_DIR.joinpath('data').joinpath('ini_example.txt')
        reference_data = reference_path.read_text()

        self.oscg_config = oscg.example.generate()
        with io.StringIO() as f:
            self.oscg_config.write(f)
            f.seek(0)
            oscg_data = f.read()

        self.assertEqual(reference_data, oscg_data, 'File contents not equal.')

    def test_type(self):
        """Test that a ConfigParser object is returned."""
        self.oscg_config = oscg.example.generate()

        self.assertIsInstance(self.oscg_config, configparser.ConfigParser, 'Example is not a ConfigParser object.')

    def test_example_privkey_invalid(self):
        """Verify that the example server private key is invalid."""
        self.oscg_config = oscg.example.generate()
        key = self.oscg_config['WGB']['server_privkey']
        key_data = base64.b64decode(key)

        self.assertIsNot(len(key_data), 32, 'Key is valid length 32 bytes.')


if __name__ == '__main__':
    unittest.main(verbosity=2)

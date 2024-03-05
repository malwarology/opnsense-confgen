# Copyright 2024 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test config generator utils module."""
import base64
import struct
import unittest

import nacl.public

import oscg.utils


class TestKeyGeneration(unittest.TestCase):
    """Check WireGuard key generation function."""

    def setUp(self):
        """Create a key pair."""
        private, public = oscg.utils._wgkeys()
        self.keypair = {'private': private,
                        'public': public}

    def test_key_lengths(self):
        """Test that a key is 32 bytes."""
        for key_type, key in self.keypair.items():
            with self.subTest(key=key_type):
                key_data = base64.b64decode(key)

                self.assertIs(len(key_data), 32, 'Key is not 32 bytes.')

    def test_key_is_string(self):
        """Test that a key is a string."""
        for key_type, key in self.keypair.items():
            with self.subTest(key=key_type):

                self.assertIsInstance(key, str, 'Key is not a string.')


class TestPublicKeyRecovery(unittest.TestCase):
    """Check if a public key is correctly recovered from a private key."""

    def test_key_string(self):
        """Test that a public key is correctly recovered from a text string format private key."""
        private = 'mNR9EaPCPaJBBaNdYwYX97kBPWAsfZuqKTEIQJhJmUM='
        public = 'GgDbQ4r/Rdz4N/2n5O+tFX09Rx7N4pZTXvoqhMEvtHc='

        pubkey = oscg.utils._wggetpub(private)

        self.assertEqual(pubkey, public, 'Public key recovered does not match expected.')

    def test_key_object(self):
        """Test that a public key is correctly recovered from a private key in object format."""
        private = nacl.public.PrivateKey.generate()
        public = base64.b64encode(bytes(private.public_key)).decode()

        pubkey = oscg.utils._wggetpub(private)

        self.assertEqual(pubkey, public, 'Public key recovered does not match expected.')


class TestMakeISO(unittest.TestCase):
    """Check that the output is an ISO."""

    def test_output_type(self):
        """Test that the output of the function is bytes."""
        iso = oscg.utils.make_iso('DUMMYDATA')

        self.assertIsInstance(iso, bytes, 'Return value not bytes as expected.')

    def test_output_content(self):
        """Test that the output contains the input string."""
        input_string = 'DUMMYDATA'
        iso = oscg.utils.make_iso(input_string)

        self.assertRegex(iso, input_string.encode(), 'Output does not contain input string.')

    def test_output_magic(self):
        """Test that the output has the correct ISO9660 volume descriptor magic number."""
        iso9660 = (1, b'CD001', 1)  # https://en.wikipedia.org/wiki/ISO_9660#Volume_descriptor_set
        iso = oscg.utils.make_iso('DUMMYDATA')
        magic = struct.unpack_from('B5sBx', buffer=iso, offset=0x8000)

        self.assertTupleEqual(magic, iso9660, 'Output volume descriptor magic number is incorrect.')


if __name__ == '__main__':
    unittest.main(verbosity=2)

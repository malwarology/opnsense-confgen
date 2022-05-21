# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Module for utility functions."""
import base64

import nacl.public


def _wggetpub(private):
    """Get a WireGuard public key from a private key."""
    if isinstance(private, str):
        key_bytes = base64.b64decode(private)
        private = nacl.public.PrivateKey(private_key=key_bytes)
    public = base64.b64encode(bytes(private.public_key)).decode()

    return public


def _wgkeys():
    """Generate a WireGuard keypair."""
    private = nacl.public.PrivateKey.generate()

    privkey = base64.b64encode(bytes(private)).decode()
    pubkey = _wggetpub(private)

    return privkey, pubkey

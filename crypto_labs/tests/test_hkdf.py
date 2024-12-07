"""Test case for hkdf module."""

import unittest

# from hashlib import pbkdf2_hmac
from crypto_labs.hkdf import hkdf_extract, hkdf_expand
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class TestHKDF(unittest.TestCase):
    """Test case for HKDF module."""


    def test_hkdf_expand(self):
        """Test that hkdf_extract function returns the expected key."""
        prk = b"pseudorandomkey"
        info=b"makis"

        key = hkdf_expand(prk, info, 5, "sha256")
        self.assertEqual(key, HKDF(hashes.SHA256(), 5, prk, info).derive(info))




    # TODO: add test cases for HKDF
    def test_hkdf(self):
        """Test that hkdf function returns the expected key."""



if __name__ == "__main__":
    unittest.main()

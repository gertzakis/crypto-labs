"""Test case for kdf module."""

import unittest
from hashlib import pbkdf2_hmac

from crypto_labs.pbkdf import pbkdf2


class TestPBKDF(unittest.TestCase):
    """Test case for PBKDF module."""

    def test_pbkdf2(self):
        """Test that pbkdf2 function returns the expected key."""
        password = b"password"
        salt = b"salt"
        iterations = 4096
        key_length = 5
        digest = "sha256"
        key = pbkdf2(password, salt, iterations, key_length, digest)
        expected_key = pbkdf2_hmac(digest, password, salt, iterations, key_length)
        self.assertEqual(key, expected_key)

    def test_pbkdf2_against_rfc_vectors(self):
        """Test that pbkdf2 function returns the expected results based on RFC-6070 test vectors.

        PBKDF2 HMAC-SHA1 Test Vectors: https://datatracker.ietf.org/doc/html/rfc6070.
        """
        test_vectors = [
            (b"password", b"salt", 1, 20),
            (b"password", b"salt", 2, 20),
            (b"password", b"salt", 4096, 20),
            (b"pass\0word", b"sa\0lt", 4096, 16),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                25,
            ),
            # Test vector with 16777216 iterations, takes 2-3min to run
            (
                b"password",
                b"salt",
                16777216,
                20,
            ),
        ]

        expected_results = [
            b"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6",
            b"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57",
            b"\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1",
            b"\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3",
            b"\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38",
            b"\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84",
        ]

        for i, test_vector in enumerate(test_vectors):
            self.assertEqual(pbkdf2(*test_vector, "sha1"), expected_results[i])

    def test_pbkdf2_value_error_on_long_key(self):
        """Test that pbkdf2 raises a ValueError when the derived key length is too long."""
        password = b"password"
        salt = b"salt"
        iterations = 1
        key_length = (2**32 - 1) * 20 + 1  # SHA1 has a digest_size of 20
        digest = "sha1"
        with self.assertRaises(ValueError):
            pbkdf2(password, salt, iterations, key_length, digest)



if __name__ == "__main__":
    unittest.main()

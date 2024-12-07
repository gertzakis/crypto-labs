"""Test case for hkdf module."""

import unittest
import hashlib
# from hashlib import pbkdf2_hmac
from crypto_labs.hkdf import hkdf_extract, hkdf_expand, hkdf_expand_tupou
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes


class TestHKDF(unittest.TestCase):
    """Test case for HKDF module."""

    # def test_hkdf_expand(self):
    #     """Test that hkdf_extract function returns the expected key."""
    #     prk = b"pseudorandomkey"
    #     info = b"makis"

    #     key = hkdf_expand(prk, info, 5, "sha256")
    #     self.assertEqual(key, HKDF(hashes.SHA256(), 5, prk, info).derive(info))

    def hex_to_bytes(self, hex_string):
        return bytes.fromhex(hex_string[2:])

    def test_hkdf_against_rfc_vectors(self):
        """Test that hkdf functions returns the expected results based on RFC-5869 test vectors.

        HKDF Test Vectors: https://datatracker.ietf.org/doc/html/rfc5869.
        """
        test_vectors = [
            {
                "hash": "sha256",
                "ikm": "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "salt": "0x000102030405060708090a0b0c",
                "info": "0xf0f1f2f3f4f5f6f7f8f9",
                "L": 42,
                "PRK": "0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "OKM": "0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            },
            {
                "hash": "sha256",
                "ikm": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                "salt": "0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "info": "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "L": 82,
                "PRK": "0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "OKM": "0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            },
        ]

        for test_vector in test_vectors:
            pseudo_random_key = hkdf_extract(
                salt=self.hex_to_bytes(test_vector["salt"]),
                input_key_material=self.hex_to_bytes(test_vector["ikm"]),
                hash_function=test_vector["hash"],
            )
            output_keying_material = hkdf_expand(
                pseudo_random_key=pseudo_random_key,
                info=self.hex_to_bytes(test_vector["info"]),
                key_length=test_vector["L"],
                hash_function=test_vector["hash"],
            )

            self.assertEqual(pseudo_random_key, self.hex_to_bytes(test_vector["PRK"]))
            self.assertEqual(output_keying_material, self.hex_to_bytes(test_vector["OKM"]))

    # TODO: add test cases for HKDF
    def test_hkdf(self):
        """Test that hkdf function returns the expected key."""


if __name__ == "__main__":
    unittest.main()

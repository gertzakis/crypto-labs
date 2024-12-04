"""Simple implementation of basic HMAC-based Extract-and-Expand Key Derivative Functions (HKDF)."""

import hmac
# import struct


def hkdf_extract(salt: bytes, input_key_material: bytes, hash_function: str) -> bytes:
    """HKDF Extract function that uses HMAC as the pseudorandom function.

    Args:
        salt (bytes): The salt to use for the HMAC function.
        input_key_material (bytes): The input key material to use.
        hash_function (str): The hash function to use.

    Returns:
        bytes: The extracted key.
    """
    # If a salt is not provided, set it to a string of zeros("0").
    # The length of the string should be the length of the hash function's output.
    if not salt:
        hash_length = hmac.new(b"", b"", hash_function).digest_size
        salt = bytes("0" * hash_length, "utf-8")

    # The result of the HMAC function is the extracted key
    return hmac.new(salt, input_key_material, hash_function).digest()


# TODO add HKDF implementation
def hkdf():
    """Have to implement HKDF funciton."""
    # TODO implement HKDF

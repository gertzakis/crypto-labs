"""Simple implementation of Password-Based Key Derivative Functions (PBKDF) for cryptographic purposes."""

import hmac
import struct


def pbkdf2(password: bytes, salt: bytes, count: int, key_length: int, hash_function: str = "sha1") -> bytes:
    """Password-Based Key Derivation Function 2 (PBKDF2) using HMAC as the pseudorandom function.

    Args:
        password (bytes): The password to derive the key from.
        salt (bytes): A salt to make the derived key unique.
        count (int): The number of iterations to perform.
        key_length (int): The length of the derived key.
        hash_function (str): The hash function to use. By default it uses SHA-1.

    Returns:
        bytes: The derived key.
    """
    derived_key = b""
    block_number = 1
    hash_length = hmac.new(b"", b"", hash_function).digest_size

    # Check if the derived key's expected length is too long based on RFC 2898
    if key_length > (2**32 - 1) * hash_length:
        raise ValueError("Derived key too long")

    # While the derivative key length is less than the desired key length
    while len(derived_key) < key_length:
        # For the first iteration of the HMAC function, the salt is
        # the initially provided salt concatenated with the block number
        iteration_salt = salt + struct.pack(">i", block_number)
        result = prf_result = hmac.new(password, iteration_salt, hash_function).digest()

        # Iterate the requested count of iterations
        for _ in range(1, count):
            # The previous step Pseudo Random Function(HMAC)'s result is used as the salt for the next iteration
            prf_result = hmac.new(password, prf_result, hash_function).digest()
            # XOR the result of this PRF's result with the previous iteration's result (same we used for salt)
            result = bytes(a ^ b for a, b in zip(result, prf_result))

        # Concatenate the result of the iteration to the derivative key
        derived_key += result
        block_number += 1

    return derived_key[:key_length]

"""Simple implementation of basic HMAC-based Extract-and-Expand Key Derivative Functions (HKDF)."""

import hmac


def hkdf_extract(salt: bytes, input_key_material: bytes, hash_function: str) -> bytes:
    """HKDF Extract function that uses HMAC as the pseudorandom function.

    Args:
        salt (bytes): The salt to use for the HMAC function.
        input_key_material (bytes): The input key material to use.
        hash_function (str): The hash function to use.

    Returns:
        bytes: The extracted Pseudo Random Key (PRK).
    """
    # If a salt is not provided, set it to a string of zeros("0").
    # The length of the string should be the length of the hash function's output.
    if not salt:
        hash_length = hmac.new(b"", b"", hash_function).digest_size
        salt = bytes((0,) * hash_length)

    # The result of the HMAC function is the extracted key
    return hmac.new(salt, input_key_material, hash_function).digest()


def hkdf_expand(pseudo_random_key: bytes, info: bytes, key_length: int, hash_function: str) -> bytes:
    """HKDF Expand function that uses HMAC as the pseudorandom function.

    Args:
        pseudo_random_key (bytes): The pseudo-random key to use for the HMAC function.
        info (bytes): The context and application specific information.
        key_length (int): The length of the output keying material in bytes.
        hash_function (str): The hash function to use.

    Returns:
        bytes: The expanded Output Keying Material (OKM).
    """
    expanded_key = b""
    block_result = b""
    block_number = 1
    hash_length = hmac.new(b"", b"", hash_function).digest_size

    # Check if the expanded key's desired length is too long based on RFC 5869
    if key_length > 255 * hash_length:
        raise ValueError("Key length too long. Cannot expand output keying material bigger than `255 * Hash's length`.")

    # The output of the HMAC function is the expanded key
    while len(expanded_key) < key_length:
        block_result = hmac.new(
            pseudo_random_key,
            block_result + info + bytes([block_number]),
            hash_function,
        ).digest()
        expanded_key += block_result
        block_number += 1

    return expanded_key[:key_length]


def hkdf(salt: bytes, input_key_material: bytes, info: bytes, key_length: int, hash_function: str) -> tuple:
    """Executing the whole HKDF process.

    Args:
        salt (bytes): The salt to use for the HMAC function.
        input_key_material (bytes): The input key material to use.
        info (bytes): The context and application specific information.
        key_length (int): The length of the output keying material in bytes.
        hash_function (str): The hash function to use.

    Returns:
        tuple: Psuedo Random Key (PRK) and Output Keying Material (OKM).
    """
    prk = hkdf_extract(salt, input_key_material, hash_function)
    okm = hkdf_expand(prk, info, key_length, hash_function)

    return prk, okm

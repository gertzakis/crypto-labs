"""Simple implementation of basic Key Derivative Functions (KDF) for cryptographic purposes."""

import hmac
import struct


def pbkdf2(password, salt, count, key_length, hash_function):
    """ "Password-Based Key Derivation Function 2 (PBKDF2) using HMAC as the pseudorandom function.
    Args:
        password (bytes): The password to derive the key from.
        salt (bytes): A salt to make the derived key unique.
        count (int): The number of iterations to perform.
        key_length (int): The length of the derived key.
        hash_function (str): The hash function to use.
    Returns:
        bytes: The derived key.
    """

    derived_key = b""
    iteration = 1

    # While the derivative key length is less than the desired key length
    while len(derived_key) < key_length:
        # For the first iteration of the HMAC function, the salt is
        # the initially provided salt concatenated with the iteration number
        iteration_salt = salt + struct.pack(">i", iteration)
        result = prf_result = hmac.new(password, iteration_salt, hash_function).digest()
        # print(iteration)
        # Iterate the requested count of iterations
        for i in range(1, count):
            # The previous step Pseudo Random Function(HMAC)'s result is used as the salt for the next iteration
            prf_result = hmac.new(password, prf_result, hash_function).digest()
            # XOR the result of this PRF's result with the previous iteration's result (same we used for salt)
            result = bytes(a ^ b for a, b in zip(result, prf_result))

        # Concatenate the result of the iteration to the derivative key
        derived_key += result
        iteration += 1

    return derived_key[:key_length]


# TODO add HKDF implementation
def hkdf():
    pass

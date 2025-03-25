import binascii

def hex_to_bytes(hex_string):
    return binascii.unhexlify(hex_string)

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def decrypt_with_key(ciphertext, key):
    return ''.join(
        chr(byte ^ key[i]) if i < len(key) and 32 <= (byte ^ key[i]) <= 126 else '?' if i < len(key) else '.'
        for i, byte in enumerate(ciphertext)
    )

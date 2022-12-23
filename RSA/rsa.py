from math import ceil
def encrypt(plainText: bytes,e: int,n: int) -> bytes:

    plainText = int.from_bytes(plainText,'big',signed=False)

    if plainText > n:
        raise OverflowError(f'The plainText {plainText} is too long for n={n}')
    
    cipherText = pow(plainText,e,n)

    return cipherText.to_bytes(max(1,ceil(cipherText.bit_length() / 8)))

def decrypt(cipherText: bytes,d: int,n: int) -> bytes:
    cipherText = int.from_bytes(cipherText,'big',signed=False)

    plainText = pow(cipherText,d,n)
    
    return plainText.to_bytes(max(1,ceil(plainText.bit_length() / 8)))


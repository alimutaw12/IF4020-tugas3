from cipher.operations import *
from datetime import datetime
import time    

def encrypt(plaintext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=10, mode='ecb'):
    # start timer
    start = time.time()

    key = charToBytes(key)
    IV = charToBytes(IV)
    if len(key) != 16 and IV != 16:
        print("ERROR! Key must be 16 bytes long")
        return []
    plaintext = bytes(plaintext)

    # add padding to plaintext to be multiple of 16
    plaintext = plaintext + bytes(16 - len(plaintext) % 16)
    
    # split plaintext into blocks of 16 bytes
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    # make 10 keys
    keys = keySchedule(key, num_rounds)

    match mode:
        case "cbc":
            blocks = CBC(blocks, keys, IV)
        case "cfb":
            blocks = CFB(blocks, keys, IV)
        case "ofb":
            blocks = OFB(blocks, keys, IV)
        case _:
            blocks = ECB(blocks, keys, IV)

    # join blocks of 16 bytes into one ciphertext
    ciphertext = b''
    for i in range(len(blocks)):
        ciphertext += blocks[i]
    progressbar(11, 11, 11)
    

    # end timer
    end = time.time()
    print("Time taken: ", end - start)

    return ciphertext

def decrypt(ciphertext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=10, mode='ecb'):
    #start timer
    start = time.time()

    key = charToBytes(key)
    IV = charToBytes(IV)
    if len(key) != 16 and IV != 16:
        print("ERROR! Key must be 16 bytes long")
        return []
    ciphertext = bytes(ciphertext)
    
    # split ciphertext into blocks of 16 bytes
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    # make 10 keys
    keys = keySchedule(key, num_rounds)
    keys = keys[::-1]

    match mode:
        case "cbc":
            resultingBlock = CBC_decrypt(blocks, keys, IV)
        case "cfb":
            resultingBlock = CFB_decrypt(blocks, keys, IV)
        case "ofb":
            resultingBlock = OFB_decrypt(blocks, keys, IV)
        case _:
            resultingBlock = ECB_decrypt(blocks, keys, IV)

    # join blocks of 16 bytes into one ciphertext
    plaintext = b''
    for i in range(len(resultingBlock)):
        plaintext += resultingBlock[i]
    progressbar(11, 11, 11)
    
    # end timer
    end = time.time()
    print("Time taken: ", end - start)

    return plaintext.rstrip(b'\x00')

if __name__ == "__main__":
    print("Welcome")
    print("Operation:")
    print("1. Encrypt")
    print("2. Decrypt")
    try:
        op = int(input("Choose operation (1-2): "))
    except:
        print("Invalid input")
        exit()

    if (op == 1):
        filename = input("Plaintext (file): ")
        ext = filename.split(".")[-1]
        with open(filename, 'rb') as file:
            plaintext = file.read()
            # print(plaintext)
        # file = open(plaintext, 'rb')
        # plaintext = file.read()
    elif (op == 2):
        filename = input("CipherText (file): ")
        ext = filename.split(".")[-1]
        with open(filename, 'rb') as file:
            ciphertext = file.read()
        # file = open(ciphertext, 'rb')
        # ciphertext = file.read()
    else:
        print("Invalid input")
        exit()
    
    key = input("Key (16 byte): ")
    IV = input("Initialization Vector (16 byte). Leave blank for default: ")

    if (op == 1):
        if len(IV):
            result_ciphertext = encrypt(plaintext, key, IV=IV)
        else:
            result_ciphertext = encrypt(plaintext, key)
        # print(printHexa16bytes(result_ciphertext))
        # print(bytesToChar(result_ciphertext))
        file = open(f'{datetime.now().strftime("%d-%m-%Y %H.%M.%S")}.{ext}', 'wb')
        file.write(result_ciphertext)
        
    elif (op == 2):
        if len(IV):
            result_plaintext = decrypt(ciphertext, key, IV=IV)
        else:
            result_plaintext = decrypt(ciphertext, key)
        # print(result_plaintext)
        file = open(f'{datetime.now().strftime("%d-%m-%Y %H.%M.%S")}.{ext}', 'wb')
        file.write(result_plaintext)
from operations import *
from datetime import datetime
import time

def progressbar(current_value,total_value,bar_lengh): 
    percentage = int((current_value/total_value)*100)                                            
    progress = int((bar_lengh * current_value ) / total_value)                                   
    loadbar = "Progress: {}%".format(percentage)
    print(loadbar)     

def encrypt(plaintext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=10):
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

    # make 16 keys
    keys = keySchedule(key, num_rounds)

    # encrypt each block
    lo = 1
    for k in keys:
        for i in range(len(blocks)):
            # print(i)
            # if i == 0:
            #     blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(IV,byteorder="big")).to_bytes(16,byteorder="big")
            # else:
            #     blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(blocks[i-1],byteorder="big")).to_bytes(16,byteorder="big")
            blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            
            blocks[i] = S1Process(blocks[i])
            blocks[i] = r4Shift(blocks[i])
            blocks[i] = P1Process(blocks[i])
        progressbar(lo, 11, 11)
        lo = lo + 1

    # join blocks of 16 bytes into one ciphertext
    ciphertext = b''
    for i in range(len(blocks)):
        ciphertext += blocks[i]
    progressbar(11, 11, 11)
    

    # end timer
    end = time.time()
    print("Time taken: ", end - start)

    return ciphertext

def decrypt(ciphertext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=10):
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
    resultingBlock = blocks.copy()

    # make 16 keys
    keys = keySchedule(key, num_rounds)
    keys = keys[::-1]

    # encrypt each block
    lo = 1
    for k in keys:
        for i in range(len(resultingBlock)):
            resultingBlock[i] = P1Process_reverse(blocks[i])
            resultingBlock[i] = r4Shift_reverse(resultingBlock[i])
            resultingBlock[i] = S1Process_reverse(resultingBlock[i])
            
            resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")

            # if i == 0:
            #     resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(IV,byteorder="big")).to_bytes(16,byteorder="big")
            # else:
            #     resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(blocks[i-1],byteorder="big")).to_bytes(16,byteorder="big")
        blocks = resultingBlock.copy()
        progressbar(lo, 11, 11)
        lo = lo + 1

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
        #     print(plaintext)
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
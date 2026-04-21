from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii

def pkcs7_unpad(data: bytes) -> bytes:
    """PKCS#5/PKCS#7 去除填充（CBC模式专用）"""
    pad_len = data[-1]
    return data[:-pad_len]

def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES-CBC 解密实现
    :param key: AES密钥（16字节）
    :param ciphertext: 密文（前16字节为IV，后续为加密数据）
    :return: 明文
    """
    # 1. 拆分IV和密文数据（IV固定16字节）
    iv = ciphertext[:16]
    cipher_data = ciphertext[16:]
    
    # 2. 初始化AES-ECB解密器（CBC核心依赖ECB）
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = b""
    prev_block = iv  # 初始前一分组为IV
    
    # 3. 按16字节分组解密
    for i in range(0, len(cipher_data), 16):
        cipher_block = cipher_data[i:i+16]
        # ECB解密当前分组
        decrypted_block = aes.decrypt(cipher_block)
        # 与前一个密文分组异或得到明文分组
        plain_block = strxor(decrypted_block, prev_block)
        plaintext += plain_block
        # 更新前一分组为当前密文分组
        prev_block = cipher_block
    
    # 4. 去除PKCS#7填充
    return pkcs7_unpad(plaintext)

# ====================== CTR 模式解密（自行实现） ======================
def aes_ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES-CTR 解密/加密实现（CTR加解密逻辑完全相同）
    :param key: AES密钥（16字节）
    :param ciphertext: 密文（前16字节为nonce/IV，后续为加密数据）
    :return: 明文
    """
    # 1. 拆分nonce(IV)和密文数据
    nonce = ciphertext[:16]
    cipher_data = ciphertext[16:]
    
    # 2. 初始化AES-ECB加密器（CTR仅使用ECB加密）
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = b""
    counter = 0 
    
    # 3. 按16字节分组生成密钥流并解密
    for i in range(0, len(cipher_data), 16):
        # 生成计数器块：nonce + 计数器（大端序）
        counter_block = nonce[:8] + counter.to_bytes(8, byteorder='big')
        # 加密计数器块得到密钥流
        keystream = aes.encrypt(counter_block)
        # 取对应长度的密钥流与密文异或
        cipher_block = cipher_data[i:i+16]
        plain_block = strxor(keystream[:len(cipher_block)], cipher_block)
        plaintext += plain_block
        # 计数器自增
        counter += 1
    
    return plaintext

# ====================== 题目解密 ======================
if __name__ == '__main__':
    print("===== 第1题：CBC模式解密 =====")
    key1 = binascii.unhexlify("140b41b22a29beb4061bda66b6747e14")
    ct1 = binascii.unhexlify("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    pt1 = aes_cbc_decrypt(key1, ct1)
    print("明文：", pt1.decode('utf-8'))

    print("\n===== 第2题：CBC模式解密 =====")
    ct2 = binascii.unhexlify("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")
    pt2 = aes_cbc_decrypt(key1, ct2)
    print("明文：", pt2.decode('utf-8'))

    print("\n===== 第3题：CTR模式解密 =====")
    key2 = binascii.unhexlify("36f18357be4dbd77f050515c73fcf9f2")
    ct3 = binascii.unhexlify("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
    pt3 = aes_ctr_decrypt(key2, ct3)
    print("明文：", pt3.decode('utf-8'))

    print("\n===== 第4题：CTR模式解密 =====")
    ct4 = binascii.unhexlify("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")
    pt4 = aes_ctr_decrypt(key2, ct4)
    print("明文：", pt4.decode('utf-8'))
def caesar_decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if 'A' <= char <= 'Z':  # 仅处理大写字母
            # 解密公式：(密文ASCII - 偏移量 - 'A'的ASCII + 26) % 26 + 'A'的ASCII
            decrypted_char = chr(((ord(char) - ord('A') - key) % 26) + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char  # 非字母字符保留（本题无此类字符）
    return plaintext
    # 实验密文
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

print("===== 凯撒密码穷举解密实验 =====")
print(f"原始密文: {ciphertext}\n")
print("开始穷举解密（密钥1~25）：\n")

for key in range(1, 26):
    decrypted = caesar_decrypt(ciphertext, key)
    print(f"密钥 {key:2d}: {decrypted}")
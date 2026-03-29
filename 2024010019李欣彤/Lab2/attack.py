def hex_to_bytes(hex_str):
    """十六进制字符串转字节数组（增加长度校验与空白清除，解决ValueError）"""
    # 清除所有空白字符（空格、换行、制表符）
    hex_str_clean = hex_str.strip().replace(" ", "").replace("\n", "").replace("\t", "")
    # 校验长度为偶数
    if len(hex_str_clean) % 2 != 0:
      raise ValueError(f"十六进制字符串长度必须为偶数，当前长度: {len(hex_str_clean)}，字符串: {hex_str_clean}")
    return bytes.fromhex(hex_str_clean)

def bytes_to_hex(b):
    """字节数组转十六进制字符串"""
    return b.hex()

def xor_bytes(a, b):
    """两个字节数组异或（自动截断到较短长度）"""
    min_len = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:min_len], b[:min_len]))

def is_printable(c):
    """判断字符是否为可打印ASCII字符"""
    return 32 <= c <= 126

# -------------------------- 1. 输入所有密文（严格核对长度，修正密文#1） --------------------------
cipher_hex_list = [
    # 密文#1（已修正末尾，长度106）
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dffff5b403b510d0d0",
    # 密文#2
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f",
    # 密文#3
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b82",
    # 密文#4
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a8119784",
    # 密文#5
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade87",
    # 密文#6
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c",
    # 密文#7
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd0",
    # 密文#8
    "315c4eeaa8b5f8bffd111155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0",
    # 密文#9
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a98",
    # 密文#10
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f",
    # 目标密文
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e"
]

# 转换为字节数组，保留原始长度
cipher_bytes_list = [hex_to_bytes(h) for h in cipher_hex_list]
max_len = max(len(c) for c in cipher_bytes_list)

# -------------------------- 2. 初始化明文与密钥数组 --------------------------
plain_list = [bytearray(len(c)) for c in cipher_bytes_list]
key = bytearray(max_len)
key_found = [False] * max_len  # 标记密钥位置是否已确定

# -------------------------- 3. 空格推断法还原明文与密钥 --------------------------
SPACE = ord(' ')
for pos in range(max_len):
    # 遍历所有已知密文（0-9），尝试假设该位置为空格
    for guess_cipher_idx in range(10):
        if pos >= len(cipher_bytes_list[guess_cipher_idx]):
            continue
        # 计算候选密钥
        k_guess = cipher_bytes_list[guess_cipher_idx][pos] ^ SPACE
        # 验证所有密文该位置是否为可打印字符
        valid = True
        for c_idx in range(len(cipher_bytes_list)):
            if pos >= len(cipher_bytes_list[c_idx]):
                continue
            p = cipher_bytes_list[c_idx][pos] ^ k_guess
            if not is_printable(p):
                valid = False
                break
        if valid:
            # 验证通过，更新密钥
            key[pos] = k_guess
            key_found[pos] = True
            # 更新对应明文
            for c_idx in range(len(cipher_bytes_list)):
                if pos < len(cipher_bytes_list[c_idx]):
                    plain_list[c_idx][pos] = cipher_bytes_list[c_idx][pos] ^ key[pos]
            break

# -------------------------- 4. 输出结果 --------------------------
print("="*80)
print("✅ 解密成功！")
print("🎯 最终明文：")
target_plain = plain_list[-1].decode('ascii', errors='replace').strip('\x00')
print(target_plain)
print("="*80)
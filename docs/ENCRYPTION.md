# ICMP Shell 加密通信协议详解

本文档详细介绍了 `go-icmpshell` (token 分支) 采用的全新加密通信协议。该协议引入了 **随机会话密钥 (Random Session Key)** 机制，显著提高了通信安全性，即使攻击者持有源代码也无法解密捕获的流量（除非拥有握手包和 Token）。

## 1. 核心安全机制

### 1.1 双层加密体系
通信过程分为两个阶段，分别使用不同的密钥：

1.  **握手阶段 (Handshake)**：
    *   **密钥**：预共享 Token 的 MD5 哈希值 (16字节)。
    *   **目的**：仅用于传输由客户端随机生成的会话密钥 (Session Key)。
2.  **会话阶段 (Session)**：
    *   **密钥**：握手阶段协商出的随机 Session Key (16字节)。
    *   **目的**：加密后续所有的命令控制、结果回传和心跳保活。

### 1.2 加密算法
采用 **循环异或加密 (Repeating XOR / Cycle XOR)** 算法。
*   **原理**：将数据字节与密钥字节逐个进行异或运算。当数据长度超过密钥长度时，密钥循环使用。
*   **公式**：`ciphertext[i] = plaintext[i] ^ key[i % len(key)]`

## 2. 通信流程

### 步骤 1: 握手 (Handshake)
1.  **Client** 启动时，使用 `crypto/rand` 生成一个 **16字节的随机 Session Key**。
2.  **Client** 构造握手包：`KEY:` + `随机SessionKey`。
3.  **Client** 使用 **Token MD5** 对握手包进行加密，并发送给 Server。
4.  **Server** 收到包后，尝试用 Token MD5 解密。
5.  如果解密结果以 `KEY:` 开头，则提取出 Session Key，并保存到内存中。
6.  **Server** 回复 `KEY_OK` (使用 Session Key 加密)，表示握手成功。

### 步骤 2: 会话 (Session)
一旦 Session Key 建立，后续所有通信（Client 发送的心跳、Server 发送的命令、Client 回传的输出）均使用 **Session Key** 进行加密。

## 3. 协议数据包结构

解密后的明文数据包含“协议头”，用于标识数据类型：

| 类型 | 前缀格式 | 说明 |
| :--- | :--- | :--- |
| **握手** | `KEY:<16-byte-key>` | 包含随机生成的会话密钥 |
| **命令** | `CMD:<command>` | Server 下发的 Shell 命令 |
| **输出** | `OUT:<output>` | Client 回传的命令执行结果 |
| **心跳** | `PING` | Client 发送的保活包，或 Server 的空闲回复 |
| **确认** | `KEY_OK` | Server 确认握手成功 |

## 4. 流量解密脚本 (Python)

用 tshark 将抓取到的 ICMP 流量的 data 数据批量导出

```bash
tshark -r icmp.pcapng -Y "icmp && data.data" -T fields -e data.data

6b69e058240639e1c57e8b4ad6ea029631862b1e
c31a67e51c7e
d81670fd
d81670fd
d81670fd
d81670fd
d81670fd
d81670fd
d81670fd
d81670fd
d81670fd
cb127a803a51
c70a6a80265ce862cbe13b897edebb5cef365a87631dfb379eac25cf31cde013fd2f4d87631dfb379eac25cf3d9bba18e93a53d53d1ca06dd3a224837c83be4fa02c47c97a19b8778fbd30cf3d9fba13f83a4cdb275afe76d7f1619663c5f10ae13a49937f0ca42f89a62a8b7ecebb50b96d16df2550fe2694a72ccf3d98a254fb2b5fdc351ca06dc2e12a8363dee70fed2d4d937f03bd7797a62a877dcbf11fe72a50ce201ca067cbe128827cc3fc55a46c0d920c54fc2f88bd26947483be45b07761d62354e83292a760ca209aa254d7334ed52350fe3e8fa63bcf3d98a248a0005adf2550e0308bac3bcf3d98a74ca0005fd43259f52b92aa3a9362cfe00fa1730d83661def3096e7289661c6f752e93c5ddf2046d3398fb960ca2293aa54eb3053943245fc339ee7288572cfe10fd72c5dc83650e22c93a83b8f7fcdbb50bb660792305ae1719ab9398a7484f31feb3a4dc90c46ff37d2e57dd62182f113e5715fca2359e9719aaa2a8362d9cd0eed3251ce366aed3ad2e57ed62282f113e5715fca2359e97188a1289474dafd15e62b10dd215af92fd5fa60ca269aa654eb3053943245fc339ee73a8e70d8f70ce73650ce7d52fe308eb967d23886a54cba775dd53e1bed2f8ba52cc862c2f30eed2f51d33d41a23889a63c963f98bb50bf6f0b92305ae1719ab9398a7484e114e92d5bca3c5ce22bd5ae3b8964dabc49a1730f8a621ded3c98ac3a954ec8e21aa173098a621def3096e7289661c6f752fb375fc83645e33695bd678163c5e70ca66e17b059
d81670fd
d81670fd
cb127a803f46
c70a6a803140e5339fe73d9e65a0fb1fe52f4dd23659e07288ac3b9074d8bf10e1314bc27e54e13bcdfd64a369a0fb1fe52f4dd23659e07288ac3b9074d8bf10e1314bc27e54fe32cdfd64a369a0fb1fe52f4dd23659e07288a12c8a7d87f61dfa2857d47e54fe32cdfd64a369a0fb1fe52f4dd23659e07288a12c8a7d87fe15e62a46973258e869cfe40c9e1bc3f111f82c56df3f59a12c93ac258a3cc6fb12fd2713db2158ba6bd68c31ec78c9ff0cfb375bd63f18ff379ea525cb66c3fc18e7284d97164da23a83ac43ec
d81670fd
d81670fd
d81670fd
```

以下脚本可用于解密 Wireshark 捕获的 ICMP 流量。
**注意：必须捕获到连接建立时的第一个“握手包”，否则无法获取 Session Key，后续流量将无法解密。**

```python
import hashlib
import binascii


class ICMPDecryptor:
    def __init__(self, token_str):
        self.token = token_str
        # 1. 计算 Token 的 MD5 (16字节) 作为握手密钥
        self.token_md5 = hashlib.md5(self.token.encode()).digest()
        self.session_key = None
        print(f"[*] Token: {self.token}")
        print(f"[*] Token MD5 (Handshake Key): {binascii.hexlify(self.token_md5).decode()}")

    def xor_crypt(self, data, key):
        """循环异或算法 (Repeating XOR)"""
        if not key:
            return data
        output = bytearray(len(data))
        key_len = len(key)
        for i in range(len(data)):
            output[i] = data[i] ^ key[i % key_len]
        return bytes(output)

    def decrypt_packet(self, hex_payload, packet_index=0):
        """尝试解密数据包"""
        try:
            # 清理 Hex 字符串中的空格和换行
            data = binascii.unhexlify(hex_payload.replace(" ", "").replace("\n", ""))
        except Exception as e:
            return f"Error parsing HEX: {e}"

        # --- 阶段 1: 尝试作为握手包解密 (使用 Token MD5) ---
        if self.session_key is None:
            decrypted_with_token = self.xor_crypt(data, self.token_md5)
            # 检查是否包含 Session Key (格式: "KEY:" + 16字节密钥)
            if decrypted_with_token.startswith(b"KEY:"):
                key_part = decrypted_with_token[4:]  # 去掉 "KEY:" 前缀
                if len(key_part) == 16:
                    self.session_key = key_part
                    return f"[!] 包 #{packet_index}: 捕获握手包! Session Key 已获取: {binascii.hexlify(self.session_key).decode()}"

        # --- 阶段 2: 使用 Session Key 解密 ---
        if self.session_key:
            decrypted_with_session = self.xor_crypt(data, self.session_key)
            try:
                # 尝试解码为文本
                text = decrypted_with_session.decode('utf-8', errors='ignore')

                # 识别协议前缀
                prefix = ""
                content = text
                if text.startswith("CMD:"):
                    prefix = "[命令 CMD]"
                    content = text[4:]
                elif text.startswith("OUT:"):
                    prefix = "[输出 OUT]"
                    content = text[4:]
                elif text == "PING":
                    prefix = "[心跳 PING]"
                elif text == "KEY_OK":
                    prefix = "[握手确认]"

                # 显示解密内容
                return f"[+] 包 #{packet_index} {prefix}: {content}"
            except:
                return f"[?] 包 #{packet_index}: 解密原始字节: {binascii.hexlify(decrypted_with_session).decode()}"
        else:
            return f"[-] 包 #{packet_index}: 无法解密 (未找到 Session Key)"


# ================= 配置与运行 =================

# 1. 设置 Token (必须与 Server/Shell 启动参数一致)
TOKEN = "123"

# 2. 填入 Wireshark 抓包数据 (Data 部分的 Hex Stream)
# 注意：列表中的第一个包必须是握手包，否则后续无法解密
captured_packets = [
    # 1. 握手包 (必须是第一个)
    "6b69e058240639e1c57e8b4ad6ea029631862b1e",

    # 2. 短包 (可能是 KEY_OK 或 PING)
    "c31a67e51c7e",

    # 3. PING (心跳，重复多次)
    "d81670fd",
    "d81670fd",
    "d81670fd",
    "d81670fd",
    "d81670fd",
    "d81670fd",
    "d81670fd",
    "d81670fd",
    "d81670fd",

    # 4. 中等长度包
    "cb127a803a51",

    # 5. 长包 (数据输出)
    "c70a6a80265ce862cbe13b897edebb5cef365a87631dfb379eac25cf31cde013fd2f4d87631dfb379eac25cf3d9bba18e93a53d53d1ca06dd3a224837c83be4fa02c47c97a19b8778fbd30cf3d9fba13f83a4cdb275afe76d7f1619663c5f10ae13a49937f0ca42f89a62a8b7ecebb50b96d16df2550fe2694a72ccf3d98a254fb2b5fdc351ca06dc2e12a8363dee70fed2d4d937f03bd7797a62a877dcbf11fe72a50ce201ca067cbe128827cc3fc55a46c0d920c54fc2f88bd26947483be45b07761d62354e83292a760ca209aa254d7334ed52350fe3e8fa63bcf3d98a248a0005adf2550e0308bac3bcf3d98a74ca0005fd43259f52b92aa3a9362cfe00fa1730d83661def3096e7289661c6f752e93c5ddf2046d3398fb960ca2293aa54eb3053943245fc339ee7288572cfe10fd72c5dc83650e22c93a83b8f7fcdbb50bb660792305ae1719ab9398a7484f31feb3a4dc90c46ff37d2e57dd62182f113e5715fca2359e9719aaa2a8362d9cd0eed3251ce366aed3ad2e57ed62282f113e5715fca2359e97188a1289474dafd15e62b10dd215af92fd5fa60ca269aa654eb3053943245fc339ee73a8e70d8f70ce73650ce7d52fe308eb967d23886a54cba775dd53e1bed2f8ba52cc862c2f30eed2f51d33d41a23889a63c963f98bb50bf6f0b92305ae1719ab9398a7484e114e92d5bca3c5ce22bd5ae3b8964dabc49a1730f8a621ded3c98ac3a954ec8e21aa173098a621def3096e7289661c6f752fb375fc83645e33695bd678163c5e70ca66e17b059",

    # 6. 后续短包 (PING)
    "d81670fd",
    "d81670fd",

    # 7. 另一个中等长度包
    "cb127a803f46",

    # 8. 另一个长包 (数据输出)
    "c70a6a803140e5339fe73d9e65a0fb1fe52f4dd23659e07288ac3b9074d8bf10e1314bc27e54e13bcdfd64a369a0fb1fe52f4dd23659e07288ac3b9074d8bf10e1314bc27e54fe32cdfd64a369a0fb1fe52f4dd23659e07288a12c8a7d87f61dfa2857d47e54fe32cdfd64a369a0fb1fe52f4dd23659e07288a12c8a7d87fe15e62a46973258e869cfe40c9e1bc3f111f82c56df3f59a12c93ac258a3cc6fb12fd2713db2158ba6bd68c31ec78c9ff0cfb375bd63f18ff379ea525cb66c3fc18e7284d97164da23a83ac43ec",

    # 9. 后续 PING
    "d81670fd",
    "d81670fd",
    "d81670fd"
]

print("=== 开始 ICMP 流量解密 ===")
decryptor = ICMPDecryptor(TOKEN)

for i, packet_hex in enumerate(captured_packets):
    print(decryptor.decrypt_packet(packet_hex, i))
```

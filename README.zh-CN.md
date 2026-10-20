# miwear — 小米穿戴设备 BLE 协议

逆向自**小米运动健康** App（`com.xiaomi.hm.health`，分析版本 **3.59.1**）与小米手环 / 小米手表之间的
BLE 私有通信协议。

[English](README.md) · [协议参考](docs/PROTOCOL.md) · [分层图解](docs/LAYERS.md) · [提取过程](docs/EXTRACTION.md)

> **状态：** 分帧、校验与密钥派生已完整还原，并通过公开测试向量验证。
> L2 以上的应用层为 protobuf，可做**结构级**解析，但未附带 `.proto`——详见[已知限制](#已知限制)。

> **本仓库范围。** 这里是**完整工具包**：报文格式参考、逆向过程记录，以及生成下面
> 那些十六进制转储的 Python 参考实现。全部只依赖标准库，解一帧不需要安装任何东西。

---

## 为什么有这个项目

这里的一切都来自对 APK 的静态分析：没有设备固件、没有厂商 SDK、没有厂商文档。
目标是把一段原始 `btsnoop` 抓包变成可读的帧，并把线格式记录到任何人都能重新实现的程度。

本仓库不包含任何专有源码、密钥或固件，只有协议事实与干净的 Python 实现。

---

## 一张图看懂

```
                                     ┌──────────── ATT / GATT ────────────┐
  服务 0xFE95                        │ 写 0x005F    通知 0x005E           │
                                     │ 每次 MTU-3 字节，必须拼流           │
                                     └────────────────┬───────────────────┘
                                                      │
                              ┌───────────────────────▼────────────────────────┐
                              │ L1  SAR 帧（8 字节头，CRC-16/ARC）              │
                              │  A5 A5 │ type|frx │ seq │ len │ crc │ payload  │
                              │  滑动窗口 32，累计 ACK，10 秒重传               │
                              └───────────────────────┬────────────────────────┘
                                                      │
                              ┌───────────────────────▼────────────────────────┐
                              │ L2  channel(1) │ opcode(1) │ payload           │
                              │  ch 1 = protobuf 业务流量                      │
                              │  opcode 2 = 已加密（AES-CTR，IV = 密钥）        │
                              └───────────────────────┬────────────────────────┘
                                                      │
                              ┌───────────────────────▼────────────────────────┐
                              │ 应用层：protobuf(nano)、大文件传输、OTA         │
                              └────────────────────────────────────────────────┘
```

完整字段表见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。

---

## 怎么用

装上它，或者直接从源码跑——核心包没有任何依赖：

```bash
python -m miwear selftest                     # 40 项协议自检，不需要任何数据
python -m miwear decode <hex>                 # 从 hex 字符串解 SAR 帧
python -m miwear capture btsnoop_hci.log      # 逐层剥 HCI -> ATT -> SAR -> L2
python -m miwear keys --token <hex> --app <hex> --dev <hex>
python -m miwear decrypt --key <hex> <payload-hex>
```

`pip install -e .` 会装出 `miwear` 命令，并启用可选依赖：
`[ccm]` 为旧版 V1 载荷加上 AES-CCM 支持。

按下面的顺序读文档：

| 你的目的 | 读这个 |
|---|---|
| 先搞清楚三层结构长什么样 | 本文[上面那张图](#一张图看懂) |
| 要把协议**实现**一遍 | [docs/PROTOCOL.md](docs/PROTOCOL.md) — 每个字段、每个枚举、每条时序 |
| 想跟着真实报文走一遍 | [docs/LAYERS.md](docs/LAYERS.md) — 带十六进制转储的逐层讲解 |
| 想知道这些结论是怎么来的 | [docs/EXTRACTION.md](docs/EXTRACTION.md) — 反编译步骤与定位方法 |

抓一份自己的报文来对照：

```bash
# Android：开发者选项 → 启用蓝牙 HCI 侦听 → 复现一次配对
adb bugreport bugreport.zip
unzip -o bugreport.zip 'FS/data/misc/bluetooth/logs/*' -d hci
```

`btsnoop` 里是完整的 HCI 层，需要按 L2CAP → ATT → SAR 逐层剥开。
**拼流这一步不能省**：一帧 SAR 可能跨多次 ATT 写，一次写也可能含多帧。

---

## 报文长什么样

下面这一帧来自一次真实的连接初始化，可以直接对照
[docs/PROTOCOL.md](docs/PROTOCOL.md#l1--sar-framing) 手工解出来：

```
a5a5020016001d4d 0101030001000002020000fc03020020000402001027
└──┬──┘│││└─┬─┘└┬┘ └──────────────────┬───────────────────────┘
 magic │││ len  crc                    payload
       ││└ seq                      CMD_L1START_REQ
       │└ opcode/type
       └ frx
```

解出来的配置 TLV：

| 字段 | 值 | 含义 |
|---|---|---|
| `CONFIG_TYPE_VERSION` | `010000` | 1.0.0 |
| `CONFIG_TYPE_MPS` | `00fc` | 64512 |
| `CONFIG_TYPE_TX_WIN` | `2000` | 32（滑动窗口） |
| `CONFIG_TYPE_SEND_TIMEOUT` | `1027` | 10000 ms（重传超时） |

更多样例见 [docs/LAYERS.md](docs/LAYERS.md)。

---

## 哪些已验证，哪些没有

以下结论已用**公开测试向量**逐条验证：

| 组件 | 测试向量 |
|---|---|
| CRC-16/ARC | check 值 `0xBB3D` |
| CRC-32/IEEE | check 值 `0xCBF43926` |
| AES-128 分组 | FIPS-197 附录 C.1 |
| AES-CTR | NIST SP 800-38A F.5.1 |
| HKDF-SHA256 | RFC 5869 附录 A.1 |
| HMAC-SHA256 | RFC 4231 用例 1 |
| START_REQ 帧字节 | 与 `CMDPacket.createCmdData()` 逐字节一致 |
| 解帧器 | 往返、损坏、重同步 |

## 已知限制

依赖本工具前请先了解：

1. **没有 `.proto`。** 应用层载荷只能做结构级解析（字段号 + wire 类型），不是语义级。
   能从反编译代码还原出含义的字段都记录在 [docs/PROTOCOL.md](docs/PROTOCOL.md)。
2. **V2 的 IV 就是会话密钥本身——已由代码定论。** `CipherApiCall` 调用的是
   `r1.a(mDeviceKey, mDeviceKey, input)`，而 `defpackage.r1` 把第二个实参直接塞进
   `new IvParameterSpec(iv)`。密钥和 IV 是同样的 16 字节，**没有补零这一步**，
   初始计数块就是密钥本身。`CipherApiCall` 里那个 12 字节 `ByteBuffer` 属于
   **V1 CCM** 路径（`decryptData`/`encryptData`），与 V2 无关；本文档早先的版本
   把两者混为一谈了。详见 [docs/PROTOCOL.md](docs/PROTOCOL.md#v2--aes-ctr-with-the-key-as-iv)。
   唯一残留的疑问是 SunJCE 如何递增计数器，而这在任何不超过 2^32 个分组的
   载荷上都不可能区别于普通的大端递增。
3. **两代协议并存。** 固件版本为 `0.x` 的设备使用完全不同的通道协议
   （见 `miwear/legacy_v1.py`）。判断前先读版本特征 `0x0050`。
4. **同一 App 里的华米/Zepp 手表**走另一套 Huami 模块协议（ECDH-P256 + ECDSA），本项目**有意不含**。
5. **纯静态分析。** 没有用真实握手确认过任何一步。非常欢迎带抓包的补充。

---

## 目录结构

```
miwear-ble-protocol/
├── miwear/              参考实现（仅标准库）
│   ├── constants.py     UUID、枚举、魔数
│   ├── crc.py           CRC-16/ARC、CRC-32
│   ├── layer_l1.py      SAR 分帧、CMD/TLV、ACK/NAK
│   ├── layer_l2.py      channel | opcode 解复用
│   ├── crypto.py        HKDF、HMAC、AES-CTR、V1 nonce 布局
│   ├── protobuf.py      结构性 protobuf wire 解码
│   ├── capture.py       btsnoop / pcap -> ATT 值
│   ├── session.py       整份抓包的处理流水线
│   ├── legacy_v1.py     BA DC FE … EF 旧版分帧
│   └── cli.py           `miwear` 命令
├── tests/               单元测试（`python tests/run_tests.py`）
├── examples/            生成好的样例帧，同时充当冒烟测试
├── docs/
│   ├── PROTOCOL.md      逐字段协议参考
│   ├── LAYERS.md        分层走查，带 hexdump
│   └── EXTRACTION.md    分析方法与可复现步骤
├── CONTRIBUTING.md
└── LICENSE
```

---

## 参与贡献

最有价值的贡献是**抓包**——一段包含握手的 `btsnoop` 加上固件版本，
就能回答「已知限制」里的全部问题。提交前请抹掉 MAC 地址与 token。

详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 法律

对自有硬件上可观测协议的独立互操作性研究，仅供学习、调试与互操作目的。
与小米公司无任何关联，也未获其背书。

小米、小米手环、小米手表为各自权利人的商标。本项目以 [MIT](LICENSE) 许可发布。

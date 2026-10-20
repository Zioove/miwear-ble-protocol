# 3.59.1 反编译源码深挖记录（P0–P2）

> 样本：`com.xiaomi.hm.health` 3.59.1，jadx 1.5.6 全量反编译，49,775 个 java 文件，13 个 dex。
> 分析对象：`D:\dsh-workspace\04-逆向小米健康蓝牙协议\mihealth\src\sources\`（只读）。
> 本文每条结论都给出 **完整类名 + 行号 + 代码原文**。凡无代码直接支撑的推断，一律标注 **【推测】**。
> 本文不修改任何已有文档；对 `docs/miwear_ble_protocol.md`（中文初稿）与 `docs/PROTOCOL.md`（英文版）的差异只在「订正记录」一节列出。

---

## 0. 结论速览

| 编号 | 结论 | 影响 |
|---|---|---|
| **P0** | V2 的 AES-CTR **IV = 完整的 16 字节会话密钥**（`r1.a(key, key, data)`），**不存在** 12 字节 IV、不存在补零、不存在"末 4 字节计数器"。CTR 初始计数器就是 **key[12:16] 按大端解释**。 | `miwear/crypto.py` 的 `decrypt_v2_payload()` 正确；英文文档原「12B IV 补零」说法错误 |
| **P0-补** | `CipherApiCall` 里的 `ByteBuffer.allocate(12).order(LITTLE_ENDIAN)` 属于 **V1 CCM 路径**，且其末 4 字节计数器是 **小端**（因为 `tp5.c()/d()` 自己就把 int 拆成了小端字节）。 | 复核 lead 的 `build_v1_nonce` 修复，**确认小端正确** |
| **P1-a** | `pyt` / `va0` / `bb0` / `hb0` / `ya0` / `eb0` / `jd0` 的字段号与类型已 **100% 从 nano 编码器读回**，初稿表格 **全部正确**，另发现初稿遗漏的 `va0` 字段 29/34–37 与 `pyt` 的 cmd 白名单。 | 可直接据此生成 `.proto` |
| **P1-b** | channel 1 上 **没有独立的 cmd 层**：L2 payload 直接就是 protobuf。业务类型由 `channelToType()` 决定，业务子类由**信封消息的 field 1（枚举）**区分。存在**两套并存信封** `pyt` 与 `oyt`。 | 抓包识别方法需要按此重写 |
| **P2-a** | Mass 头不是 26 字节而是 **22 字节**，且 **dataType 字节 = dataType×16 + subType**（不是两个独立字节）；首包总前缀 **26B**（4+22）、中间包 4B、末包 4B+4B CRC32。 | 初稿的 26B Header 说法错误 |
| **P2-b** | channel 5 的 `sport800` detail 是 **BER-TLV**，tag 1–19 的映射表已完整还原（含每个 node 的字段位宽）。**这层没有 channel 5 关系**——BER-TLV 是 channel 5 内 protobuf 之后再嵌套的一层。 | 新增可用 tag 表 |
| **P2-c** | 固件 OTA **不走 channel 6**，而是**走 channel 2 的 Mass**，`type=2`、`detailType∈{0,15}`。channel 6（`TRANSPORT_CHANNEL_OTA`）在本版本中**没有找到任何构造方**。 | 初稿"OTA=channel 6"需降级为【推测】 |
| **P3-3** ⚠️ | **签名消息顺序与两份文档相反**：HKDF salt = `randomApp ‖ randomDevice`，但 **deviceSign/appSign 的签名消息 = `randomDevice ‖ randomApp ‖ oob`**。 | **若不改，双向签名校验必然失败**——优先处理项 |
| **P3-3b** | `ByteUtil.equals()` 是**按 `min(len)` 做前缀比较**，不是全长比较。 | 我方实现必须用全长比较；抓包时"App 显示验证通过"不能反证算式正确 |
| **P3-4** | `itn.i()` 的 HKDF 展开长度是 **64** 字节，`WearAuthV2` 只取前 40。 | `HKDF_OUTPUT_LEN=40` 仍正确（前缀性质），无需改 |

---

## P0. AES-CTR 的 IV 究竟是什么（已由 lead 结案，此处仅留档）

> **状态：已结案。** 本节结论由 lead 独立查出并已修正两份文档，此处只保留证据索引，不再展开论证。

### P0-1 调用点：IV 就是 key 本身

`com/xiaomi/wearable/wear/api/CipherApiCall.java:73-79`

```java
73:     public byte[] decryptDataV2(@Nullable byte[] input) {
74:         byte[] bArr;
75:         if (input == null || (bArr = this.mDeviceKey) == null) {
76:             return null;
77:         }
78:         return r1.a(bArr, bArr, input);
79:     }
```

`com/xiaomi/wearable/wear/api/CipherApiCall.java:112-118`

```java
112:     public byte[] encryptDataV2(@Nullable byte[] input) {
113:         byte[] bArr;
114:         if (input == null || (bArr = this.mAppKey) == null) {
115:             return null;
116:         }
117:         return r1.b(bArr, bArr, input);
118:     }
```

**关键点：第 2 个实参（IV）与第 1 个实参（key）是同一个引用 `bArr`**，长度恒为 16（见 P0-2）。

### P0-2 key 的长度是 16 字节

`com/xiaomi/wearable/wear/api/WearAuthV2.java:164-173`

```java
164:         byte[] bArrI = itn.i("miwear-auth", this.f13866b, bArr5);
165:         byte[] bArr6 = new byte[16];
166:         this.j = bArr6;
167:         this.f6425k = new byte[16];
168:         this.l = new byte[4];
169:         this.m = new byte[4];
170:         System.arraycopy(bArrI, 0, bArr6, 0, 16);      // DeviceKey  = okm[0:16]
171:         System.arraycopy(bArrI, 16, this.f6425k, 0, 16); // AppKey     = okm[16:32]
172:         System.arraycopy(bArrI, 32, this.l, 0, 4);       // DeviceIV   = okm[32:36]
173:         System.arraycopy(bArrI, 36, this.m, 0, 4);       // AppIV      = okm[36:40]
```

`WearAuthV2.java:93` 把两者交给 `CipherApiCall.updateKeys(deviceKey, appKey, deviceIV, appIV)`：

```java
93:     ((CipherApiCall) wearAuthV2.c).updateKeys(wearAuthV2.j, WearAuthV2.this.f6425k, WearAuthV2.this.l, WearAuthV2.this.m);
```

### P0-3 底层实现

`defpackage/r1.java:9-25`

```java
 9:     public static final byte[] a = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
10:
11:     public static byte[] a(byte[] bArr, byte[] bArr2, byte[] bArr3) throws Exception {
12:         SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
13:         IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr2);
14:         Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
15:         cipher.init(2, secretKeySpec, ivParameterSpec);
16:         return cipher.doFinal(bArr3);
17:     }
18:
19:     public static byte[] b(byte[] bArr, byte[] bArr2, byte[] bArr3) throws Exception {
20:         SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
21:         IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr2);
22:         Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
23:         cipher.init(1, secretKeySpec, ivParameterSpec);
24:         return cipher.doFinal(bArr3);
25:     }
```

### P0-4 结论与影响

1. `IvParameterSpec` 收到的是 **16 字节**，`SunJCE` 的 `AES/CTR` 对 16 字节 IV **不做补零**。
2. 初始计数器块 = `key[0:16]`，其后每块对**末 4 字节按大端 +1**（JCE CTR 语义）。即 CTR 起点 = `key[12:16]` 的 big-endian 值。
3. **无 counter 前缀、无 MAC、无填充**：`encryptDataV2` / `decryptDataV2` 的入参出参长度相同，前后没有任何附加字节。
4. 对 `miwear/crypto.py` 的判断：`decrypt_v2_payload()` → `aes_ctr_crypt(key, key, 0, data)` **正确**，无需改动。
5. 对文档的判断：**`mihealth/docs/miwear_ble_protocol.md` §4.4 的原始结论（IV 16 字节直接取 key）正确**；**`docs/PROTOCOL.md` 原「APK 用 12 字节 IV，SunJCE 补零到 16B，末 4 字节大端计数器」错误**——该描述张冠李戴到了 V1 CCM 路径上。

### P0-5 补充核实：V1 CCM 的 nonce 末 4 字节是小端

lead 指出的 `tp5` 细节复核无误。`com/xiaomi/wearable/wear/api/CipherApiCall.java:57-59`（V1 路径）先建 12 字节缓冲：

```java
57:         ByteBuffer byteBufferOrder = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN);
58:         byteBufferOrder.put(this.mDeviceIV);
59:         byteBufferOrder.putInt(0);
```

而填入的计数器字节本身已经是小端展开的（`defpackage/tp5.java` 的 `c()/d()` 返回 `{(byte)(s&255),(byte)(s>>8),(byte)(s2&255),(byte)(s2>>8)}`），所以 nonce = `iv4(4B) ‖ 00000000(4B) ‖ ctr(4B, 小端)`。
**这进一步从反面证明：`ByteBuffer.allocate(12)` 属于 V1 CCM，与 V2 的 CTR 无关。**

---

## P1-a. V2 认证子消息字段语义（从 nano 编码器直接读回）

### 读法说明：nano 写方法与 wire type 的对应关系

所有"字段号 + 类型"都是从 `j(CodedOutputByteBufferNano)` 里逐行读出的。这些方法名是 jadx 从字节码还原的短名，其 wire type 可以直接验证：

`com/google/protobuf/nano/CodedOutputByteBufferNano.java:354-416`

```java
354:     public void M(int i, boolean z) throws IOException {
355:         o0(i, 0);              // -> varint
...
363:     public void O(int i, byte[] bArr) throws IOException {
364:         o0(i, 2);              // -> length-delimited（bytes）
...
382:     public void S(int i, int i2) throws IOException {
383:         o0(i, 0);              // -> varint（int32，含负数 10 字节）
...
391:     public void U(int i, float f) throws IOException {
392:         o0(i, 5);              // -> fixed32（float）
...
400:     public void W(int i, int i2) throws IOException {
401:         o0(i, 0);              // -> varint（**带 zigzag**，即 sint32）
...
413:     public void Y(int i, udh udhVar) throws IOException {
414:         o0(i, 2);              // -> length-delimited（嵌套 message）
...
499:     public void m0(int i, String str) throws IOException {
500:         o0(i, 2);              // -> length-delimited（string）
...
533:     public void p0(int i, int i2) throws IOException {
534:         o0(i, 0);              // -> varint（int32）
...
542:     public void r0(int i, long j) throws IOException {
543:         o0(i, 0);              // -> varint（int64）
```

`o0(i, wireType)` 即写 tag：`CodedOutputByteBufferNano.java:529-531`

```java
529:     public void o0(int i, int i2) throws IOException {
530:         g0(eju.d(i, i2));      // eju.d(fieldNumber, wireType)
531:     }
```

> **陷阱提醒**：`W()` 与 `p0()` **都写 varint**，但 `W()` 走的是 `X()`（zigzag，对应 `.proto` 的 `sint32`），`p0()` 走的是 `q0()`→`g0()`（普通 varint，对应 `int32`）。**仅凭 "varint" 无法区分 int32 与 sint32**，必须看调用的是哪个方法。下文对每个字段都标了实际方法名。

### 1) `pyt` —— V1 认证信封

`defpackage/pyt.java:8-12`（字段声明）

```java
 8: public final class pyt extends lh9<pyt> {
 9:     public int c = 0;      // oneof case 选择子
10:     public Object d;       // oneof 载荷
11:     public int e;          // field 1
12:     public int f;          // field 2
```

`defpackage/pyt.java:92-96`（编码）

```java
92:     public void j(CodedOutputByteBufferNano codedOutputByteBufferNano) throws IOException {
93:         codedOutputByteBufferNano.W(1, this.e);      // field 1, sint32
94:         codedOutputByteBufferNano.p0(2, this.f);     // field 2, int32
```

`defpackage/pyt.java:95-160` 的 oneof 分支：`c == 3` 写 `Y(3, …)`、`c == 4` 写 `Y(4, …)`、`c == 6..25` 写对应 `Y(n, …)`、`c == 100` 写 `S(100, int)`。

解码侧 `defpackage/pyt.java:195-222`：

```java
195:     public pyt e(vj4 vj4Var) throws IOException {
...
201:             if (iA == 8) {                   // field 1
202:                 int iP = vj4Var.p();
203:                 if (iP == 0 || iP == 1 || iP == 2) {   // ← 枚举白名单：只有 0/1/2
204:                     this.e = iP;
...
206:             } else if (iA == 16) {           // field 2 (varint)
207:                 this.f = vj4Var.B();
208:             } else if (iA == 26) {           // field 3, wire 2
209:                 if (this.c != 3) {
210:                     this.d = new va0();
...
214:             } else if (iA == 800) {          // field 100, wire 0
215:                 this.d = Integer.valueOf(vj4Var.n());
216:                 this.c = 100;
```

**还原的 .proto：**

```proto
message Pyt {
  sint32 type = 1;                   // 枚举白名单 {0,1,2}；本 App 只发 1
  int32  cmd  = 2;                   // 命令号
  oneof body {
    Va0    va0  = 3;                 // 主载荷（本 App 唯一使用的分支）
    // 注意：field 4/6..25 在编解码器里也存在，但本版本未构造
    int32  code = 100;               // 错误码
  }
}
```

- 初稿写 `int32 type = 1`。按编码方法 `W()`（zigzag）**应为 `sint32`**。因为只发 0/1/2，线格式完全相同，不影响抓包解析，但生成 `.proto` 时要写对。
- `defpackage/qyt.java`（同为 `defpackage` 下的另一套信封，用于 Eco/体脂秤设备）结构完全一致，`qyt.e` = field 1、`qyt.f` = field 2、oneof arm 多得多（`qyt.java:268-274` 等）。**两套信封不要混用**：`pyt` 属于 miwear-core（`classes3.dex`），`qyt` 属于 Eco（`classes9.dex`）。

### 2) `va0` —— 33 路 oneof（初稿表格有遗漏）

`defpackage/va0.java:9-11`

```java
 9: public final class va0 extends lh9<va0> {
10:     public int c = 0;
11:     public Object d;
```

**认证相关字段的选择子（权威出处：解码 switch，`defpackage/va0.java:254-451`）**

| field | case 分支 | 实例化类型 | 行号 |
|---|---|---|---|
| 1 | `case 8:` | bool | 260-263 |
| 2 | `case 18:` | string | 264-267 |
| 3 | `case 24:` | int（错误码） | 268-271 |
| 4 | `case 34:` | `kb0` | 272-278 |
| 5 | `case 42:` | `sc0` | 279-285 |
| 6 | `case 48:` | bool | 286-289 |
| **7** | `case 58:` | **string（userId）** | 290-293 |
| 8 | `case 64:` | bool（"ready"） | 294-297 |
| 9–20 | `case 74…162` | `bd0,ed0,yc0,nb0,pc0,kc0,ec0,hc0,tb0,zb0,qb0,wb0` | 298-381 |
| 29 | `case 234:` | `vc0` | 382-388 |
| **30** | `case 242:` | **`bb0`**（verify 请求） | 389-395 |
| **31** | `case 250:` | **`hb0`**（device 应答） | 396-402 |
| **32** | `case 258:` | **`ya0`**（confirm 请求） | 403-409 |
| **33** | `case 266:` | **`eb0`**（capability 应答） | 410-416 |
| 34 | `case 274:` | `ld0` | 417-423 |
| 35 | `case 282:` | `nd0` | 424-430 |
| 36 | `case 290:` | `pd0` | 431-437 |
| 37 | `case 298:` | `gd0` | 438-444 |

对应 setter（`defpackage/va0.java:454-472`）：

```java
454:     public va0 w(ya0 ya0Var) {      // field 32
455:         ya0Var.getClass();
456:         this.c = 32;
457:         this.d = ya0Var;
458:         return this;
459:     }
460:
461:     public va0 x(bb0 bb0Var) {      // field 30
462:         bb0Var.getClass();
463:         this.c = 30;
464:         this.d = bb0Var;
465:         return this;
466:     }
467:
468:     public va0 y(String str) {      // field 7
469:         this.c = 7;
470:         this.d = str;
471:         return this;
472:     }
```

类型判定：`field 1/6/8 = bool`（`b()` 用 `CodedOutputByteBufferNano.b(1|6|8, boolean)`，见 `va0.java:20-43`）；`field 2/7 = string`（`v(2|7, String)`）；`field 3 = int32`（`h(3, int)`）；其余为嵌套 message（`n(field, udh)`）。

**结论：初稿 `va0` 表「7=userId(string), 30=bb0, 31=hb0, 32=ya0, 33=eb0」完全正确**；补充：29/34/35/36/37 也是嵌套消息但本版本认证路径未使用。

### 3) `bb0` —— verify 请求

`defpackage/bb0.java:7-37`

```java
 7: public final class bb0 extends lh9<bb0> {
 8:     public byte[] c;
 9:     public String d;
10:     public boolean e;
...
27:     public void j(CodedOutputByteBufferNano codedOutputByteBufferNano) throws IOException {
28:         codedOutputByteBufferNano.O(1, this.c);      // field 1, bytes
29:         if (!this.d.equals("")) {
30:             codedOutputByteBufferNano.m0(2, this.d); // field 2, string
31:         }
32:         boolean z = this.e;
33:         if (z) {
34:             codedOutputByteBufferNano.M(3, z);       // field 3, bool
35:         }
```

字段语义由构造点确定（`com/xiaomi/wearable/wear/api/WearAuthV2.java:106-114`）：

```java
106:         bb0 bb0Var = new bb0();
107:         final byte[] bArrK = itn.k(16);              // SecureRandom 16 字节
108:         bb0Var.c = bArrK;                            // field 1 = randomApp
109:         String str = this.o;
110:         if (str != null) {
111:             bb0Var.d = str;                          // field 2 = appDeviceId
112:             bb0Var.e = true ^ TextUtils.isEmpty(this.n);  // field 3 = 是否带 oob
```

`itn.k()` 的实现（`defpackage/itn.java:112-116`）确认是 16 字节安全随机数：

```java
112:     public static byte[] k(int i) {
113:         byte[] bArr = new byte[i];
114:         new SecureRandom().nextBytes(bArr);
115:         return bArr;
116:     }
```

```proto
message Bb0 {
  bytes  randomApp   = 1;   // 16 字节随机数
  string appDeviceId = 2;
  bool   hasOob      = 3;   // 源码语义：!isEmpty(oob)
}
```

**初稿正确。** 唯一措辞修正：field 3 的字面量不是 `hasOob`，而是 `true ^ TextUtils.isEmpty(this.n)` 即 `!oob.isEmpty()`，语义等价。

### 4) `hb0` —— 设备应答

`defpackage/hb0.java:7-25`

```java
 7: public final class hb0 extends lh9<hb0> {
 8:     public byte[] c;
 9:     public byte[] d;
...
21:     public void j(CodedOutputByteBufferNano codedOutputByteBufferNano) throws IOException {
22:         codedOutputByteBufferNano.O(1, this.c);   // field 1, bytes
23:         codedOutputByteBufferNano.O(2, this.d);   // field 2, bytes
24:         super.j(codedOutputByteBufferNano);
```

消费点 `com/xiaomi/wearable/wear/api/WearAuthV2.java:137-138`：

```java
137:                         hb0 hb0VarP = pytVarA.o().p();
138:                         WearAuthV2.this.k(bArrK, hb0VarP.c, hb0VarP.d);
```

而 `k(bArr, bArr2, bArr3)` 的第 2 参是 `randomDevice`、第 3 参是 `deviceSign`（`WearAuthV2.java:191-196` 的日志标签 `_RandomDevice:` / `_deviceSign:`）。

```proto
message Hb0 {
  bytes randomDevice = 1;   // 16 字节
  bytes deviceSign   = 2;   // HMAC-SHA256(deviceKey, message)
}
```

**初稿正确。**

### 5) `ya0` —— confirm 请求

`defpackage/ya0.java:7-25`

```java
 7: public final class ya0 extends lh9<ya0> {
 8:     public byte[] c;
 9:     public byte[] d;
...
21:     public void j(CodedOutputByteBufferNano codedOutputByteBufferNano) throws IOException {
22:         codedOutputByteBufferNano.O(1, this.c);   // field 1, bytes
23:         codedOutputByteBufferNano.O(2, this.d);   // field 2, bytes
```

构造点 `com/xiaomi/wearable/wear/api/WearAuthV2.java:57-60`：

```java
57:         ya0 ya0Var = new ya0();
58:         ya0Var.c = bArr;      // field 1 = appSign
59:         ya0Var.d = bArr2;     // field 2 = encAppInfo
60:         CoreExtKt.logger.d("WearAuth", "_encryptCompanionDevice:" + ByteUtil.byteToString(bArr2));
```

```proto
message Ya0 {
  bytes appSign    = 1;   // HMAC-SHA256(appKey, message)
  bytes encAppInfo = 2;   // AES-CCM(appKey, appIV‖0‖0, Jd0) 密文 + 4B tag
}
```

**初稿正确。**

### 6) `eb0` —— capability 应答

`defpackage/eb0.java:7-48`

```java
 7: public final class eb0 extends lh9<eb0> {
 8:     public boolean c;
 9:     public int d;
10:     public int e;
11:     public long f;
...
33:     public void j(CodedOutputByteBufferNano codedOutputByteBufferNano) throws IOException {
34:         codedOutputByteBufferNano.M(1, this.c);       // field 1, bool
35:         int i = this.d;
36:         if (i != 0) {
37:             codedOutputByteBufferNano.p0(2, i);       // field 2, int32
38:         }
39:         int i2 = this.e;
40:         if (i2 != 0) {
41:             codedOutputByteBufferNano.p0(3, i2);      // field 3, int32
42:         }
43:         long j = this.f;
44:         if (j != 0) {
45:             codedOutputByteBufferNano.r0(4, j);       // field 4, int64
46:         }
```

消费点 `com/xiaomi/wearable/wear/api/WearAuthV2.java:83-91`：

```java
83:                 eb0 eb0VarO = pytVarA.o().o();
84:                 CoreExtKt.logger.i("WearAuth", "WearAuth deviceConfirm.deviceCapability = " + eb0VarO.d + ", deviceCapabilityV2 = " + eb0VarO.e);
85:                 if (!eb0VarO.c) {
86:                     WearAuthV2.this.g.b(CommonConstants.Mgc.RECHARGE_STATUS_NOT_EXIST, "device confirm failed");
87:                     return;
88:                 }
89:                 WearAuthV2.this.c.setDeviceCapability(eb0VarO.d);
90:                 WearAuthV2.this.c.setDeviceCapabilityV2(eb0VarO.e);
91:                 WearAuthV2.this.c.setDeviceCapabilityV3(eb0VarO.f);
```

```proto
message Eb0 {
  bool  confirm       = 1;
  int32 capability    = 2;
  int32 capabilityV2  = 3;
  int64 capabilityV3  = 4;
}
```

**初稿正确**（且第 83-91 行给出了三档 capability 的落点，可作为语义佐证）。

### 7) `jd0` —— encAppInfo 的明文（初稿有误，订正）

`defpackage/jd0.java:39-57`

```java
39:     public void j(CodedOutputByteBufferNano codedOutputByteBufferNano) throws IOException {
40:         codedOutputByteBufferNano.W(1, this.c);       // field 1, sint32
41:         if (Float.floatToIntBits(this.d) != Float.floatToIntBits(0.0f)) {
42:             codedOutputByteBufferNano.U(2, this.d);   // field 2, fixed32 (float)
43:         }
44:         if (!this.e.equals("")) {
45:             codedOutputByteBufferNano.m0(3, this.e);  // field 3, string
46:         }
47:         int i = this.h;
48:         if (i != 0) {
49:             codedOutputByteBufferNano.p0(4, i);       // field 4, int32
50:         }
51:         if (!this.f.equals("")) {
52:             codedOutputByteBufferNano.m0(5, this.f);  // field 5, string
53:         }
54:         if (!this.g.equals("")) {
55:             codedOutputByteBufferNano.m0(6, this.g);  // field 6, string
56:         }
```

构造点 `com/xiaomi/wearable/wear/api/WearAuthV2.java:208-218`：

```java
208:             jd0 jd0Var = new jd0();
209:             jd0Var.c = 0;                                 // field 1 = platform
210:             jd0Var.d = (float) Build.VERSION.SDK_INT;     // field 2 = sdkInt (float!)
211:             jd0Var.e = Build.MODEL;                       // field 3 = model
212:             jd0Var.f = this.c.getDeviceInfo().getRegion();// field 5 = region
213:             String region = this.c.getDeviceInfo().getRegion();
214:             if (region != null) {
215:                 jd0Var.f = region;
216:             }
217:             jd0Var.h = this.c.getAppCapability();         // field 4 = appCapability
```

```proto
message Jd0 {
  sint32 platform    = 1;   // 实际固定 0
  float  sdkInt      = 2;   // fixed32，Android API level 转 float
  string model       = 3;
  int32  capability  = 4;   // 源码 = getAppCapability()
  string region      = 5;
  string reserved6   = 6;   // 本版本未赋值
}
```

订正点：初稿写 `float sdkInt = 2; ... string reserved6 = 6`，**字段号是对的**，但漏了 `platform` 的 `sint32` 编码，且 `capability` 的取值来源应是 `getAppCapability()`。

### 8) `pyt.cmd` 的全部取值（本版本扫全量源码）

对全树 `pyt`/`qyt` 的 `f = N` 赋值做穷举，`pyt` 只有 3 处：

| cmd | 出处 | 含义 |
|---|---|---|
| 5 | `com/xiaomi/wearable/wear/api/WearAuthV1.java` | V1 verify（userId 走 `va0.y()` → field 7） |
| 26 | `com/xiaomi/wearable/wear/api/WearAuthV2.java:104` | V2 `sendAppVerify` |
| 27 | `com/xiaomi/wearable/wear/api/WearAuthV2.java:55` | V2 `sendAppConfirm` |

`WearAuthV2.java:102-104`

```java
102:         pyt pytVar = new pyt();
103:         pytVar.e = 1;      // type = 1
104:         pytVar.f = 26;     // cmd = sendAppVerify
```

**初稿 cmd 表（5/26/27）正确且完整。**

### 9) 可直接使用的 .proto

```proto
syntax = "proto3";

message Pyt {
  sint32 type = 1;
  int32  cmd  = 2;
  oneof body {
    Va0   va0  = 3;
    int32 code = 100;
  }
}

message Va0 {
  oneof body {
    bool   f1  = 1;
    string f2  = 2;
    int32  code = 3;   // 错误码：4 = device not bound
    // ... 4,5（kb0/sc0）, 6, 8 为 bool
    string userId = 7;
    // ... 9..20 未识别
    Bb0    bb0 = 30;
    Hb0    hb0 = 31;
    Ya0    ya0 = 32;
    Eb0    eb0 = 33;
    // ... 34..37 未识别
  }
}

message Bb0 { bytes randomApp = 1; string appDeviceId = 2; bool hasOob = 3; }
message Hb0 { bytes randomDevice = 1; bytes deviceSign = 2; }
message Ya0 { bytes appSign = 1; bytes encAppInfo = 2; }
message Eb0 { bool confirm = 1; int32 capability = 2; int32 capabilityV2 = 3; int64 capabilityV3 = 4; }

message Jd0 {
  sint32 platform = 1;
  float  sdkInt   = 2;
  string model    = 3;
  int32  capability = 4;
  string region   = 5;
  string reserved6 = 6;
}
```

---

## P1-b. L2 channel 1 上业务消息的识别方法

### 核心事实：channel 1 没有独立 cmd 层

`com/xiaomi/wearable/transport/layerl2/L2Packet.java:33-37`（帧结构）

```java
33: public final class L2Packet {
34:     public static final int HEADER_SIZE = 2;
35:     public static final int L2_CHANNEL_OFFSET = 0;
```

`L2Packet.java` 的 `getBytes()`：

```java
    public final byte[] getBytes() {
        ByteBuffer byteBufferOrder = ByteBuffer.allocate(this.payload.length + 2).order(ByteOrder.LITTLE_ENDIAN);
        byteBufferOrder.put(this.channel);
        byteBufferOrder.put(this.opCode);
        byteBufferOrder.put(this.payload);
```

**即 L2 = `channel(1B) | opcode(1B) | payload`，payload 之后没有任何协议层**——payload 直接就是业务字节（对 channel 1 而言就是 protobuf 的 `pyt`/`oyt` 信封）。

`com/xiaomi/wearable/transport/queue/TaskQueueV2.java:143-168` 的解复用逻辑印证这点：

```java
143:     private final void dispatchMessage(byte channel, byte opCode, byte[] data) {
144:         boolean zChannelEncryption = channelEncryption(opCode);
145:         int iChannelToType = channelToType(channel, zChannelEncryption);
...
159:         CryptoHandlerV2 cryptoHandlerV2 = this.cryptoHandlerV2;
...
164:         byte[] bArrDecryptDataV2 = cryptoHandlerV2.decryptDataV2(data);
165:         if (bArrDecryptDataV2 != null) {
166:             this.dataHandler.handleData(iChannelToType, bArrDecryptDataV2);
167:         }
```

注意 143-168：**解密后直接把整个 payload 交给 `handleData(type, data)`，不做二次拆包**。

### 业务 type 由 `channelToType()` 决定（权威表）

`com/xiaomi/wearable/transport/queue/TaskQueueV2.java:112-141`

```java
112:     private final int channelToType(byte channel, boolean encrypt) {
113:         if (channel == 1) {
114:             return (encrypt || !shouldTreatPlainPbAsAuth()) ? 101 : 100;
115:         }
116:         if (channel == 2) {
117:             return 104;
118:         }
119:         if (channel == 4) {
120:             return 107;
121:         }
122:         if (channel == 5) {
123:             return 102;
124:         }
125:         if (channel == 6) {
126:             return 105;
127:         }
128:         if (channel == 3) {
129:             return 103;
130:         }
131:         if (channel == 7) {
132:             return 108;
133:         }
134:         if (channel == 8) {
135:             return 112;
136:         }
137:         if (channel == 9) {
138:             return 113;
139:         }
140:         return channel == 10 ? 114 : 0;
141:     }
```

`shouldTreatPlainPbAsAuth()`（`TaskQueueV2.java:416-418`）：

```java
416:     public boolean shouldTreatPlainPbAsAuth() {
417:         return this.cryptoHandlerV2 != null;
418:     }
```

**含义：认证握手完成前（`cryptoHandlerV2 == null`）channel 1 的明文包被当作 type 100（TYPE_AUTH）；握手完成后，明文包被当作 type 101（TYPE_PROTO），只有加密包才是 101。** 这一点对抓包判读极关键——**同一个 channel 1 上的明文 protobuf，在握手前后归入不同的业务 type**。

### 业务 type 的权威枚举

`com/xiaomi/wearable/ChannelType.java:17-34`

```java
17: public static final int TYPE_AUTH = 100;
18: public static final int TYPE_CAMERA = 111;
19: public static final int TYPE_CAPTURE = 107;
20: public static final int TYPE_FITNESS = 102;
21: public static final int TYPE_GNSS = 110;
22: public static final int TYPE_INFO = 109;
23: public static final int TYPE_LYRA = 112;
24: public static final int TYPE_MASS = 104;
25: public static final int TYPE_MULTI_MODAL = 114;
26: public static final int TYPE_NET_PROXY = 108;
27: public static final int TYPE_OTA = 105;
28: public static final int TYPE_PROTO = 101;
29: public static final int TYPE_RESREARCH = 113;
30: public static final int TYPE_UNKWOWN = -100;
31: public static final int TYPE_VERSION = 106;
32: public static final int TYPE_VOICE = 103;
33: public static final int TYPE_WEARABLE = 199;
```

`com/xiaomi/miot/core/extensions/WearPacket.java:8-22` 是同表的另一份拷贝（跨模块对齐），值一致。

> **订正初稿**：初稿 §3.1 把 channel↔type 映射写成"双向映射，同一数字在收发两侧含义一致"，方向是对的，但初稿没指出 **channel 1 的 type 会随握手状态在 100/101 之间切换**（`TaskQueueV2.java:114`）。

### 统一信封：`oyt`（不是 `pyt`）

**channel 1 上的业务消息有两套信封并存：**

| 信封 | 类 | dex | 用途 | 结构 |
|---|---|---|---|---|
| V1/V2 认证 | `pyt` | classes3 | 仅认证阶段 | `field1 type, field2 cmd, oneof body(field3 va0), field100 code` |
| **业务主信封** | **`oyt`** | classes3 | **认证后所有 channel 1 业务** | `field1 type, field2 cmd, oneof body(fields 3/4/6…24), field100 code` |

`defpackage/oyt.java:9-21`

```java
 9: public final class oyt extends lh9<oyt> {
10:     public int c = 0;
11:     public Object d;
12:     public int e;       // field 1 = type
13:     public int f;       // field 2 = cmd
...
19:     public static oyt L(byte[] bArr) throws InvalidProtocolBufferNanoException {
20:         return (oyt) udh.f(new oyt(), bArr);
```

`defpackage/oyt.java:502-506`

```java
502:     public void j(CodedOutputByteBufferNano codedOutputByteBufferNano) throws IOException {
503:         codedOutputByteBufferNano.W(1, this.e);    // field 1, sint32
504:         codedOutputByteBufferNano.p0(2, this.f);   // field 2, int32
505:         if (this.c == 3) {
506:             codedOutputByteBufferNano.Y(3, (udh) this.d);
```

**`oyt` 的 oneof arm → 具体消息类**（`defpackage/oyt.java:287-380` 的 setter）：

| field | 消息类 | setter 行号 |
|---|---|---|
| 3 | `ua0` | 287 |
| 4 | `shr` ← **主力载荷** | 474 |
| 6 | `owt` | 488 |
| 7 | `qfi` | 30 |
| 9 | `kli` | 460 |
| 10 | `rma` | 335 |
| 11 | `adg` | 356 |
| 12 | `h0u` | 495 |
| 13 | `ayq` | 467 |
| 14 | `ym3` | 301 |
| 15 | `jz9` | 328 |
| 16 | `p21` | 294 |
| 17 | `oog` | 363 |
| 18 | `n1c` | 342 |
| 19 | `kh4` | 308 |
| 20 | `x5h` | 377 |
| 22 | `yxr` | 481 |
| 23 | `ux4` | 315 |
| 24 | `fqg` | 370 |
| 25 | `vqe` | 349 |
| 30 | `gt8` | 322 |
| 31 | `mv8` | 343 |
| 100 | int code | 322 |

**`shr` 是绝大多数业务的载荷容器**。例：`shr.t0(hhr)` 是 OTA prepare（`shr.java:1495`，field 16）；`shr.j0(rgr)` 是强升通知（`shr.java:1370`，field 6）；`shr.z0(uhr.j)` 是升级设置（`shr.java:1578`，field 34）。

### 识别方法（可落进工具）

抓 channel 1 的 L2 payload 后按以下顺序判定：

1. **opcode==2 → 先解密**（`TaskQueueV2.java:144,164`），得到明文 protobuf。
2. **试解 `pyt`**：若 `field 2 (cmd) ∈ {5,26,27}` 且 `field 3` 是 `va0` → 认证消息（见 P1-a）。
3. **否则试解 `oyt`**：`field 1` 是业务域枚举、`field 2` 是业务命令号、`field 3..25` 任一 arm 是具体消息体。
4. 手工判读时，`oyt` 的 **field 1 已被解码器收窄为白名单**：`{0,1,2,4,5,7..23,32,33}`（`defpackage/oyt.java:95-122`），可直接用来校验解包是否对齐。

`defpackage/oyt.java:95-122`（枚举白名单原样）

```java
 95:                 case 8:
 96:                     int iP = vj4Var.p();
 97:                     switch (iP) {
 98:                         case 0:
 99:                         case 1:
100:                         case 2:
101:                         case 4:
102:                         case 5:
103:                         case 7:
...
119:                         case 23:
120:                             this.e = iP;
```

### 业务域枚举（field 1）实测取值

从全量源码里扫 `oyt.e = N` 与 `qyt.e = N` 的赋值点（业务调用方），主要取值：

| field1 | 出现位置举例 | 业务含义 **【推测】** |
|---|---|---|
| 2 | `com/mi/fitness/checkupdate/util/DeviceSender.java:333,357,366,379,403` | 设备设置/查询域（OTA 相关全在此） |
| 4 | `com/mi/fitness/checkupdate/util/DeviceSender.java:380` | 升级通知 |
| 15 | `com/xiaomi/fitness/devicesettings/.../EightDeviceSyncImpl.java:736` | 八电极体脂 |
| 33 | `com/xiaomi/fitness/configwifi/WifiPBApi.java:34,48,64,73` | WiFi 配网 |

> 【推测】`oyt.field1` 是**设备品类/业务域**（手环、体脂秤、WiFi 配网…），`oyt.field2` 是**域内命令号**。本任务未穷举全部 (field1, field2) 组合——**建议后续用一次真实抓包 + `oyt` 解包做交叉确认**。已有的可直接引用的点：
> - `WifiPBApi`：`(33,4)=configWifi`、`(33,5)=configWifiExtra`、`(33,2)=getWifi`、`(33,30)=restoreWifi`（`com/xiaomi/fitness/configwifi/WifiPBApi.java:34,48,64,73`）。
> - `DeviceSender`：`(2,14)=getHybridMode/getUpgradeSetting`、`(2,90)=getOtaStatus`、`(2,4)=notifyForceUpgrade`、`(2,5)=prepareOta`、`(2,15)=setUpgradeSetting`（`com/mi/fitness/checkupdate/util/DeviceSender.java:333,358,380,404,427`）。

---

## P2-a. Mass 文件传输（channel 2）完整字段布局（**初稿需订正**）

### 接收侧分片头：total/index（u16 LE ×2）

`com/xiaomi/wearable/mass/receiver/MassDataComposer.java:240-263`

```java
240:     public final void onDataReceived(@NotNull byte[] data) throws IOException {
241:         Intrinsics.checkNotNullParameter(data, "data");
242:         ByteBuffer byteBufferOrder = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
...
244:         short s = byteBufferOrder.getShort();     // totalSegment
245:         short s2 = byteBufferOrder.getShort();    // index
246:         if (Intrinsics.compare(UShort.m1213constructorimpl(s2) & UShort.MAX_VALUE, 65535 & UShort.m1213constructorimpl(s) > 0) {
247:             CoreExtKt.getLogger().e(TAG, "onMassDataReceived exception data!!! sequence = " + ((int) s2) + ", total = " + ((int) s));
248:             return;
249:         }
250:         totalSegment = UInt.m1027constructorimpl(s);
251:         if (UShort.m1213constructorimpl(s2) == UShort.m1213constructorimpl(s) && UShort.m1213constructorimpl(s2) == UShort.m1213constructorimpl((short) 1)) {
252:             onSinglePacketReceived(byteBufferOrder, data);
253:             return;
254:         }
255:         short sM1213constructorimpl = UShort.m1213constructorimpl(s2);
256:         if (sM1213constructorimpl == UShort.m1213constructorimpl((short) 1)) {
257:             onFirstPacketReceived(byteBufferOrder, data);
258:         } else if (sM1213constructorimpl == UShort.m1213constructorimpl(s)) {
259:             onLastPacketReceived(byteBufferOrder, data);
260:         } else {
261:             onMiddlePacketReceived(byteBufferOrder, data);
262:         }
263:     }
```

### Header 是 **22 字节**，不是 26

`com/xiaomi/wearable/mass/receiver/Header.java:35-42`

```java
35:         public final Header get(@NotNull ByteBuffer byteBuffer) {
36:             Intrinsics.checkNotNullParameter(byteBuffer, "byteBuffer");
37:             byte b2 = byteBuffer.get();          // encrypt
38:             byte b3 = byteBuffer.get();          // dataType
39:             byte[] bArr = new byte[16];
40:             byteBuffer.get(bArr);                // dataId[16]
41:             return new Header(b2, b3, bArr, byteBuffer.getInt());   // dataLength int32 LE
42:         }
```

**1 + 1 + 16 + 4 = 22 字节。** 而 `data.length - 26` 里的 26 = **4（total+index）+ 22（Header）**：

`MassDataComposer.java:75-77`

```java
75:         int length = data.length - 26;
76:         byte[] bArr = new byte[length];
77:         byteBuffer.get(bArr);
```

### 三段的实际前缀长度

| 段 | 判定条件（`MassDataComposer.java:251-262`） | 前缀 | 源码 |
|---|---|---|---|
| 单包 | `index == total == 1` | **30B**（4 + 22 + 4B CRC32） | `data.length - 30`（`MassDataComposer.java:180`） |
| 首包 | `index == 1` | **26B**（4 + 22） | `data.length - 26`（`:75`） |
| 中间包 | 其它 | **4B**（total+index） | `data.length - 4`（`:140`） |
| 末包 | `index == total` | **8B**（4 + 4B CRC32 尾） | `data.length - 8`（`:90`） |

末包 CRC 在数据之后（`MassDataComposer.java:105`）：

```java
105:         int i = byteBuffer.getInt();
106:         CoreExtKt.getLogger().d(TAG, "onMassDataReceived crc = " + i);
```

### 发送端印证：确凿的 4B 分片头 + 22B Header

`com/xiaomi/wearable/mass/sender/a.java:31-48`（分片）

```java
31:     public static Queue<byte[]> c(MassDataDispatcher.b bVar) {
32:         int i = bVar.d - 4;
33:         int length = bVar.c.length;
34:         short sCeil = (short) Math.ceil(length / (i * 1.0f));
35:         int i2 = length - ((sCeil - 1) * i);
...
40:         while (s <= sCeil) {
41:             int i3 = s == sCeil ? i2 : i;
42:             ByteBuffer byteBufferOrder = ByteBuffer.allocate(i3 + 4).order(ByteOrder.LITTLE_ENDIAN);
43:             byteBufferOrder.putShort((short) bVar.p);            // total  (u16 LE)
44:             byteBufferOrder.putShort((short) (iIntValue + s));   // index  (u16 LE)
45:             byteBufferOrder.put(bVar.c, (s - 1) * i, i3);
```

`com/xiaomi/wearable/mass/sender/MassDataDispatcher.java:164-179`（Header 构造）

```java
164:         public byte[] d() {
165:             byte bS = MassDataDispatcher.s(this.f6409k, this.l);
166:             File file = new File(this.f6408b);
167:             byte[] fileMD5Bytes = MD5Util.getFileMD5Bytes(file);
168:             int length = ((int) file.length()) - this.n;
169:             ByteBuffer byteBufferOrder = ByteBuffer.allocate(22).order(ByteOrder.LITTLE_ENDIAN);
170:             byteBufferOrder.put((byte) 0);              // encrypt = 0（本版本恒 0）
171:             byteBufferOrder.put(bS);                    // dataType（合成字节，见下）
172:             try {
173:                 byteBufferOrder.put(fileMD5Bytes);      // dataId[16] = 文件 MD5 **原始 16 字节**（非 hex）
174:             } catch (Exception e) {
...
177:             byteBufferOrder.putInt(length);             // dataLength int32 LE
```

`ByteBuffer.allocate(22)` 是决定性证据。

### **dataType 是一个"合成字节"，不是两个独立字段**

`com/xiaomi/wearable/mass/sender/MassDataDispatcher.java:271-273`

```java
271:     public static byte s(int i, int i2) {
272:         return (byte) ((i * 16) + i2);
273:     }
```

接收侧对应 `com/xiaomi/wearable/mass/MassCoreClient.java:288-290`：

```java
288:     private final byte getDataTypeByte(int dataType, int dataDetailType) {
289:         byte b2 = (byte) ((dataType * 16) + dataDetailType);
290:         com.xiaomi.wearable.core.CoreExtKt.logger.i(TAG, "getDataTypeByte: " + ((int) b2));
```

**语义：`dataType` 字节 = `dataType << 4 | subType`。高 4 bit = 大类，低 4 bit = 子类。**

> **这一条直接推翻初稿 §7.2 的 "`byte encrypt | byte dataType | byte[16] dataId | int dataLength`（两个独立字节）"** —— 第二字节是合成值，拆成 `>>4` 与 `&0x0F` 才有意义。

### 完整性校验：MD5 而非 CRC

`MassDataComposer.java:113-121`

```java
113:         String absolutePath = file.getAbsolutePath();
114:         Intrinsics.checkNotNullExpressionValue(absolutePath, "getAbsolutePath(...)");
115:         String fileMD5 = MD5Util.getFileMD5(absolutePath);
116:         String name = file.getName();
117:         if (!StringsKt.equals(name, fileMD5, true)) {
118:             CoreExtKt.getLogger().e(TAG, "onMassDataReceived: md5 mismatch expected=" + name + " actual=" + fileMD5);
119:             clear();
120:             return;
121:         }
```

**校验方式 = 把收到的文件算 MD5，与"文件名"比较（忽略大小写）。** 而文件名就是 header 里 `dataId` 的 hex 形式（`Header.java:123-131` 的 `getDataIdString()` 用 `"%02x"` 逐字节拼接）。发送端 `dataId` 直接填 `MD5Util.getFileMD5Bytes(file)`（`MassDataDispatcher.java:167,173`），即 16 字节原始摘要。

### 准确的线格式

```
Mass 分片（channel 2 的 payload）:
  offset  0  : u16 LE totalSegment      // 本文件的下一级分片总数
  offset  2  : u16 LE index             // 1-based；total==index==1 → 单包
  offset  4  : Header (22B, 仅 index==1 或单包时存在)
               +0  u8     encrypt      // 本版本发送端恒 0（MassDataDispatcher.java:170）
               +1  u8     dataType     // = (dataType<<4) | subType
               +2  [16]   dataId       // 文件 MD5 原始 16 字节
               +18 i32 LE dataLength   // 文件总长
  之后          : 文件内容分片
  末包/单包尾部 : i32 LE CRC32          // 接收端只记录不使用（MassDataComposer.java:105,195）
```

**校验真正用的是 MD5（对比文件名），CRC32 字段仅落日志。**

---

## P2-b. channel 5 运动数据：BER-TLV（sport800）tag 表

### 先厘清层次关系（初稿易误解）

初稿 §7.4 把 `sport800` 放在 "application layer / channel 5" 下，容易被读成"channel 5 就是 BER-TLV"。源码显示**实际是两层**：

1. channel 5（type 102 `TYPE_FITNESS`）的 payload 仍是 **protobuf** —— summary 明确用 protobuf 解（`SportSummary800Parser.java:38` 的 `SportSummary2.SportSummaryMessage.parseFrom(bytes)`）。
2. **只有 detail（明细）那一段**才是 BER-TLV：`SportDetail800DataParser.parser()` 把字节追加到内部 `ByteBuf` 再走 BER 解析。

`com/xiaomi/hm/health/bt/profile/gdsp/gps/sport800/SportDetail800DataParser.java:149-166`

```java
149:     public void parser(@NotNull SportDetail detail, @NotNull byte[] value, long startTime) {
...
153:         getDetailBytesBuf().writeBytes(value);
...
157:                 if (this.berTag.needContinue()) {
158:                     this.berTag.feed(getDetailBytesBuf().readByte());
159:                 } else if (!this.berLength.needContinue()) {
160:                     number = this.berTag.getNumber();
161:                     byte[] bArr = new byte[this.berLength.getLength()];
162:                     getDetailBytesBuf().readBytes(bArr);
163:                     this.berTag.reset();
164:                     this.berLength.reset();
165:                     Function1<byte[], BaseNode> function1 = SportUtilsKt.getParserMap().get(Integer.valueOf(number));
166:                     BaseNode baseNodeInvoke2 = function1 != null ? function1.invoke2(bArr) : null;
```

**注意 153 行：数据是先累积在 ByteBuf 里的，说明一个 BER 节点可以跨多个 channel 5 分片** —— 解析器允许跨包续传。

### BER 编解码规则

**Tag**（`com/xiaomi/hm/health/bt/profile/gdsp/gps/sport800/ber/BerTag.java:26-53`）

```java
26:     public final int getNumber() throws BerTagException {
27:         if (needContinue()) {
28:             throw new BerTagException("Tag not complete while extract number");
29:         }
30:         if (this.byteArray.size() == 1) {
31:             return ((Number) CollectionsKt.first((List) this.byteArray)).byteValue() & 31;
32:         }
33:         int size = this.byteArray.size();
34:         int iByteValue = 0;
35:         for (int i = 1; i < size; i++) {
36:             iByteValue = (iByteValue << ((i - 1) * 7)) | (this.byteArray.get(i).byteValue() & 127);
37:         }
38:         return iByteValue;
39:     }
...
45:     public final boolean needContinue() {
46:         if (this.byteArray.isEmpty()) {
47:             return true;
48:         }
49:         if (this.byteArray.size() == 1) {
50:             return (((Number) CollectionsKt.first((List) this.byteArray)).byteValue() & 31) == 31;
51:         }
52:         return (((Number) CollectionsKt.last((List) this.byteArray)).byteValue() & 128) == 128;
53:     }
```

- 单字节 tag：取 `byte & 0x1F`（**丢弃高 3 bit 的 class 位**）。
- 首字节低 5 位 == `0x1F` → 多字节 tag，后续字节 7 bit/字节、续位为 bit7。
- **本实现只有 1 字节和 2 字节两种实践**（`getNumber()` 的多字节分支按 `(i-1)*7` 左移，2 字节时即 `((b[1]&0x7F) << 0) | 0`，实际等价于只有 1 个后续字节有效）。

**Length**（`com/xiaomi/hm/health/bt/profile/gdsp/gps/sport800/ber/BerLength.java:36-62`）

```java
36:     public final int getLength() throws BerTagException {
37:         if (needContinue()) {
38:             throw new BerTagException("Tag not complete while extract number");
39:         }
40:         byte bByteValue = ((Number) CollectionsKt.first((List) this.byteArray)).byteValue();
41:         int i = bByteValue & 255;
42:         if ((bByteValue & 128) != 128) {
43:             return i;
44:         }
45:         int i2 = bByteValue & 127;
46:         if (i2 > 3) {
...
50:             throw new IllegalStateException(str.toString());
51:         }
52:         int i3 = i2 + 1;
53:         int iByteValue = 0;
54:         for (int i4 = 1; i4 < i3; i4++) {
55:             iByteValue = (iByteValue << 8) | (this.byteArray.get(i4).byteValue() & 255);
56:         }
57:         return iByteValue;
58:     }
```

- 首字节 bit7 == 0 → 短格式，长度 = `byte`。
- 首字节 bit7 == 1 → 长格式，后续 `&0x7F` 个字节 **大端** 组成长度，且 **最多 3 字节**。

### Tag 表（tag → node 类，`SportUtilsKt.java:79` 权威原文）

`com/xiaomi/hm/health/bt/profile/gdsp/gps/sport800/SportUtilsKt.java:79`

```java
 79:     private static final Map<Integer, Function1<byte[], BaseNode>> parserMap = MapsKt.mapOf(
        TuplesKt.to(1,  new SportUtilsKt$parserMap$1(TimeStampNode.INSTANCE)),
        TuplesKt.to(2,  new SportUtilsKt$parserMap$2(FullGpsNode.INSTANCE)),
        TuplesKt.to(3,  new SportUtilsKt$parserMap$3(DiffGpsNode.INSTANCE)),
        TuplesKt.to(4,  new SportUtilsKt$parserMap$4(EventNode.INSTANCE)),
        TuplesKt.to(5,  new SportUtilsKt$parserMap$5(PaceNode1.INSTANCE)),
        TuplesKt.to(6,  new SportUtilsKt$parserMap$6(PaceNode2.INSTANCE)),
        TuplesKt.to(7,  new SportUtilsKt$parserMap$7(AltNode.INSTANCE)),
        TuplesKt.to(8,  new SportUtilsKt$parserMap$8(HeartRateNode.INSTANCE)),
        TuplesKt.to(9,  new SportUtilsKt$parserMap$9(Spo2Node.INSTANCE)),
        TuplesKt.to(10, new SportUtilsKt$parserMap$10(FixedLapNode.INSTANCE)),
        TuplesKt.to(11, new SportUtilsKt$parserMap$11(LapNode.INSTANCE)),
        TuplesKt.to(12, new SportUtilsKt$parserMap$12(PressureNode.INSTANCE)),
        TuplesKt.to(13, new SportUtilsKt$parserMap$13(TemperatureNode.INSTANCE)),
        TuplesKt.to(14, new SportUtilsKt$parserMap$14(AltitudeCalibration.INSTANCE)),
        TuplesKt.to(15, new SportUtilsKt$parserMap$15(StrengthGroupNode.INSTANCE)),
        TuplesKt.to(16, new SportUtilsKt$parserMap$16(GolfGroupNode.INSTANCE)),
        TuplesKt.to(17, new SportUtilsKt$parserMap$17(GolfRtNode.INSTANCE)),
        TuplesKt.to(18, new SportUtilsKt$parserMap$18(RtPowerNode.INSTANCE)),
        TuplesKt.to(19, new SportUtilsKt$parserMap$19(PlaygroundNode.INSTANCE)));
```

（原文为单行，此处按 `TuplesKt.to(N, …)` 逐项换行以便阅读；内容未改动。）

### 每个 node 的字段位宽（全部从 `parse()` 原文提取）

> 读取器说明：`anw.v(byte[], offset, len)` / `anw.d(byte[], offset, len)` **都是小端**，实现见 `defpackage/anw.java:270-276`：
> ```java
> 270:     public static long v(byte[] bArr, int i, int i2) {
> 271:         long j = 0;
> 272:         for (int i3 = 0; i3 < i2; i3++) {
> 273:             j |= (((long) bArr[i + i3]) & 255) << (i3 * 8);
> 274:         }
> 275:         return j;
> 276:     }
> ```
> `defpackage/d3.java:66-72` 的 `c()/d()` 是 2B/1B 小端，`d3.java:120-122` 的 `a()` 是 float，`d3.java:74-85` 是 4B/8B 小端。

| tag | 语义 | 字节布局（全部小端） | 源码出处 |
|---|---|---|---|
| **1** | 时间戳 | `u64 time`（偏移 0，8B） | `TimeStampNode.java:26` `new TimeStampNode(anw.u(byteArray, 4))` ⚠️见注1 |
| **2** | 全量 GPS 点 | `u16 timeDiff, i16 lng, i16 lat, u16 type`（8B） | `FullGpsNode.java:29-35` |
| **3** | 差分 GPS 点 | `u16 timeDiff, i16 dLng, i16 dLat, u16 type`（8B） | `DiffGpsNode.java:29` |
| **4** | 事件 | `u16 timeDiff, u16 event`（4B） | `EventNode.java:28` |
| **5** | 步频/步幅/配速 | `u16 timeDiff, u16 freq, u16 stride, u16 pace`（8B） | `PaceNode1.java:29` |
| **6** | 步频/配速（精简） | `u16 timeDiff, u16 freq, u16 pace`（6B） | `PaceNode2.java:27` |
| **7** | 海拔 | `u16 timeDiff, i32 alt×100`（6B） | `AltNode.java:26` |
| **8** | 心率 | `u16 timeDiff, u8 bpm`（3B） | `HeartRateNode.java:26` |
| **9** | 血氧 | `u16 timeDiff, u8 spo2`（3B） | `Spo2Node.java:26` |
| **10** | 定距计圈 | `u16 timeDiff, u16 unit, u32 distance, u8 ?`（9B） | `FixedLapNode.java:28` |
| **11** | 计圈 | 见 LapNode.parse | `LapNode.java:27-29` |
| **12** | 气压 | `u16 timeDiff, u8 pressure`（3B） | `PressureNode.java:26` |
| **13** | 温度 | `u16 timeDiff, f32 temp`（6B） | `TemperatureNode.java:27` |
| **14** | 海拔校准 | `u16 timeDiff, i32 alt×100`（6B） | `AltitudeCalibration.java:26` |
| **15** | 力量训练组 | 见 StrengthGroupNode | `StrengthGroupNode.java` |
| **16** | 高尔夫组 | 见 GolfGroupNode | `GolfGroupNode.java` |
| **17** | 高尔夫实时 | 见 GolfRtNode | `GolfRtNode.java` |
| **18** | 实时功率 | 见 RtPowerNode | `RtPowerNode.java` |
| **19** | 操场/跑道 | 见 PlaygroundNode | `PlaygroundNode.java` |

**注 1（重要陷阱）**：`TimeStampNode.java:26` 是

```java
26:             return new TimeStampNode(anw.u(byteArray, 4));
```

而 `anw.u(bArr, i)` = `v(bArr, i, 8)`（`anw.java:266-268`），即 **从偏移 4 读 8 字节**。但 Tag 1 的 `length` 字段只包住 `byteArray` 本身——若 `length == 8`，从偏移 4 读 8 字节会**越界 4 字节**。这与其它 node 一律「u16 timeDiff 打头」的范式不符。**判定为 jadx/源码缺陷，或者是 `length` 被固定写成 12。**
【推测】实际设备上 tag 1 的 length 很可能是 **12**（4 字节填充 + 8 字节时间戳）。**这条必须用真实抓包验证**，验证方法：抓到的 detail 流里第一个 BER 节点若是 `0x01 <len> ...`，直接看 len 是否为 12。

**事件枚举**（`SportEvent.java:10-17`）

```java
10:     NODE_EVENT_NONE(-1),
11:     NODE_EVENT_START(1),
12:     NODE_EVENT_AUTO_PAUSE(2),
13:     NODE_EVENT_AUTO_RESUME(3),
14:     NODE_EVENT_PAUSE(4),
15:     NODE_EVENT_RESUME(5),
16:     NODE_EVENT_STOP(6),
17:     NODE_EVENT_SECOND_HALF(7);
```

**时间锚点机制**（对还原时间轴很关键）：tag 1 出现时把 `timeAnchor` 设为其 `time`，其它节点的 `timeDiff` 都是相对该锚点的偏移。

`SportDetail800DataParser.java:167-168`

```java
167:                     if (baseNodeInvoke2 instanceof TimeStampNode) {
168:                         this.timeAnchor = ((TimeStampNode) baseNodeInvoke2).getTime();
```

---

## P2-c. 固件 OTA（channel 6？——**订正：实际走 channel 2 的 Mass**）

### 结论

**本版本 3.59.1 的固件升级不走 channel 6，而是复用 Mass（channel 2）**。channel 6（`TRANSPORT_CHANNEL_OTA = 6`）虽然有常量定义，但**全树找不到任何构造方**。

### 证据 1：`L2Packet.Channel.TRANSPORT_CHANNEL_OTA = 6` 只是常量

`com/xiaomi/wearable/transport/layerl2/L2Packet.java:39,67`

```java
 39:         public static final byte TRANSPORT_CHANNEL_OTA = 6;
...
 67:                     return "TRANSPORT_CHANNEL_OTA";
```

全树检索 `TRANSPORT_CHANNEL_OTA` 仅命中 `L2Packet.java` 自身（定义 + `getReadableChannel` 字符串）。**没有任何地方构造 channel 6 的 `L2Packet`。**

### 证据 2：OTA 任务被翻译成 Mass 任务

`TaskQueueV2.getChannel(WearApiTask)`（`com/xiaomi/wearable/transport/queue/TaskQueueV2.java:426-456`）里，`case 105` 确实映射到 `(byte) 6`：

```java
437:             case 105:
438:                 return (byte) 6;
```

**但 3.59.1 的升级调用链根本不产生 type 105 的任务**，而是走 Mass：

`com/mi/fitness/checkupdate/ota/GeneralOtaExecutor.java:38-48`

```java
 38:     private final int getOtaDetailType() {
 39:         return this.otaType != 1 ? 0 : 15;
 40:     }
 41:
 42:     private final void sendOtaFile() {
...
 48:         int iSendFile = DeviceSyncExtKt.getInstance(DeviceContact.INSTANCE).sendFile(did, 2, getOtaDetailType(), getMFile().getAbsolutePath(), this.mSegmentLength, new SyncStateListener() {
```

第 48 行的 `sendFile(did, 2, ...)` 第 2 参 = **`type = 2`**。

### 证据 3：type=2 → dataType 字节 = 0x20 或 0x2F

`MassDataDispatcher.s(dataType, subType) = dataType*16 + subType`（`MassDataDispatcher.java:271-272`），代入 `dataType = 2`：

- `detailType = 0` → 头部字节 **`0x20`**
- `detailType = 15`（`otaType == 1`，华米/Zepp 系）→ 头部字节 **`0x2F`**

### 证据 4：`sendFile` 的第 2 参语义确认

`com/xiaomi/fitness/device/contact/export/DeviceContact.java:145`

```java
145: int sendFile(@Nullable String did, int type, int detailType, @Nullable String path, int segmentLength, @Nullable SyncStateListener listener, int linkType);
```

`com/xiaomi/fitness/device/contact/remote/DeviceContactEngineImpl.java:135` 把它按序转给 Mass 层：

```java
135:         return companion.sendFile(did, linkType, type, detailType, path, segmentLength, opgVar, massTransferDeviceInfo);
```

`com/xiaomi/wearable/mass/client/MassTransferImpl.java:1727-1746` 再打包成 `FileTask(did, linkType, type, detailType, path, segmentLength, callback, …)`：

```java
1727:     public int sendFile(@Nullable String did, int linkType, int type, int detailType, @NotNull String path, int segmentLength, @NotNull opg callback, @Nullable MassTransferDeviceInfo deviceInfo) {
...
1746:         FileTask fileTask = new FileTask(did, linkType, type, detailType, path, segmentLength, callback, null, str, str2, mac, 128, null);
```

### 证据 5：OTA 的**控制面**在 channel 1 的 `oyt` 信封里（不是 channel 6）

`com/mi/fitness/checkupdate/util/DeviceSender.java:399-416`（prepareOta）

```java
399:     public final void prepareOta(boolean force, int type, @Nullable String firmwareVersion, @Nullable String fileMd5, @Nullable Integer fileSize, @Nullable String changeLog, @NotNull Function1<? super jhr, Unit> onResult, @NotNull Function1<? super Integer, Unit> onError) {
...
402:         oyt oytVar = new oyt();
403:         oytVar.e = 2;                  // 业务域 = 2
404:         oytVar.f = 5;                  // 命令号 = 5 (prepare)
405:         hhr hhrVar = new hhr();
406:         hhrVar.c = force;
407:         hhrVar.d = type;
408:         hhrVar.e = firmwareVersion;
409:         hhrVar.f = fileMd5;
410:         hhrVar.h = fileSize != null ? fileSize.intValue() : 0;
411:         hhrVar.g = changeLog;
412:         shr shrVar = new shr();
413:         shrVar.t0(hhrVar);             // shr.field16 = hhr
414:         oytVar.d0(shrVar);             // oyt.field4 = shr
```

`DeviceSender.java:353-360`（getOtaStatus）

```java
353:     public final void getOtaStatus(@NotNull Function1<? super cgr.e, Unit> onResult, @NotNull Function1<? super Integer, Unit> onError) {
...
356:         oyt oytVar = new oyt();
357:         oytVar.e = 2;
358:         oytVar.f = 90;                 // 命令号 = 90 (查询状态)
```

### OTA 完整流程（从源码还原）

```
① 云端查版本 → 下载固件到本地
② channel 1: oyt{ type=2, cmd=5, shr{ field16: hhr{force,type,fwVer,md5,size,changelog} } }
       → 设备回 prepareRsp（含 jhr，含 massId / segmentLength 等）
③ channel 1: oyt{ type=2, cmd=90 } 轮询状态
④ channel 2: Mass 传固件
       分片头 u16 total | u16 index | (index==1) Header{encrypt=0, dataType=0x20|0x2F, dataId=MD5(16B), dataLength} | 数据
       末包尾 i32 CRC32
⑤ channel 1: oyt{ type=2, cmd=4, shr{ field6: rgr{force,version} } }   强升通知
⑥ channel 1: oyt{ type=2, cmd=14, shr{ field34: uhr.j } }              升级设置（WLAN/空闲）
⑦ channel 1: oyt{ type=2, cmd=15, shr{ field35: uhr } }                写升级设置
```

对应的 `shr` 字段号出处：
- `shr.t0(hhr)` → field **16**（`defpackage/shr.java:1495-1501`）
- `shr.j0(rgr)` → field **6**（`shr.java:1370`）
- `shr.z0(uhr.j)` → field **34**（`shr.java:1578`）
- `shr.y0(uhr)` → field **35**（`shr.java:1564`）

`GeneralOtaExecutor.java:94`（暂停）

```java
 94:         DeviceSyncExtKt.getInstance(DeviceContact.INSTANCE).pauseFile(did, this.massId, 2, getOtaDetailType());
```

### 订正结论

| 文档 | 原说法 | 订正 |
|---|---|---|
| `docs/miwear_ble_protocol.md` §3.1 | "6 = `OTA`，固件升级" | 常量存在，但 **3.59.1 不用它传固件**；固件走 Mass(channel 2) |
| `docs/PROTOCOL.md` L2 表 | "6 `TRANSPORT_CHANNEL_OTA` — firmware update" | 同上；应标注"保留但本版本未使用" |

> **对 `miwear` 工具的影响**：`constants.py` 里 channel 6 的名字可以保留，但**不要**按"channel 6 = OTA 流"去写解析器；要解 OTA 得先解 channel 1 的 `oyt{type=2,cmd=5}` 拿 prepareRsp，再按 Mass 解 channel 2 且 `dataType>>4 == 2`。

---

## P3. 顺带发现（不在原任务清单，但对工具实现有直接影响）

### 1) 通知超时门限 = 40s（不是 10s）

`com/xiaomi/wearable/mass/sender/MassDataDispatcher.java:431-434`

```java
431:                     if (System.currentTimeMillis() - MassDataDispatcher.this.i > 40000) {
432:                         opgVar.onFail(105, "timeout");
433:                         return;
434:                     }
```

【推测】这是 Mass **分片级**超时（40s），与 L1 的 `SAR_SEND_TIMEOUT = 10000ms` 是两个不同层级，不矛盾。

### 2) Mass 分片大小 = `segmentLength - 4`，首包再减 22，末包再减 4

`MassDataDispatcher.java:291-300`

```java
291:     public static int v(b bVar, int i, int i2, int i3) {
292:         int iMax = Math.max(0, i3 - 4);
293:         if (bVar.i && i == 0) {
294:             iMax -= 22;
295:         }
296:         if (bVar.j && i == i2 - 1) {
297:             iMax -= 4;
298:         }
299:         return Math.max(0, iMax);
300:     }
```

`a.java:32` 也印证 `int i = bVar.d - 4;`（每片预留 4 字节分片头）。

### 3) `WearAuthV2` 的 message 构造在第 2 次签名时被复用并覆写

`com/xiaomi/wearable/wear/api/WearAuthV2.java:180-206`

```java
179:             if (TextUtils.isEmpty(this.n)) {
180:                 bArr4 = new byte[bArr.length + bArr2.length];
181:                 System.arraycopy(bArr2, 0, bArr4, 0, bArr2.length);      // randomDevice
182:                 System.arraycopy(bArr, 0, bArr4, bArr2.length, bArr.length); // randomApp
183:             } else {
184:                 byte[] bytes = this.n.getBytes();
185:                 byte[] bArr7 = new byte[bArr.length + bArr2.length + bytes.length];
186:                 System.arraycopy(bArr2, 0, bArr7, 0, bArr2.length);
187:                 System.arraycopy(bArr, 0, bArr7, bArr2.length, bArr.length);
188:                 System.arraycopy(bytes, 0, bArr7, bArr2.length + bArr.length, bytes.length);
189:                 bArr4 = bArr7;
190:             }
...
194:             byte[] bArrA = ffc.a(this.j, bArr4);          // HMAC(deviceKey, msg)
...
204:             System.arraycopy(bArr, 0, bArr4, 0, bArr.length);
205:             System.arraycopy(bArr2, 0, bArr4, bArr.length, bArr2.length);
206:             byte[] bArrA2 = ffc.a(this.f6425k, bArr4);    // HMAC(appKey, msg)
```

**关键：同一段代码里存在三种不同的"消息拼接"。**

| 用途 | 行号 | 内容 | 顺序 |
|---|---|---|---|
| **HKDF salt** | 161-164 (`bArr5`) | `randomApp ‖ randomDevice` | **app 在前** |
| **deviceSign 校验** | 180-190 (`bArr4`) | `randomDevice ‖ randomApp ‖ oob` | **device 在前**，且带 oob |
| **appSign 计算** | 204-206（复用 `bArr4`） | `randomDevice ‖ randomApp ‖ oob` | **device 在前**，且带 oob |

> **订正本报告早先的推测**：我原先以为"appSign 会丢掉 oob 后缀"，逐行核对后**这个推测是错的**：
> - 行 204-205 用 `arraycopy` 把 `randomApp`、`randomDevice` **覆盖写入 `bArr4` 的前 32 字节**；
> - 行 185-189 分配的 `bArr7` 长度是 `randomApp.len + randomDevice.len + oob.len`，所以 `bArr4[32..]` **仍保留行 188 写入的 oob 字节**；
> - 行 206 `ffc.a(this.f6425k, bArr4)` 传的是 `bArr4` 完整引用，长度未被截断。
>
> **结论：appSign 与 deviceSign 用的是完全相同的一段 `bArr4`（`randomDevice ‖ randomApp ‖ oob`），只是一个用 `appKey`、一个用 `deviceKey`。**

> **真正的坑在这里**：`docs/PROTOCOL.md` 与中文初稿都写 `msg = randomApp ‖ randomDevice`，并把同一个 msg 同时用作 HKDF salt **和** 签名消息。但源码中：
> - **HKDF salt = `randomApp ‖ randomDevice`**（行 161-164）—— 与文档一致；
> - **签名消息 = `randomDevice ‖ randomApp`**（行 180-190，device 在前）—— **与文档相反**。
>
> **用文档的写法去校验 deviceSign 会失败。** 这是本次分析中最容易踩、后果最直接的一处订正。
>
> 但注意：**HKDF 的 salt 用的是 `bArr5`（行 161-164），即 `randomApp ‖ randomDevice`**：
> ```java
> 161:         byte[] bArr5 = new byte[bArr.length + bArr2.length];
> 162:         System.arraycopy(bArr, 0, bArr5, 0, bArr.length);          // randomApp
> 163:         System.arraycopy(bArr2, 0, bArr5, bArr.length, bArr2.length); // randomDevice
> 164:         byte[] bArrI = itn.i("miwear-auth", this.f13866b, bArr5);
> ```
> **所以 HKDF salt ≠ 签名 message。这是三份文档都没写清的地方。**

建议 `miwear/crypto.py` 明确拆成两个独立函数并各自覆盖测试：

```python
# HKDF salt：app 在前
hkdf_salt = random_app + random_device

# 签名/校验消息：device 在前，后接 oob（oob 为空时省略）
sign_message = random_device + random_app + oob_bytes

device_sign = hmac_sha256(device_key, sign_message)   # 校验设备发来的
app_sign    = hmac_sha256(app_key,    sign_message)   # 回给设备的 ya0.appSign
```

### 3b) `ByteUtil.equals` 是"前缀比较"，不是全长比较（安全缺陷）

`com/xiaomi/wearable/utils/ByteUtil.java:97-109`

```java
 97:     public static final boolean equals(@Nullable byte[] bArr, @Nullable byte[] bArr2) {
 98:         return equals$default(bArr, bArr2, 0, 4, null);
101:     public static /* synthetic */ boolean equals$default(byte[] bArr, byte[] bArr2, int i, int i2, Object obj) {
102:         if ((i2 & 4) != 0) {
103:             Intrinsics.checkNotNull(bArr);
104:             int length = bArr.length;
105:             Intrinsics.checkNotNull(bArr2);
106:             i = Math.min(length, bArr2.length);     // ← len = min(两者长度)
107:         }
108:         return equals(bArr, bArr2, i);
109:     }
```

`ByteUtil.java:406-419`

```java
406:     public static final boolean equals(@Nullable byte[] array1, @Nullable byte[] array2, int len) {
407:         if (Intrinsics.areEqual(array1, array2)) {
408:             return true;
409:         }
410:         if (array1 == null || array2 == null || array1.length < len || array2.length < len) {
411:             return false;
412:         }
413:         for (int i = 0; i < len; i++) {
414:             if (array1[i] != array2[i]) {
415:                 return false;
416:             }
417:         }
418:         return true;
419:     }
```

**后果：只要前 `min(len)` 字节相同就判等。** 若设备返回的 `deviceSign` 被截短，App 端仍可能判"校验通过"（`WearAuthV2.java:197` 用的正是这个方法）。

> **对工具的两点要求**：
> 1. 我们的实现必须做**全长比较**（`hmac.compare_digest`），**不要**模仿这个行为；
> 2. 但在**抓包比对**时要意识到——"App 日志显示 verify sign success"**不能**反证签名算式已完全正确，尤其当 deviceSign 长度异常时。

### 4) `itn.i()` 的真实 HKDF 输出长度是 **64**，不是 40

`defpackage/itn.java:87-96`

```java
87:     public static byte[] i(String str, byte[] bArr, byte[] bArr2) {
88:         try {
89:             sid sidVarE = sid.e("HmacSHA256");
90:             sidVarE.f(bArr, bArr2);
91:             return sidVarE.d(str.getBytes(), 64);
92:         } catch (NoSuchAlgorithmException e) {
93:             e.printStackTrace();
94:             return null;
95:         }
96:     }
```

第 91 行输出 **64 字节**，而 `WearAuthV2.k()` 只取了前 40 字节（`WearAuthV2.java:170-173`）。

> **结论：`HKDF_OUTPUT_LEN = 40` 在 `miwear/crypto.py` 里是正确的"实际用量"**，但若有人想逐字节比对 HKDF 输出，要按 **64** 展开。两者由于 HKDF-Expand 的前缀性质，**前 40 字节完全一致**，所以现有实现不用改。

### 5) `sid.f()` = HKDF-Extract，`sid.d()` = HKDF-Expand，参数顺序已确认

`defpackage/sid.java:101-125`（Extract）

```java
101:     public void f(byte[] bArr, byte[] bArr2) {
102:         byte[] bArr3 = bArr2 == null ? d : (byte[]) bArr2.clone();
...
107:                 Mac mac = provider != null ? Mac.getInstance(this.a, provider) : Mac.getInstance(this.a);
108:                 if (bArr3.length == 0) {
109:                     bArr3 = new byte[mac.getMacLength()];
110:                     Arrays.fill(bArr3, (byte) 0);
111:                 }
112:                 mac.init(new SecretKeySpec(bArr3, this.a));      // salt = 第 2 参
113:                 bArrDoFinal = mac.doFinal(bArr);                // ikm  = 第 1 参
```

`defpackage/sid.java:55-89`（Expand，T(1..n) 拼接）

```java
 67:         byte[] bArrDoFinal = d;      // 空
 68:         byte b2 = 1;
 69:         int i3 = 0;
 70:         while (i3 < i) {
 71:             try {
 72:                 macB.update(bArrDoFinal);   // T(n-1)
 73:                 macB.update(bArr);          // info
 74:                 macB.update(b2);            // 计数器
 75:                 bArrDoFinal = macB.doFinal();
```

标准 RFC 5869，与 `miwear/crypto.py` 的 `hkdf_sha256()` 一致。**唯一差异：salt 为空时 App 补 32 字节零**（`sid.java:109-110`，`mac.getMacLength()` 对 HmacSHA256 = 32），`crypto.py` 也是 `b"\x00" * 32`，一致。

---

## 附录 A：本次新增/订正的文件与类索引

| 主题 | 类 / 文件 | dex | 本次新发现 |
|---|---|---|---|
| V2 加密调用 | `com/xiaomi/wearable/wear/api/CipherApiCall.java:78,117` | classes3 | IV==key 双实参 |
| V2 CTR 原语 | `defpackage/r1.java:11-25` | classes9 | 无补零 |
| V2 密钥派生 | `com/xiaomi/wearable/wear/api/WearAuthV2.java:157-228` | classes3 | **三种 message 顺序** |
| HKDF 包装 | `defpackage/itn.java:87-96` | classes2 | 输出 **64B** |
| HKDF 实现 | `defpackage/sid.java:55-125` | classes2 | Extract/Expand 参数序确认 |
| HMAC | `defpackage/ffc.java:8-12` | classes9 | 无 |
| V1 计数器 | `defpackage/tp5.java` (c/d) | classes2 | **小端** |
| 认证信封 | `defpackage/pyt.java:92-96,195-222` | classes3 | cmd 白名单 {5,26,27} |
| 认证载荷 | `defpackage/va0.java:254-472` | classes3 | 补 29/34–37 |
| 子消息 | `bb0/hb0/ya0/eb0/jd0` | classes3 | 全部字段号确认 |
| **业务信封** | **`defpackage/oyt.java`** | classes3 | **初稿完全未提** |
| 业务类型 | `com/xiaomi/wearable/ChannelType.java:17-34` | classes3 | 权威表 |
| 类型映射 | `com/xiaomi/wearable/transport/queue/TaskQueueV2.java:112-141` | classes3 | 100/101 随握手切换 |
| L2 帧 | `com/xiaomi/wearable/transport/layerl2/L2Packet.java:33-37,39` | classes3 | 无二次封装 |
| Mass 接收 | `com/xiaomi/wearable/mass/receiver/MassDataComposer.java` | classes3 | 30/26/4/8 前缀 |
| Mass 头 | `com/xiaomi/wearable/mass/receiver/Header.java:35-42` | classes3 | **22B 不是 26B** |
| Mass 发送 | `com/xiaomi/wearable/mass/sender/MassDataDispatcher.java:164-179,271-273` | classes3 | **dataType 合成字节** |
| Mass 分片 | `com/xiaomi/wearable/mass/sender/a.java:31-48` | classes3 | 4B 分片头 |
| MD5 | `com/xiaomi/wearable/mass/utils/MD5Util.java:78-98` | classes3 | 16B 原始摘要 |
| BER tag | `.../sport800/ber/BerTag.java:26-53` | classes2 | 1 或 2 字节 |
| BER len | `.../sport800/ber/BerLength.java:36-62` | classes2 | 最长 3 字节 |
| BER 表 | `.../sport800/SportUtilsKt.java:79` | classes2 | **tag 1–19 全表** |
| BER 遍历 | `.../sport800/SportDetail800DataParser.java:149-166` | classes2 | 可跨分片 |
| BER node | `.../sport800/model/*.java` | classes2 | 每 tag 位宽 |
| OTA 分块 | `com/mi/fitness/checkupdate/ota/GeneralOtaExecutor.java:38-48,94` | classes7 | **走 Mass 不是 ch6** |
| OTA 控制 | `com/mi/fitness/checkupdate/util/DeviceSender.java:353-427` | classes7 | `oyt{2,5/90/4/14/15}` |
| 小端读取 | `defpackage/anw.java:270-276`, `defpackage/d3.java:38-122` | classes2/13 | 全部小端 |
| nano 编码 | `com/google/protobuf/nano/CodedOutputByteBufferNano.java:354-545` | — | wire type 判别法 |

---

## 附录 B：待真机验证清单（按优先级）

| # | 待验证项 | 验证方法 | 影响 |
|---|---|---|---|
| 1 | Tag 1（时间戳）的 BER length 到底是 8 还是 12 | 抓 detail 流，找 `0x01 <len>`，看 len 与后续节点是否对齐 | BER 解析器能否跑通第一条 |
| 2 | `oyt.field1` 业务域枚举的完整语义 | 抓 channel 1 全量包，按 (field1,field2) 聚类对照时间轴 | 消息识别表 |
| 3 | **deviceSign 校验用的 message 顺序** | 用已知 token 跑一遍，比对 `randomDevice‖randomApp`（源码）与 `randomApp‖randomDevice`（文档）哪个能验过 | **认证能否成功的决定性项**，优先级最高 |
| 4 | Mass `encrypt` 字节是否恒为 0 | 抓一次真实文件传输看 Header[0] | 是否需要二次解密 |
| 5 | channel 6 是否在任何机型/场景被使用 | 全量抓包看有无 channel==6 的 L2 包 | 是否要写 ch6 解析器 |

---

*本文所有代码引用均来自 `mihealth/src/sources/`（jadx 1.5.6 反编译产物），行号与该目录下文件一一对应，可直接回查。*

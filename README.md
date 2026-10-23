# robot-ota-server

机器侧离线 OTA HTTP 服务端。实现 `离线OTA 评审.md` 中机器人侧的接收、验签、持久化与校验流程；
安装执行在本次版本中**明确不实现**（`POST /install` 返回 `501 INSTALL_NOT_SUPPORTED`）。

- HTTP/1.1：Boost.Beast / Boost.Asio
- 密码学：OpenSSL（RSA、AES-256-GCM、SHA-256）
- JSON：jsoncpp
- 设备私钥：软件 PEM（开发/测试）或平台安全芯片（生产）

## 1. 依赖

### 构建期（在开发机或 CI 上）

| 组件 | 版本要求 | Ubuntu 20.04 包 |
| --- | --- | --- |
| g++ | 支持 C++17（≥ 9） | `g++` |
| CMake | ≥ 3.13 | `cmake` |
| OpenSSL | 1.1.1+ | `libssl-dev` |
| jsoncpp | 1.7.4+ | `libjsoncpp-dev` |
| Boost（Beast/Asio） | ≥ 1.71 | `libboost-dev libboost-system-dev` |

```bash
sudo apt install g++ cmake libssl-dev libjsoncpp-dev libboost-dev libboost-system-dev
```

在 Ubuntu 20.04 上，`libboost-dev` / `libboost-system-dev` 会解析到 1.71 版本。

### 运行期（机器人镜像）

```bash
sudo apt install libssl1.1 libjsoncpp1
```

`ldd build/robot-ota-server` 的实际运行期依赖为：`libcrypto.so.1.1`、`libjsoncpp.so.1`、
`libstdc++.so.6`、`libgcc_s.so.1`、`libpthread`、`libdl`、`libc`、`libm`。Boost 只用于编译期头文件
（当前链接方式下不产生 `libboost_system` 运行期依赖），因此机器人上**不需要**安装 Boost 开发包。

> 如果目标镜像无法安装任何开发包：构建可以在别的机器上完成，只把二进制和配置拷到机器人。
> 只有需要“在机器人上从源码构建”时才需要上述 `-dev` 包。

## 2. 构建与测试

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(nproc)"
cd build && ctest --output-on-failure                # 单元测试 + 集成测试
python3 tests/integration_test.py --server build/robot-ota-server   # 集成测试（会生成临时 PKI）
```

集成测试覆盖：完整上传与验签、错误签名/错误设备/错误 CA、断点续传、并发冲突、回滚保护、
崩溃恢复（SIGKILL 后 Offset 不回退）、chunked 上传、`100-continue`、安装未实现语义。

## 3. 配置

`--config PATH` 指定 JSON 配置，`--check-config` 只校验并打印解析结果。

- 相对路径（`data_dir`、密钥、CA）相对于**配置文件所在目录**解析。
- 配置是严格模式：未知字段、重复键、注释都会导致启动失败。

示例：

- `config/server.example.jsonc`：生产模板（`key_provider=se`，绝对路径）。
- `config/server.dev.example.jsonc`：开发模板（`key_provider=software`，`data_dir=../data`）。

字段说明：

| 字段 | 说明 |
| --- | --- |
| `data_dir` | 会话、锁文件、最小安全版本的持久化目录 |
| `device.robot_sn` | 设备序列号，必须与 Manifest 一致 |
| `device.product_id` / `hw_revision` | 必须与 Manifest 一致 |
| `device.firmware_version` | 当前固件版本，仅用于上报 |
| `device.security_version` | 初始最小安全版本（首次启动写入 `state/min_security_version`） |
| `device.max_plaintext_bytes` | 明文固件上限 |
| `device.max_chunk_bytes` | 单次 PATCH 请求体的上限，也是 `device-info` 上报值 |
| `crypto.key_provider` | `software` 或 `se` |
| `crypto.device_private_key_file` | `software` 模式必填，PEM 私钥 |
| `crypto.plat_ca_file` | 平台 CA（PEM），用于验证 Manifest 签名证书链 |
| `crypto.signature_scheme` | `RSA_PKCS1_SHA256`（默认）或 `RSA_PSS_SHA256`，必须与云端 KMS 一致 |
| `crypto.sign_domain_prefix` | 签名域分隔前缀，必须与云端逐字节一致 |
| `crypto.check_cert_validity` | 是否校验签名证书有效期 |
| `se.lib_path` | 安全芯片 SDK 路径，出厂镜像默认 `/unitree/lib/libsesdk.so` |
| `se.key_index` | 设备 RSA 私钥索引 |
| `se.export_platform_ca` | 从 SE 导出平台 CA（导出失败时回退到 `plat_ca_file`） |
| `http.bind` / `port` | 监听地址与端口 |
| `http.threads` | 工作线程数 |
| `http.max_body_bytes` | 非上传接口的请求体上限；必须 ≥ `max_chunk_bytes + 65536` |
| `http.idle_timeout_seconds` | 连接空闲/读写超时 |
| `http.max_queued_connections` | 等待工作线程的连接上限，超出返回 `503 SERVER_BUSY` |
| `http.max_header_bytes` | 请求头上限 |
| `session.receiving_ttl_hours` | `RECEIVING` 会话过期时间，0 表示不过期 |
| `install.engine` | 当前只支持 `disabled` |

## 4. HTTP API

所有接口均为明文 HTTP（协议本身不依赖 TLS，见第 9 节安全边界）。
错误统一为：

```json
{"error": {"code": "OFFSET_MISMATCH", "message": "Upload-Offset does not match"}}
```

### `GET /ota/v1/device-info`

```json
{
  "robot_sn": "AS2_000001",
  "product_id": "AS2",
  "hw_revision": "REV_A",
  "firmware_version": "2.4.0",
  "ota_api_version": 1,
  "manifest_versions": [1],
  "max_chunk_bytes": 4194304
}
```

### `POST /ota/v1/sessions`

请求体为 `SignedManifestBundle`（`manifest` + `signature_b64` + `signer_cert_b64`）。

- 新任务：`201 Created`
- 相同 `package_id`、相同 Manifest：`200 OK`，返回原 Session（包括终态）
- 相同 `package_id`、不同 Manifest：`409 PACKAGE_ID_CONFLICT`
- 已有其它活动任务：`409 OTA_BUSY`
- 验签失败：`400 SIGNATURE_INVALID` / `400 CERT_INVALID`
- 设备或固件不匹配：`400 DEVICE_MISMATCH` / `400 SPKI_MISMATCH` / `400 FIRMWARE_MISMATCH`
- 安全版本回滚：`400 VERSION_ROLLBACK`

响应：

```json
{"session_id": "ota_...", "state": "RECEIVING", "offset": 0, "total": 300000, "result": null}
```

### `GET /ota/v1/sessions/{id}`

返回 `session_id`、`state`、`offset`、`total`、`result`。状态枚举：
`RECEIVING`、`VERIFYING`、`READY`、`INSTALLING`、`SUCCESS`、`FAILED`、`EXPIRED`、`RECOVERY_REQUIRED`。

### `PATCH /ota/v1/sessions/{id}/payload`

```http
PATCH /ota/v1/sessions/ota_.../payload
Content-Type: application/octet-stream
Upload-Offset: 8388608

<binary ciphertext>
```

- 请求体可以是 `Content-Length` 或 `Transfer-Encoding: chunked`；支持 `Expect: 100-continue`。
- 单个请求体不得超过 `device.max_chunk_bytes`（`413 CHUNK_TOO_LARGE`）。
- `Upload-Offset` 必须等于机器人持久化的 Offset（`409 OFFSET_MISMATCH`）。
- 只允许 `RECEIVING` 状态（`409 INVALID_STATE`）。
- 成功：`204 No Content` + `Upload-Offset: <新偏移>`。
- 最后一块收齐后自动进入 `VERIFYING`，不需要单独的 verify 接口。

`HEAD /ota/v1/sessions/{id}/payload` 返回 `204`，带 `Upload-Offset` 与 `Session-State`，用于续传前查询。

### `POST /ota/v1/sessions/{id}/install`

再次提交完整 `SignedManifestBundle`。机器人重新验签并核对 Manifest 与当前 Session 一致。

- 当前版本 `install.engine=disabled`：返回 `501 INSTALL_NOT_SUPPORTED`，Session **保持 `READY`**，不会伪造成功。
- 非 `READY` 状态：`409 INVALID_STATE`；Manifest 不一致：`409 MANIFEST_MISMATCH`。
- `INSTALLING` / `SUCCESS` / `FAILED` / `RECOVERY_REQUIRED` 的重复请求返回当前状态，不会触发第二次安装。

`include/robot_ota/ota_engine.h` 是后续接入真实安装引擎的接口点。

## 5. 状态机与持久化

```text
RECEIVING --(收齐)--> VERIFYING --(校验通过)--> READY --(install)--> INSTALLING --> SUCCESS
     |                    |                        |                       |
     +--(超时)--> EXPIRED  +--(失败)--> FAILED     +--(安装不确定)--> RECOVERY_REQUIRED
```

- 每个 PATCH 先 `pwrite` + `fsync` 数据，再原子写 `meta.json`（临时文件 + `fsync` + `rename` + 目录 `fsync`），最后才返回 204。
- 崩溃恢复：
  - `RECEIVING`：把未确认的尾部截断，`offset` 保持为最后持久化的值。
  - `VERIFYING`：请求体完整则重新排队校验。
  - `READY` 但固件文件缺失：重新校验；数据不完整则置 `FAILED`。
  - `INSTALLING`：置 `RECOVERY_REQUIRED`，禁止自动重试。
  - `SUCCESS`：提升并持久化最小安全版本。
- 数据目录：

```text
data/
  lock
  state/min_security_version
  sessions/ota_<32 hex>/meta.json
  sessions/ota_<32 hex>/payload.enc
  sessions/ota_<32 hex>/firmware.bin
  quarantine/            # 损坏或不完整的会话目录
```

- `data_dir/lock` 防止同一目录启动多个实例。

## 6. 签名与设备绑定

云端签名输入：

```text
sign_domain_prefix (UTF-8 bytes) || 0x00 || JCS(manifest)
```

- JCS 按 RFC 8785：对象键按 UTF-16 code unit 排序、最小转义、只允许整数数字。
- `sign_domain_prefix` 由配置提供，必须与云端 KMS 完全一致；它不是额外的哈希算法，
  而是防止签名被跨协议复用的域分隔标记。
- 默认 `RSA_PKCS1_SHA256`（PKCS#1 v1.5），可选 `RSA_PSS_SHA256`。
- 签名证书必须能通过 `plat_ca_file` 链式验证（`check_cert_validity` 控制有效期检查）。
  - `plat_ca_file` 是**信任锚**：链路可以终止在这张证书上，不要求它是自签名根。
    这对应 `X509_V_FLAG_PARTIAL_CHAIN`，也是只带 `signer_cert` 的 Bundle 能工作的前提
    （生产链通常是 `signer ← PLAT_CA ← ROOT_CA`，Bundle 里没有中间证书）。
  - 如果配置文件里放的是多证书 PEM，`X509_STORE_load_locations` 会把它们都作为信任材料加载。
- 设备绑定：
  - Manifest 的 `robot_sn` == `device.robot_sn`
  - `recipient_spki_sha256` == 设备公钥 SPKI 的 SHA-256
  - `product_id` / `hw_revision` 匹配
  - `security_version` ≥ 已持久化的最小安全版本
  - `wrapped_dek` 长度 == RSA 模长
- 校验顺序：密文 SHA-256 → RSA 私钥运算 + 软件 OAEP-SHA256 解包 → AES-256-GCM 解密并验 tag → 明文大小/SHA-256。

## 7. 安全芯片（SE）接入

生产环境 `crypto.key_provider=se`：

1. 启动时检查标记文件 `/unitree/robot/basic/sec_chip_status`；不存在则报“非安全芯片产品，不可用”，拒绝启动。
2. `dlopen("/unitree/lib/libsesdk.so", RTLD_LAZY)`，先按平台统一的可用性判定解析四个符号：
   `SE_OpenDevice`、`SE_OpenSession`、`SE_BLE_GenKeyCipher`、`SE_BLE_GetKey`。
   - 四个符号齐全：打印 `成功加载 libsesdk.so,将使用安全芯片功能`。
   - 缺任一符号：`dlclose` 并输出缺少的符号名（回退，不可用）。
3. 可用性判定通过后，再解析 OTA 实际使用的符号：
   `SE_CloseSession`、`SE_CloseDevice`、`SE_ExportSignPublicKey_RSA`、
   `SE_InternalPrivateKeyOperation_RSA`，以及可选的 `SE_ExportCertificate`
   （`se.export_platform_ca=true` 时使用）。
4. `key_provider=se` 时**不会**静默回退到软件私钥——云端是把 DEK 包到 SE 公钥上的，
   软件回退只会导致解密失败，而且会掩盖部署问题。

`SE_BLE_GenKeyCipher` / `SE_BLE_GetKey` 是平台可用性判定的一部分，OTA 服务只解析、不调用。

SE 只执行原始 RSA 私钥运算（`SE_InternalPrivateKeyOperation_RSA`），
OAEP-SHA256 解码由软件完成（`oaep_sha256_decode`），与协议要求一致。

### 导出设备公钥（云端封装 DEK 用）

```bash
./robot-ota-server --config /etc/robot-ota/server.json --export-device-pubkey /tmp/robot_pub.pem
```

- `software` 与 `se` 两种模式都支持；SE 模式走 `SE_ExportSignPublicKey_RSA`（`se.key_index`）。
- 输出 SubjectPublicKeyInfo PEM 和 `recipient_spki_sha256`，然后退出，不启动 HTTP 服务。
- 云端必须把 32 字节 DEK 封装到**这把公钥**上；只拿到 SPKI 哈希无法生成设备包。

SDK 参考：`/home/unitree/工作中转文件夹/安全芯片SDK`（`se_sdk.h`、`sesdk_test.c`、手册）。

## 8. 日志

- `--verbose` 打开 DEBUG 级别。
- 启动时记录 `recipient_spki_sha256`，可用于与云端 Manifest 交叉核对。
- 每个请求在 DEBUG 下记录方法、路径和结果；错误响应同时记录错误码。

## 9. 安全边界

- 服务端**不认** USER/EMPLOYEE 令牌，也不做本地客户端认证；安全性来自 Manifest 签名、设备绑定和
  逐块密文传输。
- 明文 HTTP 只应部署在受限的机器人内网/局域网；不要暴露到公网。
- 私钥文件（`software` 模式）应为 `0600`；生产使用 SE。
- 所有长度、偏移和状态转换都做了上限与一致性检查；请求头/请求体/队列长度均有上限。

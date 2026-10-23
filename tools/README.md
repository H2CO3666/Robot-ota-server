# 真实 KMS 离线 OTA 测试包

用真实 KMS（`purpose=UNITREE_OTA_TEST`）签发 Manifest，并生成一份能被机器人端
`robot-ota-server` 完整验签、解密的测试包。

## 前置：KMS 网络

KMS 只能从白名单跳板机访问，先建隧道（实际地址向平台组索取，不写入仓库）：

```bash
ssh -N -L 127.0.0.1:13165:<KMS_HOST>:<KMS_PORT> root@<JUMP_HOST>
```

## 生成包

```bash
python3 tools/real_kms_bundle.py --out out/real-kms-bundle
```

首次运行会生成 `device_key.pem`（仅测试用，`0600`）；之后复用。工具会：

1. 生成 32B DEK、12B Nonce，AES-256-GCM 加密明文；
2. 用设备 RSA 公钥以 RSA-OAEP-SHA256 封装 DEK；
3. 构造 Manifest 并做 JCS 规范化；
4. 以 `ROBOT_OFFLINE_OTA_MANIFEST_V1 || 0x00 || JCS(Manifest)` 调用
   `/kms/v4/authkey/cloud/sign`；
5. 调用 `/kms/v4/authkey/cloud/cert` 取签名证书，校验
   `keyId`、`signerCertHash`、证书链、有效期，并在本地用证书公钥验签。

输出：

| 文件 | 说明 |
| --- | --- |
| `manifest.json` | 规范化 Manifest（无尾随换行，可直接用于签名复核） |
| `manifest.sig` | Detached 签名，原始 256 字节 |
| `signer_cert.der` / `.pem` | KMS 本次签名证书 |
| `firmware.enc` | 共享密文 |
| `firmware.plain` | 测试明文，用于比对 |
| `bundle.json` | `POST /ota/v1/sessions` 的请求体 |
| `plat_ca.pem` | 从 `fanxin.pem` 提取的测试平台 CA |
| `server.json` | 可直接启动的机器人端配置 |
| `package-info.json` | 包 ID、SPKI、各摘要、KMS keyId/证书信息 |

## 启动机器人端并验证解密

```bash
./build/robot-ota-server --config out/real-kms-bundle/server.json --verbose
python3 tools/real_kms_bundle.py --out out/real-kms-bundle --upload-only
```

成功时输出：

```text
session state: READY result=None
decrypted    : 1048576 bytes sha256=...
decrypt      : OK (plaintext SHA-256 matches the manifest)
```

`READY` 表示机器人端已完成密文摘要、SE/软件 Raw RSA、OAEP 解码、AES-GCM 认证和
明文摘要；工具还会把 `data/sessions/<id>/firmware.bin` 的 SHA-256 与 Manifest 比对。

## 独立复核

```bash
openssl verify -partial_chain -CAfile out/real-kms-bundle/plat_ca.pem \
  out/real-kms-bundle/signer_cert.pem

printf 'ROBOT_OFFLINE_OTA_MANIFEST_V1\0' > /tmp/sign_input.bin
cat out/real-kms-bundle/manifest.json >> /tmp/sign_input.bin
openssl x509 -in out/real-kms-bundle/signer_cert.pem -pubkey -noout > /tmp/pub.pem
openssl dgst -sha256 -verify /tmp/pub.pem \
  -signature out/real-kms-bundle/manifest.sig /tmp/sign_input.bin
```

## 真机使用

真机的设备私钥在 SE 里，不能复用本机的 `device_key.pem`。步骤：

1. 从真机导出 RSA 公钥（`SE_ExportSignPublicKey_RSA`），保存为 PEM：

   ```bash
   ./robot-ota-server --config /etc/robot-ota/server.json \
     --export-device-pubkey /tmp/robot_pub.pem
   ```

   会同时打印 `recipient_spki_sha256`，可与 `server.log` 启动行交叉核对；
2. 用真机公钥重新组包：

   ```bash
   python3 tools/real_kms_bundle.py \
     --out out/real-robot \
     --device-pubkey /path/to/robot_pub.pem \
     --robot-sn <SN> --product-id <型号> --hw-revision <硬件版本> \
     --security-version <非负整数>
   ```

3. 真机 `crypto.plat_ca_file` 指向生成的 `plat_ca.pem`；
4. 真机 `crypto.sign_domain_prefix` 必须等于 `--domain-prefix`（默认
   `ROBOT_OFFLINE_OTA_MANIFEST_V1`）；
5. 真机 `data_dir`、`max_plaintext_bytes`、`max_chunk_bytes` 按实际情况调整；
6. 机器人端需要包含 `X509_V_FLAG_PARTIAL_CHAIN`（见主 README 第 6 节），
   否则测试 `plat_ca` 不是自签根时会报 `unable to get issuer certificate`。

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--kms-url` | `http://127.0.0.1:13165` | KMS 地址（SSH 隧道） |
| `--purpose` | `UNITREE_OTA_TEST` | KMS 用途 |
| `--out` | `out/real-kms-bundle` | 输出目录 |
| `--robot-sn` | `AS2_000001` | 必须与真机一致 |
| `--product-id` / `--hw-revision` | `AS2` / `REV_A` | 必须与真机一致 |
| `--version` | `2.5.0` | 固件版本，仅展示 |
| `--security-version` | `5` | 防回滚比较值 |
| `--artifact-id` | `AS2_FW_2.5.0_REAL_KMS` | 发布物标识 |
| `--plaintext-bytes` | `1048576` | 合成明文大小 |
| `--plaintext-file` | — | 用真实固件替代合成明文 |
| `--device-key` | `device_key.pem` | 相对 `--out` 的私钥路径 |
| `--device-pubkey` | — | 只给定公钥（真机 SE 场景） |
| `--domain-prefix` | `ROBOT_OFFLINE_OTA_MANIFEST_V1` | 签名域前缀 |
| `--server-port` | `18080` | 写入 `server.json` / 上传端口 |
| `--chunk-bytes` | `100000` | 上传分块大小 |
| `--upload-only` | — | 不上传新包，只把已有包上传到运行中的机器人服务 |

> `device_key.pem` 只是开发/测试密钥，不能用于生产；真机必须用 SE。

<div align="center">

<img src="Logo.png" alt="Nexus" width="120" />

# Nexus

**高性能 · S3 兼容 · 存算一体 · 智能对象存储**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8.svg)](https://go.dev/)

</div>

---

Nexus 是一款将存储、计算与搜索融合为统一平台的智能对象存储系统。传统对象存储只负责"存"和"取"，数据的价值需要额外的计算集群和搜索引擎来挖掘。Nexus 将管线处理、向量索引和零信任加密内置于存储层——**上传即处理、存储即索引、读取即解密**，无需编排外部服务。

## ✦ 核心特性

### 存算一体

上传对象时自动触发管线处理——图片压缩、缩略图生成、PII 脱敏、元数据提取——处理结果立即可用，无需额外调度。管线通过 `pipelines.yaml` 声明式配置，支持自定义插件扩展。

### 原生向量搜索

内置 HNSW 和 IVF-PQ 向量索引引擎，支持 ONNX / OpenAI / 自定义 API 等多种嵌入提供者。对象上传后自动生成向量并索引，毫秒级语义检索，无需独立向量数据库。

### 零信任加密

AES-256-GCM 信封加密体系，KMS/DEK/KEK 三层密钥管理：

- **Ed25519 非对称令牌签名** — 令牌签发与验证解耦，验证方只需公钥，无需访问签发状态
- **加解密路径分离** — 加密和解密使用独立 KEK 派生域，操作级隔离
- **Vault Transit 真集成** — 密钥材料由 HashiCorp Vault 管理，`generate-data-key` + `decrypt` 远程调用，密钥永不离开 Vault
- **全链路审计** — 所有密钥操作输出结构化审计日志

### 智能分层存储

根据访问模式自动在 Hot / Warm / Cold / Archive 四层之间迁移数据，可配置调度策略和存储介质，冷热分离，成本最优。

### 安全与合规

- AWS Signature V4 + JWT (HS256) 双认证
- TLS/mTLS 支持，自动证书生成与热重载
- 多级速率限制（IP / 用户 / 桶 / API 方法）
- CORS 基于 Bucket 配置验证
- SSRF 防护（复制目标禁止私有/回环地址，内网部署可配置放行）
- 安全头中间件（HSTS / CSP / X-Frame-Options）

### 轻量部署

- BoltDB 嵌入式存储，零外部数据库依赖
- 单二进制部署，支持小型 VPS 和内网环境
- `replication.allow_private_endpoint` 配置项支持内网复制目标

---

## 🚀 快速开始

### 前置条件

- Go 1.21+

### 构建

```bash
go build -o nexus ./cmd/nexus
go build -o nexusctl ./cmd/nexusctl
```

### 启动

```bash
./nexus
```

服务默认监听 `:8080`，配置从 `config.yaml` 加载。

### 配置

```bash
cp config.yaml config.local.yaml
```

| 配置段 | 说明 |
|--------|------|
| `auth` | JWT 密钥、令牌有效期、匿名访问 |
| `encryption` | KMS 类型（local/vault）、主密钥路径、Vault Transit 密钥名 |
| `vector` | 嵌入提供者、维度、索引类型 |
| `pipelines` | 处理管线配置文件、并发数 |
| `tiering` | 热/温/冷存储层、调度策略 |
| `tls` | 证书路径、自动证书、最低版本 |
| `ratelimit` | IP/用户/桶/API 速率限制 |
| `replication` | 允许私有地址端点（内网部署） |

### 环境变量

| 变量 | 说明 |
|------|------|
| `NEXUS_ADMIN_USER` | CLI 管理员用户名 |
| `NEXUS_ADMIN_PASSWORD` | CLI 管理员密码 |
| `NEXUS_ACCESS_KEY` | CLI S3 访问密钥 |
| `NEXUS_SECRET_KEY` | CLI S3 密钥 |
| `NEXUS_REPLICATION_ALLOW_PRIVATE_ENDPOINT` | 允许内网复制目标 |

---

## 🔍 AI / 向量搜索

Nexus 支持可插拔嵌入提供者：

| 提供者 | 配置值 | 说明 |
|--------|--------|------|
| Mock | `mock` | 确定性哈希嵌入（测试用） |
| ONNX | `onnx` | 本地 ONNX 模型推理 |
| OpenAI | `openai` | OpenAI 嵌入 API |
| 自定义 API | `api` | 任意 OpenAI 兼容端点 |

### 下载嵌入模型

使用 Modelscope SDK 下载多语言句嵌入模型：

```python
from modelscope import snapshot_download

model_dir = snapshot_download(
    'iic/gte_sentence-embedding_multilingual-base',
    cache_dir='/models'
)
```

配置 `config.yaml`：

```yaml
vector:
  enabled: true
  embedding_provider: "onnx"
  embedding_model_path: "/models/iic/gte_sentence-embedding_multilingual-base"
  dim: 768
```

详见 [Modelscope 下载文档](https://www.modelscope.cn/docs/models/download)。

---

## ⚡ 存储管线

管线通过 `pipelines.yaml` 声明式配置，定义触发器、过滤器和处理步骤：

```yaml
pipelines:
  - name: "image-processing"
    trigger: "on_upload"
    filter: "content-type matches 'image/*' and size < 10MB"
    steps:
      - name: "compress"
        plugin: "image_compress"
        params:
          format: "webp"
          quality: "80"
        output: "{key}_compressed.webp"
      - name: "thumbnail"
        plugin: "thumbnail_generator"
        params:
          sizes: "128,256,512"
    priority: 10
    enabled: true
```

可用插件：`image_compress` · `image_resize` · `thumbnail_generator` · `image_metadata_extract` · `metadata_extract` · `encrypt_pii` · `video_thumbnail` · `pdf_to_text`

---

## 🛠 CLI 使用

```bash
# 服务状态
./nexusctl status

# 用户管理
./nexusctl user create --name myuser --role user
./nexusctl user list
./nexusctl user get --id <user-id>

# 存储桶管理
./nexusctl bucket create --name mybucket
./nexusctl bucket list
./nexusctl bucket put-object --bucket mybucket --key hello.txt --file ./hello.txt

# 管理操作
./nexusctl tiering run --bucket mybucket
./nexusctl vector rebuild --bucket mybucket
./nexusctl crypto rotate --bucket mybucket
```

---

## 🏗 架构

```
┌─────────────────────────────────────────────┐
│                  Gateway                     │
│  S3 API │ Admin API │ Auth │ CORS │ RateLimit│
├─────────────────────────────────────────────┤
│            Storage Engine                    │
│  Hot Tier │ Warm Tier │ Cold Tier │ Archive  │
├─────────────────────────────────────────────┤
│          Compute Pipelines                   │
│  Compress │ Resize │ Thumbnail │ PII │ Vector│
├─────────────────────────────────────────────┤
│           Core Services                     │
│  Encryption │ Metadata │ Cache │ Replication │
└─────────────────────────────────────────────┘
```

---

## 🧪 测试

```bash
go test ./... -count=1
```

---

## 📄 许可证

[MIT](LICENSE)

## S3/MinIO 异步归档

归档只在提供 `--archive-s3-bucket` 时启用。轮转完成后，agtap 将关闭的 JSONL 固定为唯一快照，在本地持久队列中记录作业，并由后台 worker 上传。归档对象为可查询的 JSONL 表，而不是数组包装的单个 package。

### 配置

```bash
agtap \
  --comm sub2api \
  --archive-s3-endpoint http://minio:9000 \
  --archive-s3-bucket agtap \
  --archive-s3-prefix sub2api \
  --archive-compression zstd \
  --body-store-high-water-percent 90 \
  --body-store-hard-water-percent 100 \
  --max-body-retain-kb 1024
```

`--archive-compression` 只接受 `zstd` 或 `lz4`；默认 `zstd`。DuckDB 1.5.5 已在隔离 MinIO 经 `httpfs` 验证可直接读取 `.jsonl.zst`。`lz4` 保留为显式 **LZ4 frame**（不是 raw LZ4 block）选项，但当前 DuckDB JSON S3 reader 无法解 frame，**不承诺 `.jsonl.lz4` 可直接读取**。未知值由 CLI 拒绝。AWS 凭据仍仅由 SDK 环境/实例角色/secret 注入；不得写入仓库、Issue、参数日志或对象内容。

### 对象布局与提交顺序

每个 rotation 有稳定、不可变的 ID，并在入队时固定 UTC 分区：仅 `m=YYYYMM/d=DD` 两层。

```text
<prefix>/agtap_bodies/m=YYYYMM/d=DD/part-<rotation-id>.jsonl.zst
<prefix>/agtap_events/m=YYYYMM/d=DD/part-<rotation-id>.jsonl.zst
<prefix>/agtap_manifests/m=YYYYMM/d=DD/commit-<rotation-id>.json
```

显式选择 `lz4` 时 part 后缀为 `.jsonl.lz4`。每一行都是独立 JSON：

- `agtap_events` 保留事件元数据，将本地 `body_path` 替换为 `body_id`；无正文时为 `null`。
- `agtap_bodies` 以同一个稳定 `body_id` 保存 `request` 和 `response`。`body_id` 是正文文件字节的 SHA-256，因此可以跨事件 join。
- manifest 列出两个 part 的 key、压缩后 size 和 SHA-256；它是唯一提交标记。

worker 按 **bodies → events → manifest** 上传。每一个对象 Put 后都执行 HeadObject，核对 size 和 `sha256` 元数据。仅 manifest 校验成功后才删除 pending job、轮转快照、缓存 payload 与关联正文。上传/HeadObject 任一失败会保留这些文件和持久 job，按退避重试；重启会继续同一 rotation 的同一 key，不创建新 part。

### 活动日志正文与水位

容量或时限清理命中仍在 `events.jsonl` 的正文时，agtap 先写入并回读校验一个原子 checkpoint：其中有事件 ID、事件—正文关联、正文副本及 SHA-256。只有 checkpoint job 落盘校验成功后才会回收原正文；后台 worker 继续按上述同一 manifest 契约上传，采集、转发和轮转均不等待网络。checkpoint 已提交的事件会在后续普通轮转中去重。没有活动日志引用且不在 queue/rotation intent 保护集内的孤儿正文按原保留期/水位回收；日志读取、JSON 解析或 checkpoint 校验失败时保留正文以便重试。

`--body-store-high-water-percent`（默认 90）和 `--body-store-hard-water-percent`（默认 100）必须满足 `0 < high <= hard <= 100`。高水位时日志会输出仅含计数的归档积压状态；S3 持续失败导致硬水位后，agtap 只跳过**新**正文文件，仍输出事件并保持旁路业务转发。未提交的旧正文和 checkpoint payload 不会为了腾空间被删除。

### DuckDB 查询

DuckDB 可通过 `httpfs` 读取 codec 对应的 JSONL。具体 S3 endpoint、凭据和版本取决于部署环境；以下只展示布局和 join，需先按环境配置 `httpfs`：

```sql
-- 默认 Zstd part（DuckDB 1.5.5 + httpfs + 隔离 MinIO 已验证）
SELECT *
FROM read_json_auto('s3://agtap/sub2api/agtap_events/m=202611/d=21/*.jsonl.zst');

SELECT e.*, b.request, b.response
FROM read_json_auto('s3://agtap/sub2api/agtap_events/m=202611/d=21/*.jsonl.zst') e
LEFT JOIN read_json_auto('s3://agtap/sub2api/agtap_bodies/m=202611/d=21/*.jsonl.zst') b
  USING (body_id);
```

显式 LZ4 仅供具备相应 reader 的消费者使用；当前 DuckDB JSON S3 直接读取 `.jsonl.lz4` 已知失败，故不承诺该路径。Trino 连接当前不可达（ENV-FAULT），本文不将其写成 PASS。

### Trino 查询

Trino 的对象存储 catalog 与 JSONL/Zstd reader 配置由部署侧管理。注册外部表时，events 和 bodies 的 location 分别指向 `agtap_events/`、`agtap_bodies/` 根目录，并以 `m`、`d` 为分区列；按 `body_id` join。先读取 manifest 的 checksum/size 后再发布分区，避免读取尚未提交的 part。当前没有可达 connector，属于 ENV-FAULT；connector 可用时按同一外表契约补验。

### 本地可靠性

- `archive/pending/*.json`：持久重试作业与固定对象 key/checksum。
- `archive/closed/*.jsonl`：轮转日志的唯一快照，避免 `.1`/`.2` 改名覆盖输入。
- `archive/payloads/`：两个压缩 part 和 manifest 的可恢复本地 payload。
- `archive/committed/`：已提交 checkpoint 的事件 ID 标记，供后续轮转去重。

正文清理读取 pending job 引用；活动日志正文在 checkpoint 校验前不会删除，checkpoint 和轮转都在 manifest 成功前保留可恢复内容。`scripts/verify_archive.sh` 只覆盖本地队列/快照行为；真实 S3/MinIO 与 DuckDB/Trino 读取必须在具备正常凭据和同候选版本的隔离环境验证。

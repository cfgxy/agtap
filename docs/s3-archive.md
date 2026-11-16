## S3/MinIO 异步归档

归档功能只在提供 `--archive-s3-bucket` 时启用。轮转完成后，agtap 将已关闭的 JSONL 文件固定为唯一快照，写入 `/tmp/agtap/archive/pending/` 的持久 job，并由后台 worker 上传。上传成功后使用 `HeadObject` 校验对象大小和 `sha256` 元数据，再删除快照、job 和关联正文；上传失败会保留本地数据并按退避策略重试。

### 配置

AWS S3 使用默认 SDK endpoint；MinIO 或其他 S3 兼容服务设置 `--archive-s3-endpoint`，worker 会自动使用 path-style bucket addressing。凭据由 AWS SDK 的环境变量或实例角色加载：

```bash
export AWS_ACCESS_KEY_ID='由部署系统注入'
export AWS_SECRET_ACCESS_KEY='由部署系统注入'
export AWS_REGION='us-east-1'

agtap \
  --comm sub2api \
  --archive-s3-endpoint http://minio:9000 \
  --archive-s3-bucket agtap \
  --archive-s3-prefix sub2api \
  --max-body-retain-kb 2048
```

不要把凭据写入启动脚本、仓库、Issue 或日志。生产部署应通过 systemd EnvironmentFile、容器 secret 或实例角色注入，并限制 bucket 写权限。

### 本地状态

- `archive/pending/*.json`：未完成或待重试的持久 job，重启后自动恢复。
- `archive/closed/*.jsonl`：轮转文件的唯一 hard-link 快照，避免 `.1`/`.2` 重命名覆盖队列输入。
- `archive/payloads/*.json`：已完成本地打包、但尚未完成对象上传或清理的 payload；用于上传后进程崩溃恢复。

正文清理会读取 pending job 的 `body_path` 引用。只要 job 尚未完成，引用正文不会因时间或容量清理被删除。

### 验证

```bash
scripts/verify_archive.sh
```

该脚本验证本地队列、轮转快照、正文保护和打包关联。真实 MinIO/S3 读回还需要在目标部署环境提供可写 bucket、正常凭据和与候选版本一致的运行实例；脚本不会打印或读取凭据值。

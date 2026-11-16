#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

echo "运行归档队列、轮转恢复、payload 校验、worker 上传重试和正文保护测试"
cargo test --manifest-path "$repo_root/Cargo.toml" --package agtap --lib archive::
cargo test --manifest-path "$repo_root/Cargo.toml" --package agtap --lib event_log::
cargo test --manifest-path "$repo_root/Cargo.toml" --package agtap --lib body_store::

echo "本地归档验证通过；真实 S3/MinIO 读回需在部署环境单独执行。"

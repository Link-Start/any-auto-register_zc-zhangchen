#!/bin/sh
set -eu

# 无头服务器入口：与 entrypoint.sh 的唯一区别是不套 xvfb-run。
# 这个镜像不装浏览器，没有需要虚拟显示的任务。

APP_DIR="/app"
RUNTIME_DIR="${APP_RUNTIME_DIR:-/runtime}"

mkdir -p "${RUNTIME_DIR}" "${RUNTIME_DIR}/logs"
touch "${RUNTIME_DIR}/account_manager.db"

# 凭据加密密钥必须和数据库一起留在挂载卷里。放在镜像内的默认位置（/app/.secrets）
# 会在每次重建容器时重新生成，导致库里已加密的 iCloud/ChatGPT 凭据全部解不开
# （decrypt 抛 InvalidTag），而且没有任何补救手段。
mkdir -p "$(dirname "${CREDENTIAL_ENCRYPTION_KEY_FILE:-${RUNTIME_DIR}/.secrets/credential_key}")"
chmod 700 "$(dirname "${CREDENTIAL_ENCRYPTION_KEY_FILE:-${RUNTIME_DIR}/.secrets/credential_key}")"

ln -sfn "${RUNTIME_DIR}/account_manager.db" "${APP_DIR}/account_manager.db"

if ! command -v node >/dev/null 2>&1; then
  echo "[entrypoint] 警告: 找不到 node，ChatGPT 的 Sentinel PoW 无法求解，注册会收不到验证码" >&2
fi

echo "[entrypoint] Starting backend (headless, solver disabled)"
exec python main.py

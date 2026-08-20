#!/bin/sh
set -eu

APP_DIR="/app"
RUNTIME_DIR="${APP_RUNTIME_DIR:-/runtime}"

mkdir -p "${RUNTIME_DIR}" "${RUNTIME_DIR}/logs"
touch \
  "${RUNTIME_DIR}/account_manager.db" \
  "${RUNTIME_DIR}/logs/solver.log"

ln -sfn "${RUNTIME_DIR}/account_manager.db" "${APP_DIR}/account_manager.db"
ln -sfn "${RUNTIME_DIR}/logs/solver.log" "${APP_DIR}/services/turnstile_solver/solver.log"

# 凭据加密密钥必须和数据库一起留在挂载卷里。放在镜像内的默认位置（/app/.secrets）
# 会在每次重建容器时重新生成，导致库里已加密的 iCloud/ChatGPT 凭据全部解不开
# （decrypt 抛 InvalidTag），而且没有任何补救手段。
mkdir -p "$(dirname "${CREDENTIAL_ENCRYPTION_KEY_FILE:-${RUNTIME_DIR}/.secrets/credential_key}")"
chmod 700 "$(dirname "${CREDENTIAL_ENCRYPTION_KEY_FILE:-${RUNTIME_DIR}/.secrets/credential_key}")"

echo "[entrypoint] Starting backend under Xvfb so Docker can handle both headed and headless browser tasks"
exec xvfb-run -a --server-args="-screen 0 1920x1080x24" python main.py

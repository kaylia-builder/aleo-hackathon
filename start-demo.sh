#!/usr/bin/env bash
# ==============================================================================
# LeoZap Demo — 启动方式（任选其一）
#
# 🌐 GitHub Pages (推荐，无需端口)：
#    推送代码到 main 分支，GitHub Actions 会自动部署到:
#    https://kaylia-builder.github.io/aleo-hackathon/
#
# 🧱 本地 WASM 模式：
#    ./start-demo.sh wasm       # 构建 WASM + 启动静态服务
#
# 🖥️  完整 Server 模式（含 ZK 验证）：
#    ./start-demo.sh server     # 启动后端 + bore 隧道
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

MODE="${1:-wasm}"

if [ "$MODE" = "wasm" ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       🧱  LeoZap WASM Demo (in-browser fuzzing)     ║"
    echo "╠══════════════════════════════════════════════════════╣"
    echo "║                                                      ║"
    echo "║  🌐  GitHub Pages:                                   ║"
    echo "║     https://kaylia-builder.github.io/aleo-hackathon/ ║"
    echo "║                                                      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""

    # ── Build WASM ─────────────────────────────────────
    echo "🔨 Building WASM module..."
    rustup target add wasm32-unknown-unknown 2>/dev/null || true
    cargo build --target wasm32-unknown-unknown -p leo-zap-wasm -q 2>&1 | tail -1 || true
    wasm-bindgen --target web --out-dir leo-zap-wasm/pkg target/wasm32-unknown-unknown/debug/leo_zap_wasm.wasm 2>/dev/null
    cp leo-zap-wasm/pkg/*.js leo-zap-wasm/pkg/*.wasm web/

    # ── Start static server ─────────────────────────────
    echo "🚀 Starting at http://localhost:8080"
    echo "   (static files only — fuzzing runs in-browser via WASM)"
    cd web && python3 -m http.server 8080
    exit 0
fi

# ── Server mode ────────────────────────────────────────
echo "🧹 Cleaning up old processes..."
pkill -f "leo-zap serve" 2>/dev/null || true
pkill -f "bore local"    2>/dev/null || true
sleep 1

echo "🔨 Building..."
cargo build --manifest-path leo-zap/Cargo.toml -q 2>&1 | tail -1 || true

# ── 3. 启动 Web Dashboard ───────────────────────────────
echo "🚀 Starting Web Dashboard..."
nohup ./leo-zap/target/debug/leo-zap serve --port 3000 > /tmp/leozap-server.log 2>&1 &
SERVER_PID=$!
sleep 2

# 检查服务器是否启动成功
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Server failed to start. Check /tmp/leozap-server.log"
    exit 1
fi
echo "   ✅ Server PID: $SERVER_PID"

# ── 4. 启动 Bore 隧道 ──────────────────────────────────
echo "🌐 Starting public tunnel..."
nohup bore local 3000 --to bore.pub > /tmp/leozap-tunnel.log 2>&1 &
TUNNEL_PID=$!
sleep 3

# ── 5. 提取公网 URL ────────────────────────────────────
PUBLIC_URL=$(grep -oP 'listening at \Kbore\.pub:\d+' /tmp/leozap-tunnel.log | tail -1)

if [ -z "$PUBLIC_URL" ]; then
    # 重试
    sleep 2
    PUBLIC_URL=$(grep -oP 'listening at \Kbore\.pub:\d+' /tmp/leozap-tunnel.log | tail -1)
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║       🧱  LeoZap Demo Ready                          ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
if [ -n "$PUBLIC_URL" ]; then
echo "║  🔗  http://$PUBLIC_URL                  ║"
else
echo "║  🔗  http://localhost:3000    (本地)                  ║"
fi
echo "║                                                      ║"
echo "║  📁  GitHub: github.com/kaylia-builder/aleo-hackathon║"
echo "║                                                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  按 Ctrl+C 停止所有服务                               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── 6. 持续监控，URL 变了自动提醒 ───────────────────────
trap "kill $SERVER_PID $TUNNEL_PID 2>/dev/null; echo '👋 Demo stopped.'; exit 0" INT TERM

LAST_URL="$PUBLIC_URL"
while true; do
    sleep 10
    # 检查进程是否存活
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "❌ Server crashed! Restarting..."
        nohup ./leo-zap/target/debug/leo-zap serve --port 3000 > /tmp/leozap-server.log 2>&1 &
        SERVER_PID=$!
    fi
    if ! kill -0 $TUNNEL_PID 2>/dev/null; then
        echo "❌ Tunnel died! Restarting..."
        nohup bore local 3000 --to bore.pub > /tmp/leozap-tunnel.log 2>&1 &
        TUNNEL_PID=$!
        sleep 3
        NEW_URL=$(grep -oP 'listening at \Kbore\.pub:\d+' /tmp/leozap-tunnel.log | tail -1)
        if [ -n "$NEW_URL" ] && [ "$NEW_URL" != "$LAST_URL" ]; then
            echo ""
            echo "🔄 URL updated: http://$NEW_URL"
            echo ""
            LAST_URL="$NEW_URL"
        fi
    fi
done

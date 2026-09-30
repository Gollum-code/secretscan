#!/usr/bin/env bash
# 生成演示夹具到 ./demo（该目录已被 .gitignore 排除，不会提交到仓库）
# 用法: bash scripts/make-demo.sh
# 注意：所有密钥值在运行时随机生成，纯演示用途，不是真实凭证。
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p demo/config demo/src demo/docs

ALNUM='A-Za-z0-9'; HEX='0-9a-f'; LOWER='a-z0-9'

# 从 /dev/urandom 生成指定长度的随机串（保证恰好 n 个字符）
rnd() {
    local n=$1 set=$2 out=''
    while [ "${#out}" -lt "$n" ]; do
        out+=$(LC_ALL=C tr -dc "$set" </dev/urandom | head -c $((n * 2)))
    done
    printf '%s' "${out:0:n}"
}

cat > demo/config/.env <<EOF
# ── 演示样例（全部为随机伪造值，非真实凭证）─────────────────────
AWS_ACCESS_KEY_ID=AKIA$(rnd 16 "$ALNUM")
aws_secret_access_key=$(rnd 40 "$ALNUM")

OPENAI_API_KEY=sk-proj-$(rnd 40 "$ALNUM")

SLACK_BOT_TOKEN=xoxb-$(rnd 32 "$ALNUM")

STRIPE_SECRET_KEY=sk_live_$(rnd 24 "$ALNUM")

GITHUB_TOKEN=ghp_$(rnd 36 "$ALNUM")

TELEGRAM_BOT_TOKEN=9876543210:$(rnd 35 "$ALNUM")

SENDGRID_API_KEY=SG.$(rnd 22 "$ALNUM").$(rnd 43 "$ALNUM")
EOF

cat > demo/src/app.py <<EOF
import os

# 演示：混合了后端服务的伪造凭证（非真实）
TWILIO_SID = "AC$(rnd 32 "$HEX")"
TWILIO_API_KEY = "SK$(rnd 32 "$HEX")"
DISCORD_TOKEN = "M$(rnd 24 "$ALNUM").$(rnd 6 "$ALNUM").$(rnd 38 "$ALNUM")"

# 泄漏到源码里的支付密钥（风险最高）
PAYPAL_TOKEN = 'access_token\$production\$$(rnd 16 "$LOWER")_$(rnd 32 "$LOWER")'

# 云厂商一串
DO_PAT = "dop_v1_$(rnd 64 "$HEX")"
GCP_KEY = "AIza$(rnd 35 "$ALNUM")"
ALIYUN = "LTAI$(rnd 20 "$ALNUM")"
EOF

cat > demo/docs/setup.example.md <<'EOF'
# 使用 OpenAI 密钥的示例（本文件仅为演示配置模板，密钥为占位）
OPENAI_API_KEY=sk-00000000000000000000000000000000
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
EOF

echo "已生成演示夹具到: demo"
echo "运行: ./target/release/secretscan --format all -o secretscan-report demo"

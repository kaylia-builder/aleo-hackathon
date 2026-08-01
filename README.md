# 🧱 LeoZap

> **Aleo 生态首个 Property-Based Fuzzer + Privacy Invariant Checker**
>
> 对标 Foundry forge fuzz · Move Prover · Echidna

<p align="center">
  <img src="https://img.shields.io/badge/status-hackathon--ready-brightgreen?style=for-the-badge" alt="status">
  <img src="https://img.shields.io/badge/tests-85%20passed-brightgreen?style=for-the-badge" alt="tests">
  <img src="https://img.shields.io/badge/Aleo-Leo%204.3.4-blue?style=for-the-badge" alt="leo">
  <img src="https://img.shields.io/badge/Rust-2021%20edition-orange?style=for-the-badge" alt="rust">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge" alt="license">
</p>

<p align="center">
  <a href="http://bore.pub:46914"><b>🖥️ Live Demo</b></a> &nbsp;·&nbsp;
  <a href="#-quick-start"><b>⚡ Quick Start</b></a> &nbsp;·&nbsp;
  <a href="#-architecture"><b>🏗️ Architecture</b></a> &nbsp;·&nbsp;
  <a href="#-invariant-spec-dsl"><b>📐 Spec DSL</b></a> &nbsp;·&nbsp;
  <a href="#-ecosystem-comparison"><b>🌍 Ecosystem</b></a>
</p>

---

## 🎯 Why LeoZap?

| Aleo 现状 | LeoZap 解法 |
|-----------|-------------|
| `leo test` 只支持 golden test | 随机生成隐私输入，符号执行追踪寄存器 |
| 没有 invariant / property test | 8 种内置 invariants + 自定义断言 DSL |
| 没有 fuzz coverage 工具 | 指令级覆盖率追踪 + 语料库变异 |
| ZK proof 正确性无法验证 | `leo run` + `snarkvm` 双重 ZK 验证 |
| 纯 CLI，无可视化 | Web Dashboard + SSE 实时流 |

---

## 🖥️ Live Demo

**一键启动**（自动编译、启动服务、创建公网隧道、崩溃自动重启）：

```bash
./start-demo.sh
```

启动后终端会打印公网 URL（格式 `http://bore.pub:XXXXX`），别人直接点开就能用。

<details>
<summary>📸 手动启动（点击展开）</summary>

```bash
git clone https://github.com/kaylia-builder/aleo-hackathon.git
cd aleo-hackathon/leo-zap
cargo build
cargo run -- serve          # 浏览器打开 http://localhost:3000
```
</details>

---

## ⚡ Quick Start

```bash
cd leo-zap && cargo build
```

```bash
# ┌─────────────────────────────────────────────────────┐
# │  PARSE — 解析 .aleo 合约结构                         │
# └─────────────────────────────────────────────────────┘
cargo run -- parse --file ../contracts/token_safe/build/token/token.aleo

# ┌─────────────────────────────────────────────────────┐
# │  FUZZ — 覆盖率引导的随机模糊测试                      │
# └─────────────────────────────────────────────────────┘
cargo run -- fuzz --file ../contracts/token_safe/build/token/token.aleo --runs 200

# ┌─────────────────────────────────────────────────────┐
# │  BUG HUNT — 不变式检查捕获隐私漏洞                   │
# └─────────────────────────────────────────────────────┘
cargo run -- check \
  --file ../contracts/token_bugged/build/token/token.aleo \
  --spec ../contracts/invariants/token_bugged.toml \
  --runs 100 --seed 42

# ┌─────────────────────────────────────────────────────┐
# │  SOURCE — 直接对 .leo 源码 fuzz（自动编译）          │
# └─────────────────────────────────────────────────────┘
cargo run -- fuzz --source ../contracts/token_safe --runs 100

# ┌─────────────────────────────────────────────────────┐
# │  ZK VERIFY — 真实零知识证明验证                       │
# └─────────────────────────────────────────────────────┘
cargo run -- fuzz --source ../contracts/token_safe \
  --project-dir ../contracts/token_safe --runs 50

# ┌─────────────────────────────────────────────────────┐
# │  WEB UI — 浏览器可视化面板                           │
# └─────────────────────────────────────────────────────┘
cargo run -- serve
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     🧱 LeoZap Stack                       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│   ┌──────────┐  ┌──────────┐  ┌────────────────────┐   │
│   │  .aleo   │  │  .leo    │  │   Invariant Spec    │   │
│   │  Parser  │  │  Builder │  │   TOML DSL          │   │
│   └────┬─────┘  └────┬─────┘  └─────────┬──────────┘   │
│        │              │                  │               │
│        └──────────────┼──────────────────┘               │
│                       ▼                                  │
│   ┌─────────────────────────────────────────────┐       │
│   │           🎲 Fuzz Engine                     │       │
│   │  ┌─────────────┐  ┌──────────────────────┐  │       │
│   │  │  Random     │  │  Coverage-Guided     │  │       │
│   │  │  Generator  │  │  Corpus Mutation     │  │       │
│   │  └──────┬──────┘  └──────────┬───────────┘  │       │
│   │         │                    │               │       │
│   │         └────────┬───────────┘               │       │
│   │                  ▼                           │       │
│   │  ┌─────────────────────────────────────┐    │       │
│   │  │   Symbolic Executor                 │    │       │
│   │  │   add · sub · cast · gt · assert    │    │       │
│   │  │   async · output · field-access     │    │       │
│   │  └─────────────────────────────────────┘    │       │
│   └─────────────────────┬───────────────────────┘       │
│                         ▼                                │
│   ┌─────────────────────────────────────────────┐       │
│   │         🔍 Invariant Checker                 │       │
│   │  balance · owner · overflow · zero-amount    │       │
│   │  self-transfer · record-consumption ·        │       │
│   │  private-param-usage · custom-assertions     │       │
│   └─────────────────────┬───────────────────────┘       │
│                         ▼                                │
│   ┌─────────────────────────────────────────────┐       │
│   │         🔐 ZK Verification                   │       │
│   │  ┌──────────┐  ┌───────────────────────┐    │       │
│   │  │ leo run  │  │  snarkvm verify       │    │       │
│   │  │ (proof)  │  │  (independent check)  │    │       │
│   │  └──────────┘  └───────────────────────┘    │       │
│   └─────────────────────┬───────────────────────┘       │
│                         ▼                                │
│   ┌─────────────────────────────────────────────┐       │
│   │  📊 Report {                                 │       │
│   │    passed, violations,                        │       │
│   │    zk_mismatches, coverage_pct,               │       │
│   │    violation_results[]                        │       │
│   │  }                                            │       │
│   └─────────────────────┬───────────────────────┘       │
│                         ▼                                │
│   ┌──────────┐  ┌──────────────────────────────┐       │
│   │  CLI     │  │  🌐 Web Dashboard             │       │
│   │  output  │  │  axum + SSE + Chart.js        │       │
│   └──────────┘  └──────────────────────────────┘       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 📐 Invariant Spec DSL

TOML 格式的声明式不变式规范语言，支持全局默认 + 按函数覆盖 + 自定义断言。

```toml
[contract]
name = "token.aleo"

# 全局默认
[invariants.default]
balance_conservation = true    # 非铸币操作保持余额守恒
owner_integrity = true         # output record 的 owner 字段有效
overflow_check = true          # 无符号整数溢出检查
record_consumption = true      # 输入 record 被消费（防双花）
private_param_usage = false    # 标记未使用的 .private 参数

# 按函数覆盖（mint 创建代币，不适用余额守恒）
[invariants.functions.mint_private]
balance_conservation = false

# 自定义断言
[[assertions]]
type = "amount_conserved"           # 输入总额 == 输出总额
function = "transfer_private"
description = "代币转移必须守恒"

[[assertions]]
type = "range_check"                # 数额在 [min, max] 范围
function = "transfer_private"
field = "amount"
min = 1

[[assertions]]
type = "no_field_none"              # 字段不能为空
function = "mint_private"
field = "owner"
```

---

## 🐛 Bug Detection Demo

Token 合约中故意植入 3 个 Bug，LeoZap 全部捕获：

| Bug | 位置 | 类型 | 检测方式 |
|-----|------|------|----------|
| 🐛 #1 | `transfer_private` 用 `+` 代替 `-` | 通胀漏洞 | `overflow_check` + `balance_conservation` |
| 🐛 #2 | `mint_private` 漏掉 `amount` 字段 | 字段缺失 | `field_set` 自定义断言 |
| 🐛 #3 | `transfer_private` 跳过扣款 | 双花 | `amount_conserved` 自定义断言 |

```
$ cargo run -- check --file token_bugged.aleo --spec token_bugged.toml --runs 100

  FAIL mint_private: 0/17 (0%)        ← Bug #2 命中
  FAIL transfer_private: 0/17 (0%)    ← Bug #1 & #3 命中

Result: 54 passed, 46 violations (3/3 bugs caught)
```

---

## 🌍 Ecosystem Comparison

| 功能 | LeoZap 🧱 | Foundry (Solidity) | Move Prover | Echidna |
|------|-----------|-------------------|-------------|---------|
| 随机输入生成 | ✅ coverage-guided | ✅ | ❌ | ✅ |
| 符号执行 | ✅ Aleo IR | ❌ | ✅ (Move IR) | ❌ |
| 不变量检查 | ✅ 8 种 + DSL | ✅ | ✅ | ✅ |
| ZK Proof 验证 | ✅ leo + snarkvm | ❌ | ❌ | ❌ |
| 隐私专项 invariant | ✅ record/private | ❌ | ❌ | ❌ |
| Web Dashboard | ✅ SSE real-time | ❌ | ❌ | ❌ |
| Spec 语言 | TOML DSL | Solidity inline | Move spec lang | Solidity inline |
| 代码覆盖率 | ✅ 指令级 | ✅ | ❌ | ✅ |

---

## 📁 Project Structure

```
aleo-hackathon/
├── leo-zap/                  # 🦀 Rust 工具源码
│   └── src/
│       ├── parser.rs         # .aleo 指令解析器
│       ├── generator.rs      # 随机输入生成 + 语料库变异
│       ├── fuzzer.rs         # 符号执行引擎 + Coverage Tracker
│       ├── invariants.rs     # 8 种不变式检查器
│       ├── spec.rs           # Invariant Spec TOML DSL
│       ├── leo_runner.rs     # leo run + snarkvm ZK 验证
│       ├── leo_compiler.rs   # leo build 自动编译
│       ├── web.rs            # axum HTTP server + SSE
│       ├── web_templates.rs  # 内嵌 Dashboard HTML/CSS/JS
│       └── main.rs           # CLI (clap)
├── contracts/                # 📜 Leo 合约
│   ├── token_safe/           # 安全版 token
│   ├── token_bugged/         # 3-bug 版 token
│   ├── private_voting/       # 隐私投票（safe）
│   ├── private_voting_bugged/# 隐私投票（bugged）
│   └── invariants/           # Spec 文件
├── token_demo/               # 官方 token demo
├── demo/                     # demo.sh 一键脚本
└── docs/                     # 设计文档
```

---

## 🧪 Tests

```
$ cargo test
running 85 tests
test result: ok. 85 passed; 0 failed; 0 ignored
```

---

## 🛠️ Tech Stack

| 层 | 技术 |
|----|------|
| 语言 | Rust 2021 |
| CLI | clap 4 |
| Web 框架 | axum 0.7 + tokio |
| 实时推送 | Server-Sent Events |
| 序列化 | serde + serde_json |
| 图表 | Chart.js 4 |
| ZK 验证 | `leo run` + `snarkvm` CLI |
| 模板 | 内嵌 HTML/CSS/JS |

---

## 📄 License

MIT © 2026

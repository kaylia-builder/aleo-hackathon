# Aleo Hackathon Project

> Building the future of programmable privacy on Aleo.

## Project: LeoZap

Property-based fuzzer + privacy invariant checker for Aleo Leo contracts.

### Why
Aleo 完全没有 property test / fuzz / 覆盖率 / 不变式断言工具（`leo test` 只支持 golden test）。
对标 Foundry forge fuzz / Move Prover。

### How
- 解析编译后的 `.aleo` instructions（稳定 IR），而非 `.leo` 源码
- 自动生成随机隐私输入（针对 `.private` 字段）
- 符号执行追踪寄存器值，检测 underflow/overflow/balance mismatch
- 验证隐私不变式（余额守恒、owner 不变式等）

### Quick Start
```bash
cd leo-zap
cargo build
# Parse a compiled .aleo file
cargo run -- parse --file ../token_demo/build/token/token.aleo
# Fuzz the token contract with 500 iterations
cargo run -- fuzz --file ../token_demo/build/token/token.aleo --runs 500
# Fuzz a specific function
cargo run -- fuzz --file ../token_demo/build/token/token.aleo --function transfer_private --runs 200
# Reproducible run with fixed seed
cargo run -- fuzz --file ../token_demo/build/token/token.aleo --runs 100 --seed 42
# Check invariants with a spec file
cargo run -- check --file ../token_demo/build/token/token.aleo --spec ../contracts/invariants/token.toml --runs 100 --seed 42
# Fuzz the bugged contract (all 3 bugs caught!)
cargo run -- check --file ../contracts/token_bugged/build/token/token.aleo --spec ../contracts/invariants/token_bugged.toml --runs 100 --seed 42
```

## Demo

```bash
# One-command demo — walks through all features
bash demo/demo.sh

# Or run individual steps:
cd leo-zap

# Parse contract
cargo run -- parse --file ../contracts/token_safe/build/token/token.aleo

# Fuzz with random inputs
cargo run -- fuzz --file ../contracts/token_safe/build/token/token.aleo --runs 100

# Check invariants (safe)
cargo run -- check --file ../contracts/token_safe/build/token/token.aleo --spec ../contracts/invariants/token.toml --runs 100

# Hunt bugs (bugged)
cargo run -- check --file ../contracts/token_bugged/build/token/token.aleo --spec ../contracts/invariants/token_bugged.toml --runs 100
```

## Structure
- `token_demo/` - 已跑通的官方 token 合约（含 4 个 4.3.4 兼容坑修复）
- `contracts/` - 多版本测试合约
  - `token_safe/` - 安全版 baseline
  - `token_bugged/` - 故意埋 bug 版（fuzzer 靶子）
  - `invariants/` - 不变式规范文件
- `leo-zap/` - LeoZap 工具源码（Rust）
- `docs/` - 设计文档
- `demo/` - Demo Day 材料

## Status
- [x] 环境就绪 (Ubuntu 26.04 + Leo 4.3.4)
- [x] token 合约跑通
- [x] 项目骨架初始化
- [x] .aleo parser 实现 (770 行, 11 tests)
- [x] fuzzer 引擎 (符号执行 + 随机输入生成, 37 tests)
- [x] invariant checker (spec 文件解析 + 自定义断言, 76 tests)
- [x] bugged 合约 (token_bugged/ — 3 deliberate bugs, all caught)
- [x] Demo (demo/demo.sh — 一键演示脚本)

## License
MIT

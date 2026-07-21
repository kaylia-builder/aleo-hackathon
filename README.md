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
- 驱动 snarkVM witness 生成 + verify
- 验证隐私不变式（余额守恒、owner 不变式等）

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
- [ ] .aleo parser 实现
- [ ] fuzzer 引擎
- [ ] invariant checker
- [ ] Demo

## License
MIT

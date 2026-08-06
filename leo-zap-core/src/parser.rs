//! # Aleo instructions 解析器
//!
//! 解析 `leo build` 产生的 `.aleo` 文件（稳定 IR），
//! 提取 record / mapping / function / finalize 结构。
//!
//! ## 解析策略
//!
//! Aleo instructions 是结构化的行格式：
//! - 每行一个语句
//! - 块以 `xxx:` 开头（如 `record token:` / `function mint_private:`）
//! - 块内的字段/参数以 `as` 关键字标识
//!
//! 用行扫描比正则更稳定、更好维护。

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// 数据结构
// ============================================================================

/// 解析后的完整 Aleo 合约
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contract {
    /// 合约名，如 "token.aleo"（来自 `program token.aleo;`）
    pub program: String,
    /// 所有 record 定义（隐私资产的核心数据结构）
    pub records: Vec<RecordDef>,
    /// 所有 mapping 定义（链上公开状态）
    pub mappings: Vec<MappingDef>,
    /// 所有 function 定义（链下生成 proof 的 transition）
    pub functions: Vec<FunctionDef>,
    /// 所有 finalize 定义（链上执行的逻辑，能改 mapping）
    pub finalizes: Vec<FunctionDef>,
}

/// record 定义
///
/// 对应：
/// ```text
/// record token:
///     owner as address.private;
///     amount as u64.private;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordDef {
    pub name: String,
    pub fields: Vec<RecordField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordField {
    pub name: String,
    pub ty: String,
    pub visibility: Visibility,
}

/// mapping 定义
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MappingDef {
    pub name: String,
    pub key_type: String,
    pub value_type: String,
}

/// function 或 finalize 定义
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionDef {
    pub name: String,
    pub inputs: Vec<Param>,
    pub outputs: Vec<Param>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Param {
    /// 寄存器名，如 "r0" / "r1"
    pub register: String,
    /// 参数类型，如 "address" / "u64" / "token.record"
    pub ty: String,
    /// 可见性（隐私参数是 fuzzer 的重点目标）
    pub visibility: Visibility,
}

/// 字段或参数的可见性
///
/// Aleo 隐私模型核心：`.private` 字段链上不可见，只有 owner 用 view key 才能解密。
/// fuzzer 重点 fuzz `.private` 字段。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
    Constant,
    /// 无可见性后缀（如 `token.record` / `xxx.future`）
    None,
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Private => write!(f, "private"),
            Visibility::Constant => write!(f, "constant"),
            Visibility::None => write!(f, ""),
        }
    }
}

// ============================================================================
// 错误类型
// ============================================================================

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("line {line}: {msg}")]
    Syntax { line: usize, msg: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("missing program declaration")]
    NoProgram,
}

// ============================================================================
// 入口函数
// ============================================================================

/// 解析 `.aleo` 文件内容，返回 Contract 结构
pub fn parse(content: &str) -> Result<Contract, ParseError> {
    let mut parser = Parser::new(content);
    parser.parse()
}

// ============================================================================
// 解析器主体
// ============================================================================

struct Parser<'a> {
    /// 预处理后的行列表：(行号, 行内容)，已过滤空行和注释
    lines: Vec<(usize, &'a str)>,
    /// 当前位置
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(content: &'a str) -> Self {
        let lines: Vec<(usize, &str)> = content
            .lines()
            .enumerate()
            .map(|(i, l)| (i + 1, l.trim()))
            .filter(|(_, l)| !l.is_empty() && !l.starts_with("//"))
            .collect();
        Self { lines, pos: 0 }
    }

    fn peek(&self) -> Option<(usize, &str)> {
        self.lines.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<(usize, &str)> {
        let r = self.lines.get(self.pos).copied();
        if r.is_some() {
            self.pos += 1;
        }
        r
    }

    /// 判断一行是否是块的开头
    pub fn is_block_header(line: &str) -> bool {
        line.starts_with("record ")
            || line.starts_with("mapping ")
            || line.starts_with("function ")
            || line.starts_with("finalize ")
            || line.starts_with("constructor")
            || line.starts_with("interface ")
    }

    fn parse(&mut self) -> Result<Contract, ParseError> {
        let mut contract = Contract {
            program: String::new(),
            records: vec![],
            mappings: vec![],
            functions: vec![],
            finalizes: vec![],
        };

        // 第一行必须是 `program xxx.aleo;`
        let (line_no, first) = self.next().ok_or(ParseError::NoProgram)?;
        if first.starts_with("program ") {
            contract.program = first
                .trim_start_matches("program ")
                .trim_end_matches(';')
                .trim()
                .to_string();
        } else {
            return Err(ParseError::Syntax {
                line: line_no,
                msg: format!("expected 'program xxx.aleo;', got: {}", first),
            });
        }

        // 逐块解析
        while let Some((_, line)) = self.peek() {
            if line.starts_with("record ") {
                contract.records.push(self.parse_record()?);
            } else if line.starts_with("mapping ") {
                contract.mappings.push(self.parse_mapping()?);
            } else if line.starts_with("function ") {
                contract.functions.push(self.parse_function("function")?);
            } else if line.starts_with("finalize ") {
                contract.finalizes.push(self.parse_function("finalize")?);
            } else if line.starts_with("constructor") || line.starts_with("interface ") {
                self.skip_block();
            } else {
                self.next();
            }
        }

        Ok(contract)
    }

    /// 解析 `record token: owner as address.private; amount as u64.private;`
    fn parse_record(&mut self) -> Result<RecordDef, ParseError> {
        let (line_no, header) = self.next().unwrap();
        let name = header
            .trim_start_matches("record ")
            .trim_end_matches(':')
            .trim()
            .to_string();

        if name.is_empty() {
            return Err(ParseError::Syntax {
                line: line_no,
                msg: "record name is empty".into(),
            });
        }

        let mut fields = vec![];
        while let Some((_, line)) = self.peek() {
            if Self::is_block_header(line) || !line.contains(" as ") {
                break;
            }
            let (ln, l) = self.next().unwrap();
            fields.push(parse_field_line(l, ln)?);
        }

        Ok(RecordDef { name, fields })
    }

    /// 解析 `mapping account: key as address.public; value as u64.public;`
    fn parse_mapping(&mut self) -> Result<MappingDef, ParseError> {
        let (line_no, header) = self.next().unwrap();
        let name = header
            .trim_start_matches("mapping ")
            .trim_end_matches(':')
            .trim()
            .to_string();

        if name.is_empty() {
            return Err(ParseError::Syntax {
                line: line_no,
                msg: "mapping name is empty".into(),
            });
        }

        let mut key_type = String::new();
        let mut value_type = String::new();

        while let Some((_, line)) = self.peek() {
            if Self::is_block_header(line) || !line.contains(" as ") {
                break;
            }
            let (_, l) = self.next().unwrap();
            let cleaned = l.trim_end_matches(';').trim();
            if let Some(rest) = cleaned.strip_prefix("key as ") {
                key_type = rest.trim().to_string();
            } else if let Some(rest) = cleaned.strip_prefix("value as ") {
                value_type = rest.trim().to_string();
            }
        }

        Ok(MappingDef {
            name,
            key_type,
            value_type,
        })
    }

    /// 解析 function 或 finalize 块（kind = "function" 或 "finalize"）
    fn parse_function(&mut self, kind: &str) -> Result<FunctionDef, ParseError> {
        let (line_no, header) = self.next().unwrap();
        let name = header
            .trim_start_matches(kind)
            .trim()
            .trim_end_matches(':')
            .trim()
            .to_string();

        if name.is_empty() {
            return Err(ParseError::Syntax {
                line: line_no,
                msg: format!("{} name is empty", kind),
            });
        }

        let mut inputs = vec![];
        let mut outputs = vec![];

        while let Some((_, line)) = self.peek() {
            if Self::is_block_header(line) {
                break;
            }

            let (_, l) = self.next().unwrap();
            let cleaned = l.trim_end_matches(';').trim();

            if let Some(rest) = cleaned.strip_prefix("input ") {
                if let Some(p) = parse_param(rest) {
                    inputs.push(p);
                }
            } else if let Some(rest) = cleaned.strip_prefix("output ") {
                if let Some(p) = parse_param(rest) {
                    outputs.push(p);
                }
            }
            // 其他指令（add/sub/cast/get.or_use/set/async 等）跳过
        }

        Ok(FunctionDef {
            name,
            inputs,
            outputs,
        })
    }

    /// 跳过 constructor / interface 等暂不解析的块
    fn skip_block(&mut self) {
        self.next();
        while let Some((_, line)) = self.peek() {
            if Self::is_block_header(line) {
                break;
            }
            self.next();
        }
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// "owner as address.private" -> RecordField
fn parse_field_line(line: &str, line_no: usize) -> Result<RecordField, ParseError> {
    let cleaned = line.trim_end_matches(';').trim();
    let parts: Vec<&str> = cleaned.splitn(2, " as ").collect();
    if parts.len() != 2 {
        return Err(ParseError::Syntax {
            line: line_no,
            msg: format!("expected 'name as type.visibility', got: {}", line),
        });
    }
    let name = parts[0].trim().to_string();
    let (ty, visibility) = parse_type_visibility(parts[1].trim());
    Ok(RecordField {
        name,
        ty,
        visibility,
    })
}

/// "r0 as address.public" -> Param
fn parse_param(rest: &str) -> Option<Param> {
    let parts: Vec<&str> = rest.splitn(2, " as ").collect();
    if parts.len() != 2 {
        return None;
    }
    let register = parts[0].trim().to_string();
    let (ty, visibility) = parse_type_visibility(parts[1].trim());
    Some(Param {
        register,
        ty,
        visibility,
    })
}

/// "address.private" -> ("address", Private)
/// "u64.public" -> ("u64", Public)
/// "token.record" -> ("token.record", None)
/// "token.aleo/mint_public.future" -> ("token.aleo/mint_public.future", None)
pub fn parse_type_visibility(s: &str) -> (String, Visibility) {
    if let Some(pos) = s.rfind('.') {
        let ty = &s[..pos];
        let vis = &s[pos + 1..];
        match vis {
            "public" => return (ty.to_string(), Visibility::Public),
            "private" => return (ty.to_string(), Visibility::Private),
            "constant" => return (ty.to_string(), Visibility::Constant),
            _ => {}
        }
    }
    (s.to_string(), Visibility::None)
}

/// 格式化类型 + 可见性（None 时不显示后缀）
fn format_type_vis(ty: &str, vis: Visibility) -> String {
    match vis {
        Visibility::None => ty.to_string(),
        _ => format!("{}.{}", ty, vis),
    }
}

// ============================================================================
// 格式化输出
// ============================================================================

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// 简化样本：含 record / mapping / 2 个 function / 1 个 finalize
    const SAMPLE: &str = r#"program token.aleo;

record token:
    owner as address.private;
    amount as u64.private;

mapping account:
    key as address.public;
    value as u64.public;

function mint_public:
    input r0 as address.public;
    input r1 as u64.public;
    async mint_public r0 r1 into r2;
    output r2 as token.aleo/mint_public.future;

finalize mint_public:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];

function mint_private:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;
"#;

    #[test]
    fn test_parse_program_name() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.program, "token.aleo");
    }

    #[test]
    fn test_empty_contract() {
        let c = parse("program empty.aleo;\n").unwrap();
        assert_eq!(c.program, "empty.aleo");
        assert!(c.records.is_empty());
        assert!(c.mappings.is_empty());
        assert!(c.functions.is_empty());
        assert!(c.finalizes.is_empty());
    }

    #[test]
    fn test_parse_record() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.records.len(), 1);

        let r = &c.records[0];
        assert_eq!(r.name, "token");
        assert_eq!(r.fields.len(), 2);

        assert_eq!(r.fields[0].name, "owner");
        assert_eq!(r.fields[0].ty, "address");
        assert_eq!(r.fields[0].visibility, Visibility::Private);

        assert_eq!(r.fields[1].name, "amount");
        assert_eq!(r.fields[1].ty, "u64");
        assert_eq!(r.fields[1].visibility, Visibility::Private);
    }

    #[test]
    fn test_parse_mapping() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.mappings.len(), 1);

        let m = &c.mappings[0];
        assert_eq!(m.name, "account");
        assert_eq!(m.key_type, "address.public");
        assert_eq!(m.value_type, "u64.public");
    }

    #[test]
    fn test_parse_functions() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.functions.len(), 2);

        let f0 = &c.functions[0];
        assert_eq!(f0.name, "mint_public");
        assert_eq!(f0.inputs.len(), 2);
        assert_eq!(f0.inputs[0].register, "r0");
        assert_eq!(f0.inputs[0].ty, "address");
        assert_eq!(f0.inputs[0].visibility, Visibility::Public);
        assert_eq!(f0.outputs.len(), 1);
        assert_eq!(f0.outputs[0].ty, "token.aleo/mint_public.future");
        assert_eq!(f0.outputs[0].visibility, Visibility::None);

        let f1 = &c.functions[1];
        assert_eq!(f1.name, "mint_private");
        assert_eq!(f1.inputs.len(), 2);
        assert_eq!(f1.inputs[0].visibility, Visibility::Private);
        assert_eq!(f1.outputs.len(), 1);
        assert_eq!(f1.outputs[0].ty, "token.record");
    }

    #[test]
    fn test_parse_finalizes() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.finalizes.len(), 1);

        let f = &c.finalizes[0];
        assert_eq!(f.name, "mint_public");
        assert_eq!(f.inputs.len(), 2);
        assert_eq!(f.outputs.len(), 0);
    }

    #[test]
    fn test_parse_type_visibility() {
        assert_eq!(
            parse_type_visibility("address.private"),
            ("address".to_string(), Visibility::Private)
        );
        assert_eq!(
            parse_type_visibility("u64.public"),
            ("u64".to_string(), Visibility::Public)
        );
        assert_eq!(
            parse_type_visibility("u8.constant"),
            ("u8".to_string(), Visibility::Constant)
        );
        assert_eq!(
            parse_type_visibility("token.record"),
            ("token.record".to_string(), Visibility::None)
        );
        assert_eq!(
            parse_type_visibility("token.aleo/mint_public.future"),
            ("token.aleo/mint_public.future".to_string(), Visibility::None)
        );
        assert_eq!(
            parse_type_visibility("address"),
            ("address".to_string(), Visibility::None)
        );
    }

    #[test]
    fn test_serialize_contract() {
        let c = parse(SAMPLE).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("token.aleo"));
        assert!(json.contains("\"records\""));
        assert!(json.contains("\"functions\""));
        assert!(json.contains("mint_public"));
        assert!(json.contains("mint_private"));
    }

    #[test]
    fn test_error_no_program() {
        let result = parse("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ParseError::NoProgram));
    }

    #[test]
    fn test_error_missing_program_keyword() {
        let result = parse("not a program declaration;\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_full_token_contract() {
        // 完整 token.aleo（6 function + 4 finalize + constructor）
        let full = r#"program token.aleo;

record token:
    owner as address.private;
    amount as u64.private;

mapping account:
    key as address.public;
    value as u64.public;

function mint_public:
    input r0 as address.public;
    input r1 as u64.public;
    async mint_public r0 r1 into r2;
    output r2 as token.aleo/mint_public.future;

finalize mint_public:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];

function mint_private:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function transfer_public:
    input r0 as address.public;
    input r1 as u64.public;
    async transfer_public self.caller r0 r1 into r2;
    output r2 as token.aleo/transfer_public.future;

finalize transfer_public:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.public;
    get.or_use account[r0] 0u64 into r3;
    sub r3 r2 into r4;
    set r4 into account[r0];
    get.or_use account[r1] 0u64 into r5;
    add r5 r2 into r6;
    set r6 into account[r1];

function transfer_private:
    input r0 as token.record;
    input r1 as address.private;
    input r2 as u64.private;
    sub r0.amount r2 into r3;
    cast r0.owner r3 into r4 as token.record;
    cast r1 r2 into r5 as token.record;
    output r4 as token.record;
    output r5 as token.record;

function transfer_private_to_public:
    input r0 as token.record;
    input r1 as address.public;
    input r2 as u64.public;
    sub r0.amount r2 into r3;
    cast r0.owner r3 into r4 as token.record;
    async transfer_private_to_public r1 r2 into r5;
    output r4 as token.record;
    output r5 as token.aleo/transfer_private_to_public.future;

finalize transfer_private_to_public:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];

function transfer_public_to_private:
    input r0 as address.public;
    input r1 as u64.public;
    cast r0 r1 into r2 as token.record;
    async transfer_public_to_private self.caller r1 into r3;
    output r2 as token.record;
    output r3 as token.aleo/transfer_public_to_private.future;

finalize transfer_public_to_private:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    sub r2 r1 into r3;
    set r3 into account[r0];

constructor:
    assert.eq edition 0u16;
"#;

        let c = parse(full).unwrap();

        assert_eq!(c.program, "token.aleo");
        assert_eq!(c.records.len(), 1);
        assert_eq!(c.mappings.len(), 1);
        assert_eq!(c.functions.len(), 6);
        assert_eq!(c.finalizes.len(), 4);

        // 验证 transfer_private 有 2 个 output
        let transfer_priv = c
            .functions
            .iter()
            .find(|f| f.name == "transfer_private")
            .unwrap();
        assert_eq!(transfer_priv.outputs.len(), 2);
        assert_eq!(transfer_priv.outputs[0].ty, "token.record");
        assert_eq!(transfer_priv.outputs[1].ty, "token.record");
    }
}

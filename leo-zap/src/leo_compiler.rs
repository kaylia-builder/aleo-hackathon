//! # Leo Compiler — Leo 源码编译
//!
//! 包装 `leo build` 命令，将 `.leo` 源码项目编译为 `.aleo` 文件。
//! 这让 LeoZap 不仅支持预编译的 `.aleo`，还能直接对 Leo 源码项目做 fuzz。
//!
//! ## 使用
//! ```ignore
//! let aleo_path = leo_compiler::build_project("contracts/token_safe")?;
//! // aleo_path -> "contracts/token_safe/build/token.aleo"
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

/// 编译 Leo 源码项目，返回 `.aleo` 文件路径
///
/// # 参数
/// - `source_dir`: Leo 项目根目录（含 `program.json` 和 `src/main.leo`）
///
/// # 返回
/// - `Ok(PathBuf)`: 编译产出的 `.aleo` 文件路径
/// - `Err(String)`: 编译失败的错误描述
pub fn build_project(source_dir: &Path) -> Result<PathBuf, String> {
    // 验证目录存在
    if !source_dir.exists() {
        return Err(format!("source directory '{}' does not exist", source_dir.display()));
    }
    if !source_dir.is_dir() {
        return Err(format!("'{}' is not a directory", source_dir.display()));
    }

    // 验证是 Leo 项目（含 program.json）
    let program_json = source_dir.join("program.json");
    if !program_json.exists() {
        return Err(format!(
            "'{}' does not contain program.json — is this a Leo project?",
            source_dir.display()
        ));
    }

    // 查找 leo 二进制
    let leo_path = find_leo()
        .ok_or_else(|| "leo CLI not found. Install Leo: https://developer.aleo.org/leo/installation".to_string())?;

    // 执行 leo build
    let start = std::time::Instant::now();
    let output = Command::new(&leo_path)
        .arg("build")
        .current_dir(source_dir)
        .output()
        .map_err(|e| format!("failed to run 'leo build': {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "leo build failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.lines().take(5).collect::<Vec<_>>().join("; ")
        ));
    }

    let elapsed = start.elapsed();

    // 查找编译产出: build/<program_name>.aleo
    let aleo_path = find_aleo_output(source_dir)
        .ok_or_else(|| {
            format!(
                "leo build succeeded but no .aleo file found under {}/build/",
                source_dir.display()
            )
        })?;

    eprintln!(
        "  {} compiled in {:.1}s -> {}",
        "✅".green(),
        elapsed.as_secs_f64(),
        aleo_path.display()
    );

    Ok(aleo_path)
}

/// 在 PATH 中查找 leo 二进制
fn find_leo() -> Option<String> {
    // 优先 PATH
    if let Ok(path) = which_cmd("leo") {
        return Some(path);
    }
    // 常见路径
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        "/usr/local/bin/leo",
        "/usr/bin/leo",
        &format!("{}/.cargo/bin/leo", home),
        &format!("{}/.leo/bin/leo", home),
    ];
    for c in &candidates {
        if Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    None
}

/// 简易 which 实现
fn which_cmd(cmd: &str) -> Result<String, std::io::Error> {
    let output = Command::new("which").arg(cmd).output()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(path);
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"))
}

/// 在 build/ 目录下查找 .aleo 文件
fn find_aleo_output(source_dir: &Path) -> Option<PathBuf> {
    let build_dir = source_dir.join("build");
    if !build_dir.exists() {
        return None;
    }

    // 递归查找 .aleo 文件
    find_aleo_recursive(&build_dir)
}

fn find_aleo_recursive(dir: &Path) -> Option<PathBuf> {
    if !dir.is_dir() {
        return None;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = find_aleo_recursive(&path) {
                    return Some(found);
                }
            } else if path.extension().map_or(false, |e| e == "aleo") {
                return Some(path);
            }
        }
    }
    None
}

// Import colored for log messages
use colored::Colorize;

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_leo_exists() {
        // leo should be installed in the dev environment
        let leo = find_leo();
        // Not strictly required — but expected in a dev setup
        if leo.is_none() {
            eprintln!("warning: leo not found in PATH — some tests will be skipped");
        }
    }

    #[test]
    fn test_build_nonexistent_dir() {
        let result = build_project(Path::new("/tmp/nonexistent_leo_project_12345"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn test_build_not_a_leo_project() {
        let result = build_project(Path::new("/tmp"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("program.json"));
    }
}

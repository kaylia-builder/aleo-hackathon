#!/usr/bin/env bash
# ==============================================================================
# LeoZap Demo Script
#
# Walks through all features:
#   1. Parse    — inspect contract structure
#   2. Fuzz     — random fuzzing on safe contract
#   3. Check    — invariant checking on safe contract
#   4. Bug Hunt — invariant checking on bugged contract
#   5. Compare  — side-by-side summary
#
# Usage:  bash demo/demo.sh
# ==============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/leo-zap"

BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
MAGENTA="\033[35m"
RESET="\033[0m"

SAFE_ALEO="$ROOT/contracts/token_safe/build/token/token.aleo"
BUGGED_ALEO="$ROOT/contracts/token_bugged/build/token/token.aleo"
SAFE_SPEC="$ROOT/contracts/invariants/token.toml"
BUGGED_SPEC="$ROOT/contracts/invariants/token_bugged.toml"

divider() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

step() {
    echo ""
    echo -e "${BOLD}${YELLOW}━━━ $1 ━━━${RESET}"
    echo -e "  ${MAGENTA}$2${RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# Ensure built
# ---------------------------------------------------------------------------
echo -e "${BOLD}${CYAN}🦁 LeoZap Demo${RESET}"
echo "  Property-based fuzzer + privacy invariant checker for Aleo"
divider

echo -e "Building..."
cargo build --release -q 2>&1 | tail -1 || cargo build -q 2>&1 | tail -1
echo -e "${GREEN}✅ Build ready${RESET}"

# ===========================================================================
# STEP 1: Parse
# ===========================================================================
step "Step 1: Parse" "Inspect the token contract structure"
echo -e "Command: ${CYAN}leo-zap parse --file .../token.aleo${RESET}"
echo ""
cargo run -- parse --file "$SAFE_ALEO" 2>/dev/null

# ===========================================================================
# STEP 2: Fuzz (safe)
# ===========================================================================
divider
step "Step 2: Fuzz (safe contract)" "Random input fuzzing on ALL functions"
echo -e "Command: ${CYAN}leo-zap fuzz --file .../token.aleo --runs 60 --seed 42${RESET}"
echo ""
cargo run -- fuzz --file "$SAFE_ALEO" --runs 60 --seed 42 2>/dev/null

# ===========================================================================
# STEP 3: Check (safe)
# ===========================================================================
divider
step "Step 3: Invariant Check (safe contract)" "Check invariants with spec file"
echo -e "Command: ${CYAN}leo-zap check --file .../token.aleo --spec .../token.toml --runs 60${RESET}"
echo ""
cargo run -- check --file "$SAFE_ALEO" --spec "$SAFE_SPEC" --runs 60 --seed 42 2>/dev/null

# ===========================================================================
# STEP 4: Bug Hunt
# ===========================================================================
divider
step "Step 4: Bug Hunt (bugged contract)" "Same checks on the deliberately buggy contract"
echo -e "${RED}This contract has 3 intentional bugs:${RESET}"
echo -e "  ${RED}🐛 Bug #1:${RESET} transfer_private uses ADD instead of SUB (inflation!)"
echo -e "  ${RED}🐛 Bug #2:${RESET} mint_private skips the owner field (missing ownership)"
echo -e "  ${RED}🐛 Bug #3:${RESET} transfer_private skips deduction (double-spend)"
echo ""
echo -e "Command: ${CYAN}leo-zap check --file .../token_bugged.aleo --spec .../token_bugged.toml --runs 60${RESET}"
echo ""
cargo run -- check --file "$BUGGED_ALEO" --spec "$BUGGED_SPEC" --runs 60 --seed 42 2>/dev/null

# ===========================================================================
# STEP 5: Compare
# ===========================================================================
divider
step "Step 5: Compare" "Safe vs Bugged — pass rates per function"
echo ""

# Run both and extract pass/fail rates
echo -e "${BOLD}Running both contracts with same seed & settings...${RESET}"
echo ""

SAFE_OUT=$(cargo run -- check --file "$SAFE_ALEO" --spec "$BUGGED_SPEC" --runs 60 --seed 42 2>/dev/null)
BUGGED_OUT=$(cargo run -- check --file "$BUGGED_ALEO" --spec "$BUGGED_SPEC" --runs 60 --seed 42 2>/dev/null)

echo -e "${BOLD}┌──────────────────────┬─────────────────────┬─────────────────────┐${RESET}"
echo -e "${BOLD}│ Function             │ Safe Contract       │ Bugged Contract     │${RESET}"
echo -e "${BOLD}├──────────────────────┼─────────────────────┼─────────────────────┤${RESET}"

compare_line() {
    local func="$1"
    local safe_line=$(echo "$SAFE_OUT" | grep "$func:" | head -1)
    local bugged_line=$(echo "$BUGGED_OUT" | grep "$func:" | head -1)

    local safe_pct="N/A"
    local bugged_pct="N/A"
    local safe_color="$GREEN"
    local bugged_color="$GREEN"

    if [[ "$safe_line" =~ ([0-9]+)/([0-9]+) ]]; then
        local pass="${BASH_REMATCH[1]}"
        local total="${BASH_REMATCH[2]}"
        safe_pct=$(( pass * 100 / total ))
        if [[ $safe_pct -lt 90 ]]; then safe_color="$YELLOW"; fi
        if [[ $safe_pct -lt 50 ]]; then safe_color="$RED"; fi
        safe_pct="${safe_pct}%"
    fi

    if [[ "$bugged_line" =~ ([0-9]+)/([0-9]+) ]]; then
        local pass="${BASH_REMATCH[1]}"
        local total="${BASH_REMATCH[2]}"
        bugged_pct=$(( pass * 100 / total ))
        if [[ $bugged_pct -lt 90 ]]; then bugged_color="$YELLOW"; fi
        if [[ $bugged_pct -lt 50 ]]; then bugged_color="$RED"; fi
        bugged_pct="${bugged_pct}%"
    fi

    printf " │ %-20s │ ${safe_color}%-19s${RESET} │ ${bugged_color}%-19s${RESET} │\n" \
        "$func" "$safe_pct" "$bugged_pct"
}

compare_line "mint_public"
compare_line "mint_private"
compare_line "transfer_public"
compare_line "transfer_private"
compare_line "transfer_private_to_public"
compare_line "transfer_public_to_private"

echo -e "${BOLD}└──────────────────────┴─────────────────────┴─────────────────────┘${RESET}"
echo ""

# Highlight bugs found
echo -e "${BOLD}${GREEN}Bugs detected in bugged contract:${RESET}"
echo ""
SAFE_MINT=$(echo "$SAFE_OUT" | grep "mint_private:" | head -1)
BUGGED_MINT=$(echo "$BUGGED_OUT" | grep "mint_private:" | head -1)
SAFE_XFER=$(echo "$SAFE_OUT" | grep "transfer_private:" | head -1)
BUGGED_XFER=$(echo "$BUGGED_OUT" | grep "transfer_private:" | head -1)

echo -e "  🐛 ${RED}#1 Inflation:${RESET}   transfer_private safe=${YELLOW}${SAFE_XFER##* }${RESET} → bugged=${RED}${BUGGED_XFER##* }${RESET}"
echo -e "  🐛 ${RED}#2 No Owner:${RESET}   mint_private      safe=${YELLOW}${SAFE_MINT##* }${RESET} → bugged=${RED}${BUGGED_MINT##* }${RESET}"
echo -e "  🐛 ${RED}#3 No Deduct:${RESET}  transfer_private safe=${YELLOW}${SAFE_XFER##* }${RESET} → bugged=${RED}${BUGGED_XFER##* }${RESET}"

divider
echo -e "${BOLD}${GREEN}✅ Demo complete!${RESET}"
echo ""
echo -e "Try it yourself:"
echo -e "  ${CYAN}cd leo-zap${RESET}"
echo -e "  ${CYAN}cargo run -- parse --file ../contracts/token_safe/build/token/token.aleo${RESET}"
echo -e "  ${CYAN}cargo run -- fuzz --file ../contracts/token_safe/build/token/token.aleo --runs 100${RESET}"
echo -e "  ${CYAN}cargo run -- check --file ../contracts/token_safe/build/token/token.aleo --spec ../contracts/invariants/token.toml${RESET}"
echo -e "  ${CYAN}cargo run -- check --file ../contracts/token_bugged/build/token/token.aleo --spec ../contracts/invariants/token_bugged.toml${RESET}"
echo ""

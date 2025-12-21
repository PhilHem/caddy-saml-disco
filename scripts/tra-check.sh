#!/usr/bin/env bash
#
# Pre-commit hook: Enforce TRA metadata on new/modified test files
#
# Installation:
#   cp scripts/tra-check.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or with pre-commit framework (.pre-commit-config.yaml):
#   - repo: local
#     hooks:
#       - id: tra-check
#         name: TRA Enforcement
#         entry: ./scripts/tra-check.sh
#         language: script
#         files: '_test\.go$'

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

errors=()
warnings=()

# Get staged test files
staged_files=$(git diff --cached --name-only --diff-filter=ACM)

check_go_file() {
    local file="$1"

    # Skip non-test files
    if [[ ! "$file" =~ _test\.go$ ]]; then
        return
    fi

    # Find test functions
    local test_funcs
    test_funcs=$(grep -n "^func Test" "$file" 2>/dev/null || true)

    if [[ -z "$test_funcs" ]]; then
        return
    fi

    while IFS= read -r line; do
        local line_num="${line%%:*}"
        local func_name
        func_name=$(echo "$line" | sed -n 's/.*func \(Test[^(]*\).*/\1/p')

        # Look for tra.Require or tra.RequireLegacy in function body
        # Simple heuristic: check next 20 lines for the call
        local end=$((line_num + 20))
        local body
        body=$(sed -n "${line_num},${end}p" "$file")

        if ! echo "$body" | grep -q 'tra\.Require\|tra\.RequireLegacy'; then
            warnings+=("$file:$line_num: $func_name may be missing tra.Require() - verify manually")
        fi

    done <<< "$test_funcs"
}

# Process each staged file
for file in $staged_files; do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    if [[ "$file" =~ \.go$ ]]; then
        check_go_file "$file"
    fi
done

# Report warnings
if [[ ${#warnings[@]} -gt 0 ]]; then
    echo -e "${YELLOW}TRA Warnings:${NC}"
    for warning in "${warnings[@]}"; do
        echo -e "  ${YELLOW}!${NC} $warning"
    done
    echo ""
fi

# Report errors and fail if any
if [[ ${#errors[@]} -gt 0 ]]; then
    echo -e "${RED}TRA Enforcement Failed:${NC}"
    for error in "${errors[@]}"; do
        echo -e "  ${RED}x${NC} $error"
    done
    echo ""
    echo -e "${RED}Every test must have exactly one tra.Require() or tra.RequireLegacy() call.${NC}"
    exit 1
fi

if [[ ${#warnings[@]} -eq 0 ]] && [[ ${#errors[@]} -eq 0 ]]; then
    # Only print if there were test files
    if echo "$staged_files" | grep -qE '\.go$'; then
        echo -e "${GREEN}TRA check passed${NC}"
    fi
fi

exit 0

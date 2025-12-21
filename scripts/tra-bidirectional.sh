#!/usr/bin/env bash
#
# Pre-commit hook: Bidirectional TRA validation
#
# Validates that @tra: annotations in production code reference TRAs
# that actually exist in the test suite.
#
# Installation:
#   Include in .git/hooks/pre-commit or use pre-commit framework

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

errors=()
warnings=()

# Build list of all TRAs defined in test files
collect_test_tras() {
    local tras=()

    # Go: tra.Require(t, "...")
    while IFS= read -r line; do
        anchor=$(echo "$line" | grep -oE 'tra\.Require\s*\(\s*\w+\s*,\s*"[^"]+"' | grep -oE '"[^"]+"' | tr -d '"' || true)
        if [[ -n "$anchor" ]]; then
            tras+=("$anchor")
        fi
    done < <(grep -rh 'tra\.Require' . --include='*_test.go' 2>/dev/null || true)

    # Deduplicate and output
    printf '%s\n' "${tras[@]}" | sort -u
}

# Check @tra: annotations in staged files
check_code_annotations() {
    local staged_files="$1"
    local known_tras="$2"

    for file in $staged_files; do
        # Skip test files
        if [[ "$file" =~ _test\.go$ ]]; then
            continue
        fi

        # Skip non-Go files
        if [[ ! "$file" =~ \.go$ ]]; then
            continue
        fi

        if [[ ! -f "$file" ]]; then
            continue
        fi

        # Find @tra: annotations
        while IFS=: read -r line_num content; do
            # Extract anchor from // @tra: Anchor
            anchor=$(echo "$content" | grep -oE '@tra:\s*[A-Za-z0-9_.]+' | sed 's/@tra:\s*//' || true)

            if [[ -z "$anchor" ]]; then
                continue
            fi

            # Validate anchor format
            if ! echo "$anchor" | grep -qE '^(Domain\.(Invariant|Policy)|UseCase|Port|Adapter|Contract)\.'; then
                errors+=("$file:$line_num: Invalid TRA format '$anchor'")
                continue
            fi

            # Check if TRA exists in test suite
            if ! echo "$known_tras" | grep -qxF "$anchor"; then
                errors+=("$file:$line_num: Orphaned @tra: '$anchor' - no matching test found")
            fi

        done < <(grep -n '@tra:' "$file" 2>/dev/null || true)
    done
}

main() {
    # Get staged files
    local staged_files
    staged_files=$(git diff --cached --name-only --diff-filter=ACM)

    if [[ -z "$staged_files" ]]; then
        exit 0
    fi

    # Check if any Go code files are staged (not tests)
    local has_code_files=false
    for file in $staged_files; do
        if [[ "$file" =~ \.go$ ]] && [[ ! "$file" =~ _test\.go$ ]]; then
            has_code_files=true
            break
        fi
    done

    if [[ "$has_code_files" == "false" ]]; then
        exit 0
    fi

    echo "Collecting TRAs from test suite..."
    local known_tras
    known_tras=$(collect_test_tras)

    if [[ -z "$known_tras" ]]; then
        echo -e "${YELLOW}Warning: No TRAs found in test suite. Skipping validation.${NC}"
        exit 0
    fi

    echo "Validating @tra: annotations in staged files..."
    check_code_annotations "$staged_files" "$known_tras"

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
        echo -e "${RED}TRA Validation Failed:${NC}"
        for error in "${errors[@]}"; do
            echo -e "  ${RED}x${NC} $error"
        done
        echo ""
        echo -e "${RED}@tra: annotations must reference existing TRAs in the test suite.${NC}"
        echo "Either:"
        echo "  1. Create a test with tra.Require(t, '...')"
        echo "  2. Remove the @tra: annotation from the code"
        echo "  3. Fix the typo in the anchor name"
        exit 1
    fi

    echo -e "${GREEN}TRA validation passed${NC}"
    exit 0
}

main "$@"

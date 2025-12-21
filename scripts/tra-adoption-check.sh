#!/usr/bin/env bash
#
# TRA Adoption State Check
#
# Verifies that TRA scaffolding is properly set up in a project.
# Run this to audit adoption status or after initial setup.
#
# Usage:
#   ./scripts/tra-adoption-check.sh [project-root]
#
# Exit codes:
#   0 - All checks passed
#   1 - Critical issues found
#   2 - Warnings only

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

PROJECT_ROOT="${1:-.}"
cd "$PROJECT_ROOT"

errors=()
warnings=()
info=()

section() {
    echo ""
    echo -e "${BOLD}${BLUE}[$1]${NC}"
}

check_pass() {
    echo -e "  ${GREEN}v${NC} $1"
}

check_fail() {
    echo -e "  ${RED}x${NC} $1"
    errors+=("$1")
}

check_warn() {
    echo -e "  ${YELLOW}!${NC} $1"
    warnings+=("$1")
}

check_info() {
    echo -e "  ${BLUE}i${NC} $1"
    info+=("$1")
}

# =============================================================================
# Check 1: Go TRA package
# =============================================================================
section "Go TRA Package"

go_tra_found=false
for path in internal/testutil/tra/tra.go pkg/testutil/tra/tra.go testutil/tra/tra.go; do
    if [[ -f "$path" ]]; then
        check_pass "Go TRA package found at $path"
        go_tra_found=true
        break
    fi
done

if [[ "$go_tra_found" == "false" ]]; then
    if find . -name '*_test.go' -type f 2>/dev/null | head -1 | grep -q .; then
        check_fail "No Go TRA package found (expected internal/testutil/tra/tra.go)"
    else
        check_info "No Go tests detected - skipping Go TRA check"
    fi
fi

# =============================================================================
# Check 2: Pre-commit hooks
# =============================================================================
section "Pre-commit Hooks"

if [[ -f ".git/hooks/pre-commit" ]]; then
    if grep -q 'tra' .git/hooks/pre-commit 2>/dev/null; then
        check_pass ".git/hooks/pre-commit contains TRA enforcement"

        if grep -q 'bidirectional\|@tra:' .git/hooks/pre-commit 2>/dev/null; then
            check_pass "Bidirectional TRA validation enabled"
        else
            check_warn "Bidirectional validation not detected - consider adding"
        fi
    else
        check_warn ".git/hooks/pre-commit exists but doesn't mention TRA"
    fi
elif [[ -f ".pre-commit-config.yaml" ]]; then
    if grep -q 'tra' .pre-commit-config.yaml 2>/dev/null; then
        check_pass ".pre-commit-config.yaml contains TRA hook"
    else
        check_warn ".pre-commit-config.yaml exists but no TRA hook configured"
    fi
else
    check_warn "No pre-commit hook found for TRA enforcement"
fi

# Check for TRA scripts
if [[ -f "scripts/tra-check.sh" ]]; then
    check_pass "scripts/tra-check.sh exists"
else
    check_warn "scripts/tra-check.sh not found"
fi

if [[ -f "scripts/tra-bidirectional.sh" ]]; then
    check_pass "scripts/tra-bidirectional.sh exists"
else
    check_info "scripts/tra-bidirectional.sh not found (optional)"
fi

# =============================================================================
# Check 3: CLAUDE.md References
# =============================================================================
section "CLAUDE.md Configuration"

claude_md=""
if [[ -f "CLAUDE.md" ]]; then
    claude_md="CLAUDE.md"
elif [[ -f ".claude/CLAUDE.md" ]]; then
    claude_md=".claude/CLAUDE.md"
elif [[ -f "claude.md" ]]; then
    claude_md="claude.md"
fi

if [[ -n "$claude_md" ]]; then
    check_pass "Found $claude_md"

    # Check for TRA mentions
    if grep -qi 'tra\|test.responsibility' "$claude_md" 2>/dev/null; then
        check_pass "$claude_md mentions TRA"
    else
        check_fail "$claude_md does not mention TRA - add instructions for LLM"
    fi

    # Check for @tra: annotation guidance
    if grep -q '@tra:' "$claude_md" 2>/dev/null; then
        check_pass "$claude_md documents @tra: code annotations"
    else
        check_warn "$claude_md should document @tra: annotation convention"
    fi

    # Check for test file references
    if grep -qE 'tra\.go' "$claude_md" 2>/dev/null; then
        check_pass "$claude_md references TRA implementation files"
    else
        check_warn "$claude_md should reference TRA implementation locations"
    fi
else
    check_fail "No CLAUDE.md found - LLM won't know about TRA conventions"
fi

# =============================================================================
# Check 4: Deprecated TEST_MAP.md
# =============================================================================
section "Deprecated Patterns"

test_maps=$(find . -name 'TEST_MAP.md' -type f 2>/dev/null || true)
if [[ -n "$test_maps" ]]; then
    while IFS= read -r map_file; do
        check_warn "Found $map_file - TEST_MAP.md is deprecated"
    done <<< "$test_maps"
    echo -e "  ${YELLOW}->${NC} Use @tra: code annotations instead (automatically validated)"
else
    check_pass "No deprecated TEST_MAP.md files found"
fi

# =============================================================================
# Check 5: TRA Usage Statistics
# =============================================================================
section "TRA Usage Statistics"

# Count Go tests with TRA
go_tra_count=$(grep -rh 'tra\.Require' . --include='*_test.go' 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
go_legacy_count=$(grep -rh 'tra\.RequireLegacy' . --include='*_test.go' 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
go_total=$(grep -rh '^func Test' . --include='*_test.go' 2>/dev/null | wc -l | tr -d ' \n' || echo "0")

if [[ "$go_total" -gt 0 ]]; then
    check_info "Go: $go_tra_count anchored, $go_legacy_count legacy, $go_total total test functions"

    if [[ "$go_tra_count" -eq 0 ]] && [[ "$go_legacy_count" -eq 0 ]]; then
        check_info "No Go tests have TRA calls yet - migration not started"
    elif [[ "$go_legacy_count" -gt "$go_tra_count" ]]; then
        check_warn "More legacy tests than anchored tests - migration in progress"
    fi
fi

# Count @tra: annotations in code
code_tra_count=$(grep -rh '@tra:' internal/ 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
if [[ "$code_tra_count" -gt 0 ]]; then
    check_info "Code annotations: $code_tra_count @tra: comments in production code"
else
    check_info "No @tra: annotations in production code yet"
fi

# =============================================================================
# Check 6: Namespace Coverage
# =============================================================================
section "TRA Namespace Coverage"

# Collect all unique TRA anchors
all_anchors=$(
    grep -rohE '(Domain\.(Invariant|Policy)|UseCase|Port|Adapter|Contract)\.[A-Za-z0-9_.]+' \
        . --include='*_test.go' 2>/dev/null | sort -u || true
)

if [[ -n "$all_anchors" ]]; then
    domain_inv=$(echo "$all_anchors" | grep -c '^Domain\.Invariant\.' || echo "0")
    domain_pol=$(echo "$all_anchors" | grep -c '^Domain\.Policy\.' || echo "0")
    usecase=$(echo "$all_anchors" | grep -c '^UseCase\.' || echo "0")
    port=$(echo "$all_anchors" | grep -c '^Port\.' || echo "0")
    adapter=$(echo "$all_anchors" | grep -c '^Adapter\.' || echo "0")
    contract=$(echo "$all_anchors" | grep -c '^Contract\.' || echo "0")

    check_info "Domain.Invariant: $domain_inv | Domain.Policy: $domain_pol | UseCase: $usecase"
    check_info "Port: $port | Adapter: $adapter | Contract: $contract"
else
    check_info "No TRA anchors found yet"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}=======================================================================${NC}"

if [[ ${#errors[@]} -gt 0 ]]; then
    echo -e "${RED}${BOLD}CRITICAL ISSUES (${#errors[@]}):${NC}"
    for e in "${errors[@]}"; do
        echo -e "  ${RED}*${NC} $e"
    done
fi

if [[ ${#warnings[@]} -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}${BOLD}WARNINGS (${#warnings[@]}):${NC}"
    for w in "${warnings[@]}"; do
        echo -e "  ${YELLOW}*${NC} $w"
    done
fi

echo ""
if [[ ${#errors[@]} -gt 0 ]]; then
    echo -e "${RED}${BOLD}TRA adoption incomplete - address critical issues above${NC}"
    exit 1
elif [[ ${#warnings[@]} -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}TRA adoption in progress - consider addressing warnings${NC}"
    exit 2
else
    echo -e "${GREEN}${BOLD}TRA adoption complete - all checks passed${NC}"
    exit 0
fi

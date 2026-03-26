#!/bin/bash
# =============================================================
#  ReconStorm — Shared Utilities
#  Source this in modules: source lib/utils.sh
# =============================================================

# Wait for background jobs, report failures
wait_jobs() {
    local failed=0
    for pid in "$@"; do
        if ! wait "$pid"; then
            log_warn "Background job (PID $pid) exited non-zero"
            failed=$((failed + 1))
        fi
    done
    return $failed
}

# Run a command with timeout, suppress errors gracefully
run_safe() {
    local timeout="${1}"; shift
    if command -v timeout &>/dev/null; then
        timeout "$timeout" "$@" || true
    else
        "$@" || true
    fi
}

# Check if file exists and is non-empty
has_results() {
    [[ -s "$1" ]]
}

# Deduplicate a file in-place
dedup_file() {
    local f="$1"
    [[ -f "$f" ]] && sort -u "$f" -o "$f"
}

# Merge multiple files, deduplicate, write to output
merge_files() {
    local output="$1"; shift
    cat "$@" 2>/dev/null | sort -u > "$output"
}

# Count lines in a file (0 if not exists)
count_lines() {
    [[ -f "$1" ]] && wc -l < "$1" || echo 0
}

# Sanitize a URL/host string for use as a filename
safe_filename() {
    echo "$1" | sed 's|https\?://||g' | sed 's/[^a-zA-Z0-9._-]/_/g'
}

# Check if tool is installed
require_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_warn "Tool '$1' not found — skipping this step"
        return 1
    fi
    return 0
}

# Build proxy flags for tools that support it
proxy_flag_curl()    { [[ -n "${PROXY:-}" ]] && echo "--proxy $PROXY" || echo ""; }
proxy_flag_sqlmap()  { [[ -n "${PROXY:-}" ]] && echo "--proxy=$PROXY" || echo ""; }
proxy_flag_nuclei()  { [[ -n "${PROXY:-}" ]] && echo "-proxy $PROXY"  || echo ""; }

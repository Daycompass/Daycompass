#!/bin/sh
# Verifies the "screenward-app-token" rule in .gitleaks.toml.
#
# Run it manually, or let CI run it:
#   .githooks/tests/gitleaks-rules.sh
#
# Every candidate token is generated from fresh randomness at runtime and
# piped through `gitleaks stdin`. Nothing token-shaped is ever written to
# a file, so this test needs no .gitleaks.toml allowlist entry of its own
# and cannot itself become a committed secret.
#
# What is pinned here:
#   * the widened prefix: sw<letter>_ must be caught for every letter
#     a-z, not just the handful that happen to be in use today
#   * the body length: exactly 43 base64url characters
#   * that the rule survives the `[extend] useDefault` merge
#   * the known, intended over-match on a 44-character body (the regex
#     is unanchored, so its first 43 characters still match)

set -eu

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks-rules: gitleaks is not installed or not on PATH." >&2
    echo "gitleaks-rules: see CONTRIBUTING.md, then retry." >&2
    exit 1
fi

repo_root=$(git rev-parse --show-toplevel)
config="${repo_root}/.gitleaks.toml"
rule="screenward-app-token"
failures=0

# 32 bytes of randomness as base64url without padding, which is always
# exactly 43 characters.
random_body() {
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

# Echoes "detected" or "clean" for one candidate string. Only our own
# rule is enabled, so a result can never come from one of gitleaks'
# default rules instead.
scan_with_rule_only() {
    if printf '%s\n' "$1" | gitleaks stdin \
        --no-banner --redact --log-level error \
        --config "${config}" --enable-rule "${rule}" >/dev/null 2>&1
    then
        echo clean
    else
        echo detected
    fi
}

# Same, but with the full merged ruleset, to prove the rule is still
# live after `[extend] useDefault = true`.
scan_full_config() {
    if printf '%s\n' "$1" | gitleaks stdin \
        --no-banner --redact --log-level error \
        --config "${config}" >/dev/null 2>&1
    then
        echo clean
    else
        echo detected
    fi
}

expect() {
    want=$1
    label=$2
    candidate=$3
    got=$(scan_with_rule_only "${candidate}")
    if [ "${got}" = "${want}" ]; then
        echo "ok       ${label}"
    else
        echo "FAILED   ${label}: expected ${want}, got ${got}" >&2
        failures=$((failures + 1))
    fi
}

echo "gitleaks-rules: checking every sw<letter>_ prefix is detected"
for letter in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
    expect detected "prefix sw${letter}_" "token: sw${letter}_$(random_body)"
done

echo "gitleaks-rules: checking shapes that must NOT be detected"
# 42 characters: one short of a real token body.
short=$(random_body | cut -c1-42)
expect clean "42-character body" "token: sws_${short}"
# The prefix letter must be lowercase.
expect clean "uppercase prefix letter" "token: swS_$(random_body)"
# The prefix must be a letter, not a digit.
expect clean "digit in prefix" "token: sw1_$(random_body)"
# A character outside the base64url alphabet breaks the run into two
# pieces, neither of them 43 characters long.
body=$(random_body)
expect clean "body interrupted by a dot" \
    "token: sws_$(printf '%s' "${body}" | cut -c1-20).$(printf '%s' "${body}" | cut -c22-43)"

echo "gitleaks-rules: checking intended over-matches"
# 44 characters. The regex is unanchored on purpose, so the first 43 of
# them match. Over-matching is the right failure direction for a secret
# scanner, so this is asserted rather than tolerated.
expect detected "44-character body" "token: sws_$(random_body)Z"
expect detected "token embedded mid-line" \
    "Authorization: Bearer sws_$(random_body) (trailing text)"

echo "gitleaks-rules: checking the rule survives the useDefault merge"
got=$(scan_full_config "token: swb_$(random_body)")
if [ "${got}" = "detected" ]; then
    echo "ok       full config still detects swb_"
else
    echo "FAILED   full config: expected detected, got ${got}" >&2
    failures=$((failures + 1))
fi

if [ "${failures}" -ne 0 ]; then
    echo "gitleaks-rules: ${failures} check(s) failed." >&2
    exit 1
fi

echo "gitleaks-rules: all checks passed."

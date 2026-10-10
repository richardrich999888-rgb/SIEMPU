#!/usr/bin/env bash
# Claims gate: fails if any tracked text file asserts FIPS validation or SAG grading/approval
# without a negation on the same line.
#
#   Assertions matched (case-insensitive, word-bounded): "FIPS validated", "FIPS-validated",
#   "SAG graded", "SAG-graded", "SAG approved", "SAG-approved".
#   A line passes if it also contains a negation (not, no, never, without, nor, cannot, n't,
#   avoid, unless, pending, ...). Remaining lines must be listed in scripts/check-claims.allow
#   (path, exact fragment, justification); every allow entry must still match, or the gate fails.
#
# Usage: scripts/check-claims.sh [repository-root]     Exit: 0 clean, 1 violation, 2 usage error.
set -euo pipefail

root="${1:-$(git rev-parse --show-toplevel)}"
cd "$root"
allow_file="scripts/check-claims.allow"

claim='(^|[^[:alnum:]_])(fips[- ]validated|sag[- ]graded|sag[- ]approved)([^[:alnum:]_]|$)'
negation='(^|[^[:alnum:]_])(not|no|never|none|without|nor|neither|cannot|unless|avoid|pending|outstanding|forbidden|prohibited|disallowed|do not|does not|is not|are not)([^[:alnum:]_]|$)|n'"'"'t([^[:alnum:]_]|$)'

# Tracked text files. Excluded, because they define or deliberately quote the patterns: this
# script and its allow list, its tests (tests/check-claims.test.mjs), the claims-audit tool and
# its tests (scripts/claims-audit.mjs, tests/claims-audit.test.mjs) and the generated audit
# (docs/assurance/claims-audit.md, which quotes every audited line verbatim).
mapfile -t hits < <(git grep -n -I -i -E "$claim" -- \
  '*.md' '*.mjs' '*.js' '*.ts' '*.rs' '*.yaml' '*.yml' '*.json' '*.html' '*.txt' '*.sh' \
  ':!scripts/check-claims.sh' ':!scripts/check-claims.allow' ':!docs/assurance/claims-audit.md' \
  ':!tests/check-claims.test.mjs' ':!scripts/claims-audit.mjs' ':!tests/claims-audit.test.mjs' || true)

# Allow-list entries: path<TAB>fragment<TAB>justification; '#' comments and blank lines skipped.
declare -a allow_path=() allow_frag=() allow_used=()
if [[ -f "$allow_file" ]]; then
  while IFS=$'\t' read -r path frag reason; do
    [[ -z "${path// }" || "$path" == \#* ]] && continue
    if [[ -z "${frag:-}" || -z "${reason:-}" ]]; then
      echo "check-claims: malformed allow entry (need path, fragment, justification): $path" >&2
      exit 2
    fi
    allow_path+=("$path"); allow_frag+=("$frag"); allow_used+=(0)
  done < "$allow_file"
fi

violations=0
for hit in "${hits[@]}"; do
  file="${hit%%:*}"; rest="${hit#*:}"; line="${rest%%:*}"; text="${rest#*:}"
  lower="$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]')"
  if printf '%s' "$lower" | grep -q -E "$negation"; then continue; fi
  allowed=0
  for i in "${!allow_path[@]}"; do
    if [[ "$file" == "${allow_path[$i]}" && "$text" == *"${allow_frag[$i]}"* ]]; then
      allowed=1; allow_used[$i]=1
    fi
  done
  if (( allowed == 0 )); then
    echo "check-claims: unqualified assurance claim at $file:$line: ${text:0:200}" >&2
    violations=$((violations + 1))
  fi
done

for i in "${!allow_path[@]}"; do
  if (( allow_used[$i] == 0 )); then
    echo "check-claims: stale allow entry (no longer matches): ${allow_path[$i]} :: ${allow_frag[$i]}" >&2
    violations=$((violations + 1))
  fi
done

if (( violations > 0 )); then
  echo "check-claims: FAIL ($violations)" >&2
  exit 1
fi
echo "check-claims: PASS (${#hits[@]} matching lines, all negated or allow-listed)"

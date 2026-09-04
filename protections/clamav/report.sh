#!/bin/sh
# wormbench clamav protection reporter.
# Parses clamscan text output ("path: SIGNATURE FOUND") and POSTs each hit to
# the judge as a malicious ProtectionEvent (SPEC §5.3).
#
# Note: clamscan has no --json-l output (SPEC deviation, documented); we parse
# the text format instead. busybox wget supplies --post-data.
#
# Usage: report.sh /tmp/scan.txt

SCAN_FILE="${1:-/tmp/scan.txt}"
[ -f "$SCAN_FILE" ] || exit 0

grep ' FOUND$' "$SCAN_FILE" 2>/dev/null | while IFS= read -r line; do
    # "/scan/<run>/<target>/<file>: Sig FOUND" -> judge-visible object path
    # (the volume root maps to /scan here and /shared in the worm)
    path=$(printf '%s' "$line" | sed 's/: [^:]* FOUND$//; s#^/scan/#/shared/#')
    sig=$(printf '%s' "$line" | sed -n 's/^.*: \(.*\) FOUND$/\1/p')
    ts=$(date +%s)
    json="{\"t\": $ts, \"run\": \"$RUN_ID\", \"verdict\": \"malicious\", \"confidence\": 0.9, \"technique\": \"T1105\", \"object\": \"$path\", \"note\": \"$sig found\", \"vendor\": \"clamav\"}"
    wget -q -O /dev/null \
        --header="X-Judge-Token: $JUDGE_TOKEN" \
        --header="Content-Type: application/json" \
        --post-data="$json" \
        "$JUDGE_URL/events" || true
done
exit 0

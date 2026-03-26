```
rollbackchain "blockheight"

Rolls back the blockchain to the height indicated.

Arguments:
1. blockheight (int, required) the height that you want to roll the
                               chain back to (only maxiumum rollback of
                               100 blocks allowed)
2. override    (boolean, optional, default=false) rollback more than
                               the allowed default limit of 100 blocks)

Result:

Examples:
> nexa-cli rollbackchain 501245
> nexa-cli rollbackchain 495623 true
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "rollbackchain", "params": ["blockheight"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/
```

```
gettailstorminfo

Returns details on the active state of the Tailstorm subblock pool.

Result:
{
  "chaintip": x,                (numeric) Current summary block tip hash
  "dagtip": x                   (numeric) Current dag tip hash
  "total": x,                   (numeric) Current total subblock count in the forest
  "unlinked_subblocks": x       (numeric) Number of subblocks not linked in the forest
  "unlinked_summaryblocks": x   (numeric) Number of subblocks not linked in the forest
  "uncles": x                   (numeric) Number of uncle blocks in the best dag (active dag)
  "bestdag": x                  (numeric) Number of subblocks in the best dag (active dag)
}

Examples:
> nexa-cli gettailstorminfo
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettailstorminfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/
```

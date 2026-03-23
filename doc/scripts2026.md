
# 2026 (Fork 2) Scripting Changes


## Bignum operations

Bignum operations argument order is now aligned with Integer order.

## OP_PARSE Canonical Authority

The authority bits will now be pushed to the stack **as an 8 byte bitfield**, not a script number.  Since scripting bit operations (AND, OR, XOR) operate on bitfields not numbers anyway this makes it much easier to mask them.

## OP_JUMP

Due to a bug, OP_JUMP was active inside not-taken "if" or "else" statements.  This is fixed.

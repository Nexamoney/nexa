# Nexa Signature Hash Type

A Nexa signature consists of a Schnorr signature and additional bytes called the signature hash type (sighashtype).  As with all secure Schnorr signature schemes, the signature does not sign the message bytes (in this case the transaction) directly; it signs a cryptographic hash of some subset of the transaction data.  The "signature hash type" identifies what data within the transaction is passed to which cryptographic hash algorithm to generate the actual data signed by the Schnorr signature algorithm.

## Retargetable Signature Hash Types

A "retargetable" signature hash type can be changed by a third party.  This allows transactions to be combined into a single transaction without the inputs needing to be re-signed.  For example, using the Retargetable Range output type, a transaction may contain 1 input and 3 outputs.  That transaction may be combined with another transaction that already has 5 outputs by "retargeting" the sighash from outputs 0 to 2, to outputs 5 to 7.  Since the Retargetable Range signature is agnostic to the position of the outputs in the transaction (it only cares that that they exist), this new transaction is valid without needing to be re-signed.  On the input side, the THISIN sig hash type is implicitly retargetable.

This is a powerful feature that allows a third party to combine partial transaction offers that complement each other.
Additionally, it makes it much easier for contract systems (both the smart contract and the facilitator) to interact within a single transaction.  This is how contracts "call" each other in Nexa.

**Notes about contracts**:
Note that when combined with contracts, it is important that the relevant contracts also not hard-code output indexes into their operation.  This is easily avoided by coding the contract to accept a satisfier script parameter which is the starting output index.

**Security Risks**:
Any transaction created using this sighash type can be malleated (modified structurally but not semantically) by a third party by moving outputs.  Therefore it is possible for 3rd parties to create both id and/or idem doublespends.  Applications MUST verify blockchain state change by tracking the actual state change (that is, track the confirmation of inputs being spent, or outputs being created), not the transaction id.  However, this is not onerous since it is normal for any partial transaction since the creator does not know the final transaction contents when creating it.

Even though the output positions can be changed within the contract, they still cover the contents of the specific outputs.  Therefore the spend of an input can still be predicated on the creation of some outputs.

However, let us propose that Alice wants to acquire 10 of asset A.  But typically only 1 is sold at a time.  She therefore creates 10 separate partial transaction offers, signed with RetargetableRange, all spending separate inputs of 100000 NEXA and paying 1 of A to address ADDR.  Thererfore, they all have the exact same output "pay 1 of A to address ADDR".

Mallory inputs all 10 of these offers into a single transaction, and points them all to the SAME single output.  He is able to effectively get 9 inputs of NEXA for free!

This attack is defeated in many ways: if the outputs are different in any way: pay to different addresses, contain an OP_RETURN, etc.  It also will generally be defeated if Alice needs to create a change output, since she'll pay different amounts of change to herself.

Wallet authors using RetargetableRange need to be aware of this attack to ensure that wallets do not reuse outputs.

A third party cannot ensure the atomicity of combined transactions.  Other third parties can analyze the transaction and split it back into its partials.  Therefore it is essential that all participants sign ALL relevant outputs.  For example, if some entity C provides an input on behalf of the combination of A and B, then C must sign the entire transaction to make sure that their input is not replayable outside of A and B's contribution.


# Identifying Sighashtype Bytes

A Schnorr signature is 64 bytes.  The sighashtype bytes therefore start at zero-based byte 64.  Parsing the sighashtype determines how many bytes it comprises.

Consensus validating implementations MUST enforce that the full signature contains no additional bytes.  Non-validating implementations MAY choose to be tolerant of extra bytes, as this may make them robust in the face of consensus upgrades (that may add additional data to the signature).

# Empty SigHash

Since a Schnorr signature must be 64 bytes, it is therefore possible to determine that no sighash bytes are included in a signature.  In this case, the sighash bytes are the single byte 0.

Most normal payments use a sighash of 0 (sign all inputs and outputs), so this will save a byte in this common signature format.

# Sighashtype Flag Byte

The only cryptographic hashing algorithm defined is the double SHA256, so no bits are used to specify the algorithm at this time.

The first byte of the sighash is the sighashtype flag byte.  It is divided into 2 parts, the upper (most significant) 4 bits, and the lower (least significant) 4 bits.  The upper bits define what data within the inputs used, and the lower bits determine the data in the outputs.  If additional bytes are needed, the input bytes come first, then the outputs.

## Input type flags

0: All inputs
 *no inputs can be added, removed, or modified*
 
1: First N inputs (where N is specified as 1 subsequent byte).
*Allows additional inputs to be added, so the transaction can be extended by other parties.  Note that if you want to sign 256 inputs, choose type 0*

2: This input
*Prevents signature prevout reuse by signing this input (and its outpoint hash).  Other inputs can be added, removed, or modified*

1,0: No inputs
*Note that the special case of no inputs is implementable via type 2 where N=0.  This signature can potentially be maliciously reused to sign other prevouts constrained by the same pubkey!!*

## Output type flags

0: All outputs
 *no inputs can be added, removed, or modified*

1: First N outputs (index N is specified as 1 subsequent byte)
*Allows additional outputs to be added, so the transaction can be extended by other parties.  Note that if you want to sign 256 outputs, choose type 0*
 
2: Two outputs N, M (index N and M are specified as 2 subsequent byte. To sign just 1 output, pass the same number twice)
*Note that this is an extremely common use case -- receiving something and paying yourself change.  All other outputs can be removed or modified, and additional outputs can be included*


1, 0: No outputs
*Note that the special case of no outputs is implementable via type 2 where N=0.  This is very dangerous -- whoever has this transaction can rewrite the outputs to take all of the money brought into the transaction, unless the outputs are secured by some other input, and that input is signed.*

3: Retargetable Range
Takes 2 parameters, start and subsequent count.  Start is the first output included, count denotes the number of *subsequent* outputs.  So (0,0) and (3,0) include output 0 and 3 respectively.  Formally, outputs [start, start+count] are used (inclusive).  This formulation allows us to specify all outputs, using (0,255).  But since the start output is always used, it is not possible to use this sig hash type to specify no outputs.  That is possible using FIRSTN(0).

If start is not within the vout size, this signature is invalid (regardless of count) (REQ1).
If the specified range extends beyond the outputs available in the transaction, the signature is invalid (REQ2).

**This sighashtype does NOT include itself in the sighash!** (REQ3).  This means that a third party can change these values after the transaction is issued.  Partial transactions signed with Retargetable Range can therefore be combined by a 3rd party (without requiring resigning), even if the outputs of the original partial transactions overlap.  Using this as an output sighashtype means that the input sighashtype is not signed.




# HIP Protocol v1 — Flow Diagrams

## Flow 1: Identity Handshake
1. Sender -> Verifier: HipHello
2. Verifier -> Sender: HipChallenge
3. Sender -> Verifier: HipProof
4. Verifier validates proof -> returns success/failure + optional HipTrustReceipt

## Flow 2: Protected HTTP Request
1. Sender computes payload hash + envelope signature
2. Sender sends HTTP request + HIP headers/envelope mapping
3. Receiver validates:
   - version
   - required fields
   - timestamp skew
   - nonce replay
   - signature
   - revocation
4. Receiver applies policy/reputation
5. Receiver returns app response + optional trust receipt

## Flow 3: Protected Message Interaction
1. Sender wraps message into HipMessageEnvelope
2. Receiver validates same controls as HTTP flow
3. Receiver issues decision + trust receipt

## Flow 4: Trust Receipt Verification
1. Verifier/third-party receives receipt
2. Validate schema + required fields + version
3. Canonicalize receipt payload
4. Verify receipt signature with verifier key
5. Return valid/invalid

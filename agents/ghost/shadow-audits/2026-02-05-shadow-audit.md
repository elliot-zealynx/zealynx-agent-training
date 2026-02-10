# Ghost 👻 - Shadow Audit Report - 2026-02-05

## Target: CVE-2025-55182 - React Server Components RCE ("React2Shell")
**Framework:** React v19.1.0 (react-server-dom-webpack)
**CVE:** CVE-2025-55182 (CVSS 10.0 Critical)
**Original Researcher:** Lachlan Davidson (lachlan2k)
**Published:** December 3, 2025
**Approach:** Blind source code audit -> compare with published findings
**Duration:** ~55 minutes

---

## Phase 1: Blind Audit (Before Reading Writeups)

### Starting Knowledge
- CVE ID, severity (CVSS 10.0), and that it's about React Server Components
- Affects react-server-dom-webpack/parcel versions 19.0.0-19.2.0
- Involves deserialization of HTTP requests to Server Function endpoints
- Search snippets mentioned `hasOwnProperty` on untrusted objects
- DID NOT KNOW: Exact exploit mechanism, chain, gadgets, or bypass techniques

### Files Analyzed
1. `react-server/src/ReactFlightReplyServer.js` - Core server-side deserialization (full read)
2. `react-server/src/ReactFlightActionServer.js` - Server action handling (full read)
3. `react-server/src/ReactFlightServer.js` - Main Flight server serialization (partial read, ~800 lines)
4. `react-server-dom-webpack/src/server/ReactFlightDOMServerNode.js` - Entry point (full read)
5. `react-server-dom-webpack/src/client/ReactFlightClientConfigBundlerWebpack.js` - Server ref resolution (full read)
6. `react-client/src/ReactFlightReplyClient.js` - Client serialization (partial read)
7. `react-client/src/ReactFlightClient.js` - Client-side Flight processing (partial read)
8. `shared/hasOwnProperty.js` - Safe hasOwnProperty reference (verified)
9. `shared/ReactSerializationErrors.js` - Error handling utilities (full read)

### Blind Findings

#### B1: Prototype Pollution via `__proto__` Key in reviveModel (Medium/High)
**Location:** ReactFlightReplyServer.js, reviveModel function
- `for (const key in value)` iterates over all enumerable properties
- `value[key] = newValue` where key is `"__proto__"` triggers the `__proto__` setter
- Changes the prototype of the deserialized object
- When combined with downstream code that calls methods on polluted objects, could be dangerous
- **Status:** PARTIALLY RELATED - Some PoCs use `__proto__` access but the minimum viable exploit does NOT require it

#### B2: Unsafe `.then` Property Check in renderModelDestructive (Low-Medium)
**Location:** ReactFlightServer.js, renderModelDestructive function
- `typeof value.then === 'function'` is a duck-typing check on potentially controlled objects
- Could affect control flow if attacker controls objects with `.then` properties
- **Status:** TANGENTIALLY RELATED - the exploit DOES weaponize `.then` but via a completely different mechanism

#### B3: Arbitrary Server Function Invocation via $F Handler (Medium)
**Location:** ReactFlightReplyServer.js, parseModelString $F handler
- Attacker can craft FormData with $F references pointing to any registered server function
- Combined with `bound` arguments, could call unintended server functions
- **Status:** VALID CONCERN but not the actual exploit vector

#### B4: Missing Input Validation on FormData Fields (Low)
**Location:** ReactFlightDOMServerNode.js, decodeReply/decodeReplyFromBusboy
- No validation of field names/values beyond prefix checking
- **Status:** TRUE but not the vulnerability

#### B5: Sensitive Key Processing in reviveModel (Medium)
**Location:** ReactFlightReplyServer.js, reviveModel
- `constructor`, `toString`, `valueOf` can all be set on deserialized objects
- Combined with B1, could create objects with unexpected behaviors
- **Status:** SOMEWHAT RELATED - the actual exploit does traverse `.constructor` but via chunk self-references, not direct key setting

---

## Phase 2: Published Findings Comparison

### The Actual Vulnerability

The exploit is a **4-stage gadget chain** that leverages React's internal deserialization primitives:

**Stage 1: Self-Reference Loop via $@**
- The `$@` prefix in `parseModelString` returns the RAW chunk object (not its resolved value)
- `$@0` returns the actual Chunk instance with internal properties: `status`, `value`, `reason`, `_response`, `then`
- By creating chunk 1 = `"$@0"` and chunk 0 referencing chunk 1, attacker gets access to internal objects

**Stage 2: `.then` Hijacking**
- Chunk objects have a `.then` method (they subclass Promise.prototype)
- JavaScript's `await` mechanism automatically calls `.then()` on objects that have it
- By setting `then` to point to `Chunk.prototype.then`, the attacker triggers `initializeModelChunk()`

**Stage 3: Resolved Model Injection**
- Setting `status: "resolved_model"` on the crafted chunk triggers JSON.parse on `.value`
- React trusts the status field and parses the attacker-controlled content

**Stage 4: Blob Handler Code Execution Gadget**
- `$B` prefix triggers: `response._formData.get(response._prefix + obj)`
- By pointing `_formData.get` to the `Function` constructor (via `$1:then:constructor`)
- And setting `_prefix` to malicious JavaScript code
- The call becomes `Function("malicious_code//chunk_id")()` = RCE!

### Minimum Viable Exploit (no __proto__ needed!)
```
{
  0: {
    status: "resolved_model",
    reason: -1,
    _response: {
      _prefix: "console.log('RCE')//",
      _formData: { get: "$1:then:constructor" },
    },
    then: "$1:then",
    value: '{"then":"$B"}',
  },
  1: "$@0",
}
```

### Key Details
- **Pre-authentication:** Exploitation occurs during deserialization, BEFORE the server action is validated
- **No credentials needed:** Just send a malicious HTTP POST with any `Next-Action` header value
- **Full Node.js context:** Access to process, child_process, filesystem, environment variables
- **In the compiled output:** `value.hasOwnProperty(i)` instead of safe `hasOwnProperty.call(value, key)`

---

## Phase 3: Scoring

### True Positives: 0
None of my findings identified the actual exploit chain.

### Partial/Related Findings: 3
- B1 (__proto__ processing) - Used in some PoCs but not minimum viable exploit
- B2 (.then property check) - Related concept but wrong mechanism
- B5 (sensitive key processing) - Related to constructor traversal concept

### False Negatives: 6 (Critical Misses)
1. **$@ returning raw chunk objects** - I READ the `$@` handler code and SAW it returns `getChunk(response, id)` but DID NOT recognize this as returning internal React objects with exploitable properties
2. **Self-reference loop between chunks** - Never considered circular references as an attack vector
3. **`.then` on Chunk objects as automatic trigger** - Chunk subclasses Promise.prototype, giving it `.then`; JavaScript's await calls it automatically
4. **`initializeModelChunk` as injectable via status field** - Didn't think about faking chunk status
5. **$B blob handler as code execution gadget** - Read the $B handler but didn't see the `_formData.get()` call as weaponizable
6. **Function constructor reachable via `:constructor` chain** - Didn't think about traversing from `.then` (a function) to its `.constructor` (Function itself)

### Performance Scores
- **Precision:** N/A (0 true positives for the actual CVE)
- **Recall:** 0% for the core exploit chain
- **General security awareness:** ~40% (identified related concerns but missed the critical chain)

---

## Phase 4: Lessons Learned

### Critical Gaps Identified

1. **I didn't think about framework internal objects as gadgets**
   - When `$@` returned a raw Chunk object, I should have asked: "What properties does this object have? Can they be weaponized?"
   - PATTERN: Any deserialization that exposes internal/framework objects is a potential gadget source

2. **I didn't consider self-referential data structures**
   - Circular references in deserialization can expose internal state
   - PATTERN: If a deserializer supports references between chunks, check if self-references or circular references expose unintended properties

3. **I didn't follow the JavaScript prototype chain as an exploit path**
   - From any function, `.constructor` gives you `Function`
   - `Function("code")()` = arbitrary code execution
   - PATTERN: Any path that gives attacker a function reference is 1 step from RCE in JavaScript

4. **I didn't check compiled output vs source**
   - Source used safe `hasOwnProperty.call(value, key)`
   - Compiled output may have used `value.hasOwnProperty(i)`
   - PATTERN: Always verify the actual runtime code, not just source

5. **I focused on traditional vuln patterns instead of gadget chains**
   - Was looking for prototype pollution, SSRF, injection patterns
   - Missed the creative chaining of benign features into RCE
   - PATTERN: Think like a deserialization exploit researcher, not just a web pentester

### New Methodology Rules
- **Rule: "Trace every type handler to its raw return value"** - For every special prefix/type in a deserializer, document exactly what object type it returns and all accessible properties
- **Rule: "Check for circular reference support"** - If references between chunks/objects exist, test self-references
- **Rule: "Map all paths to Function constructor"** - Any function reference -> .constructor -> Function -> RCE
- **Rule: "Always check compiled output"** - Build artifacts may differ from source code
- **Rule: "Apply Java deserialization thinking to JavaScript"** - Gadget chains in JS follow the same principle: chain benign features into dangerous outcomes

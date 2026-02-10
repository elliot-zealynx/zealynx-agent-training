# JavaScript Deserialization Gadget Methodology

## Pattern: Chaining benign framework features into RCE via JavaScript's dynamic dispatch

## Overview
JavaScript deserialization exploits follow the same principle as Java deserialization (ysoserial/gadget chains):
1. Find an "entry point" (attacker-controlled data enters the deserializer)
2. Find "gadgets" (framework features that can be chained together)
3. Find a "sink" (something that executes code: eval, Function, child_process)

## The JavaScript-Specific Advantage for Attackers
JavaScript's prototype chain and duck-typing make gadget chains easier:
- **Every function** has `.constructor` = `Function` (the universal code execution sink)
- **Every object** has `.__proto__` and `.constructor` for traversal
- **`typeof x.then === 'function'`** makes any object "thenable" (auto-called by await/Promise)
- **Dynamic property access** `obj[key]` is always available

## Gadget Discovery Checklist

### 1. Entry Points (Where attacker data enters)
- [ ] Custom deserializers (JSON.parse + revivers, custom protocols)
- [ ] FormData/multipart processing
- [ ] Query string parsing (qs, querystring with nested objects)
- [ ] URL routing parameters
- [ ] WebSocket message handling
- [ ] gRPC/Protocol Buffer deserialization

### 2. Internal Object Exposure
- [ ] Does any type handler return framework internal objects?
- [ ] Can references/pointers point to internal state?
- [ ] Can circular references be created?
- [ ] Are Proxy objects supported? (can intercept ANY property access)

### 3. Property Traversal Gadgets
- [ ] Colon-separated paths (e.g., `$1:__proto__:constructor`)
- [ ] Dot-separated paths (e.g., `a.b.c`)
- [ ] Bracket notation with controlled keys
- [ ] `for...in` loops over controlled objects
- [ ] Object.keys/Object.entries on controlled objects

### 4. Automatic Execution Triggers
- [ ] `.then()` (Promise/thenable check)
- [ ] `.toString()` (string coercion)
- [ ] `.valueOf()` (primitive coercion)
- [ ] `[Symbol.toPrimitive]()` (type conversion)
- [ ] `[Symbol.iterator]()` (for...of, spread)
- [ ] `.toJSON()` (JSON.stringify)

### 5. Code Execution Sinks
- [ ] `Function("code")()` - Via any function reference's `.constructor`
- [ ] `eval()` - Direct eval
- [ ] `require('child_process')` - Node.js command execution
- [ ] `process.mainModule.require()` - Alternative require access
- [ ] `import()` - Dynamic import
- [ ] `vm.runInThisContext()` - VM module execution
- [ ] `new Proxy()` - Can intercept method calls
- [ ] `Reflect.apply()` - Function invocation

## Common Chains
```
// Chain 1: Any function -> Function constructor -> RCE
anyFunction.constructor === Function
Function("return process.mainModule.require('child_process').execSync('id')")()

// Chain 2: Object -> constructor -> constructor -> RCE
anyObject.constructor.constructor === Function
(same as above)

// Chain 3: Array -> constructor -> constructor -> RCE
[].constructor.constructor === Function

// Chain 4: String -> constructor -> constructor -> RCE
"".constructor.constructor === Function

// Chain 5: Prototype chain traversal
anyObject.__proto__.constructor === Object
Object.constructor === Function
```

## Anti-Patterns to Flag During Audit
1. `value.hasOwnProperty(key)` instead of `Object.prototype.hasOwnProperty.call(value, key)`
2. `typeof value.then === 'function'` on untrusted data
3. `value[dynamicKey]` where dynamicKey is attacker-controlled
4. Returning internal/framework objects from type handlers
5. Supporting self-referencing data structures without cycle detection
6. Deserialization before authentication
7. Compiled output differing from source (minifiers may introduce unsafe patterns)

## Audit Approach for JavaScript Deserializers
1. **Map all type handlers** - Document what each prefix/type marker returns
2. **Check for reference support** - Can chunks/objects reference each other?
3. **Test self-references** - Can a chunk reference itself?
4. **Map property traversal** - Can paths like `a:b:c` traverse into internal objects?
5. **Find function references** - Any path to a function = 1 step from Function constructor
6. **Check compiled output** - Build the project and audit the actual runtime code
7. **Verify auth timing** - Does deserialization happen before or after authentication?

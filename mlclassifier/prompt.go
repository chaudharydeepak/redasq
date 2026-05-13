// Package mlclassifier sends a prompt to a local generative LLM (Qwen2.5
// 3B via llama-server) and parses a structured verdict — is this a
// sensitive disclosure, and what category.
//
// Runs in parallel with the regex inspector. Opinion-only in v1: the
// proxy persists the verdict to the prompt row but never gates the
// block/forward decision on it.
package mlclassifier

// SystemPrompt is sent as the system message on every classification call.
// The prompt deliberately distinguishes content disclosures (the message
// states specific secrets) from intent (the message asks ABOUT secrets) —
// the latter is the largest source of false positives at small model sizes.
const SystemPrompt = `You classify whether a user message contains a sensitive disclosure. A disclosure means the message states specific credentials, PII, internal hostnames, or private key locations. Questions ABOUT these topics, error messages, and general technical discussion are NOT disclosures. Respond with strict JSON only.`

// ResponseSchemaJSON constrains the model's output to the expected shape.
// llama-server enforces this via its OpenAI-compat json_schema response_format.
const ResponseSchemaJSON = `{
    "type": "object",
    "properties": {
        "sensitive": {"type": "boolean"},
        "category": {"type": "string", "enum": ["credentials","pii","infrastructure","key_material","none"]}
    },
    "required": ["sensitive","category"],
    "additionalProperties": false
}`

// DefaultModelFile is the GGUF filename redasq looks for under the model dir.
// Aligns with the benchmark result documented in REDASQ_KB.md.
const DefaultModelFile = "qwen2.5-3b-instruct-q4_k_m.gguf"

// DefaultPort is the loopback port llama-server binds when redasq manages it.
const DefaultPort = 8765

// DefaultBinary is the name redasq looks up in PATH if --ml-binary is unset.
const DefaultBinary = "llama-server"

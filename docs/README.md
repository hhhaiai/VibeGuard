## Rule System (Recommended Priority)

1) **Keyword list**: exact substring matching (good for names, project codenames, key fragments, etc.).
2) **Rule lists (`.vgrules`)**: line-based `keyword/regex` rules (good for common patterns like email/phone/IDs; supports local upload and subscriptions).
3) **NLP entity recognition**: detects entities like `PERSON / ORG / LOCATION` (built-in heuristics; ONNX requires a runtime and model files).

Admin UI entry:

- `http://127.0.0.1:28657/manager/`
- Rule lists: `#/rule_lists`
- Keyword list: `#/keywords`
- NLP: `#/nlp`

---

## Rule Lists (`.vgrules`)

Rule files are parsed line by line. Blank lines and comment lines are ignored (starting with `#`, `//`, `;`, or `!`).

- `keyword <CATEGORY> <TEXT...>`: exact string match (case-sensitive)
- `regex   <CATEGORY> <RE2_PATTERN...>`: Go RE2 regex match  
  If the regex contains capture groups, VibeGuard replaces the **first capture group** range first (safer, avoids redacting parameter names together with values).

Sample file: `docs/rule_lists.sample.vgrules`

### Subscriptions & Verification (Recommended)

Rule list subscriptions support the following verification methods (configure at least one):

- **ed25519 signature verification**: `sig_url + pubkey`
- **Pinned version verification**: `sha256`

Subscription cache directory: `~/.vibeguard/rule_lists/subscriptions/`

---

## NLP (Generic Entity Recognition)

NLP detects entities and replaces them with placeholders. It is best for content that is hard to enumerate as rules (e.g., personal names / organizations / locations).
For common PII (email/phone/card numbers, etc.), `.vgrules` is usually a better fit.

### Engines

- `heuristic`: built-in heuristics (more conservative, zero external dependencies)
- `onnx`: ONNX inference (“real NLP”; requires a runtime and model files)

### ONNX Model Requirements (Important)

The current implementation follows **BERT/DistilBERT + token-classification (NER) + WordPiece**, so you need:

- `model.onnx` (output shape is typically like `[1, seq_len, num_labels]`)
- `vocab.txt` (WordPiece vocabulary)
- `labels.txt` (one label per line, aligned with `num_labels`)
- `vibeguard_ner.json` (configure input/output names, `max_length`, `do_lower_case`, `min_score`, etc.)

Default lookup paths (when `model_path` is empty):

- `~/.vibeguard/models/ner`
- `./models/ner`

Environment variables:

- `VIBEGUARD_ONNX_MODEL_PATH`: single model directory (no language routing)
- `VIBEGUARD_ONNX_MODEL_PATH_EN` / `VIBEGUARD_ONNX_MODEL_PATH_ZH`: language-routed model directories
- `VIBEGUARD_ONNXRUNTIME_LIB`: manually specify the onnxruntime shared library path

### Multilingual + Lightweight Tips

- Prefer quantized models (e.g., int8). Keep models in user directories / mounted volumes instead of committing them into the repo or baking them into images.
- For a single multilingual model: disable `route_by_lang` and set `max_loaded_models: 1`.
- A relatively lightweight, multilingual option: `Xenova/distilbert-base-multilingual-cased-ner-hrl` (often available with ONNX + quantized variants).

---

## Development & Debugging

### Key Entry Points (Config → Effective Behavior)

1. Config: `internal/config/NLPConfig` (YAML: `patterns.nlp.*`) and `patterns.rule_lists`
2. Admin API: `/manager/api/nlp` and `/manager/api/rule_lists` (see `internal/admin/`)
3. Proxy wiring: `internal/proxy/proxy.go` → `applyConfig()` merges keyword list + rule lists + NLP
4. Redaction pipeline: `internal/pii_next/pipeline.Pipeline` (greedy selection by priority to avoid overlapping fragment replacements)

### Common Commands

```bash
go test ./...
go test ./internal/pii_next/...

# Build with ONNX support (requires local onnxruntime dynamic library and CGO)
CGO_ENABLED=1 go build -tags onnx -o vibeguard ./cmd/vibeguard
```

# Discord Anti-Scam Bot — Design Document

**Purpose:** design an offline-first Discord moderation bot that detects and blocks scams in text and images. It uses on-prem / self-hosted LLMs and OCR to analyze messages and images, flags/deletes confirmed scams, and surfaces borderline cases to moderators.

**Audience:** developers, ops, and moderators who will implement, host, or operate the bot.

---

# 1 — Goals & non-goals

**Goals**

* Detect scam content in messages (text) and images (text embedded in images like screenshots).
* Operate with offline LLM models (self-hosted, quantized where needed) for inference — no cloud inference required.
* Provide explainability: a concise reason + confidence score for each detection to help moderators.
* Integrate with Discord via a bot user; enforce by deleting messages, flagging images, and notifying moderators.
* High throughput and low latency for real-time message scanning (typical guild scale: up to millions of messages/day across many servers).
* Configurable thresholds and policies per guild.

**Non-goals**

* Replace human moderators — the system should augment them.
* Perform sophisticated image moderation unrelated to scams (nudity/hate/etc) — though hooking into existing classifiers later is possible.
* Guarantee 100% accuracy — instead, aim for low false-negative on high-risk scam classes and low false-positive for high-confidence matches.

---

# 2 — Threat model & detection targets

**Threats we aim to catch**

* Phishing links (fake banking, crypto, login pages).
* “Giveaway” / impersonation scams (pretend mods, fake admins).
* Payment scams (Venmo/CashApp/ApplePay requests that are fraudulent).
* Investment scams (pump-and-dump crypto schemes).
* Social engineering attempts (asking for codes, remote access).
* Scam content embedded in images (screenshots of payment instructions, scammy Discord embeds, or image text).

**Adversary behavior assumed**

* Use of obfuscation: homograph, leetspeak, image screenshots to bypass text filters.
* Short-lived accounts and rotated links.
* Attempts to mimic legitimate community messages.

---

# 3 — High-level architecture

```
Discord Gateway <- Bot (message webhook) -> Preprocessor -> Detector Pipeline -> Actioner -> Moderator UI & Logs
                                        \-> Async OCR (for images)
                                        \-> Offline LLM inference server(s)
```

Components:

1. **Discord Bot Service** — receives message create/edit events (and attachments). Runs on servers with network access to Discord Gateway.
2. **Preprocessor** — normalizes messages (decode homoglyphs, strip zero-width, extract links, expand short URLs optionally via local heuristics).
3. **OCR Service** — Tesseract / newer OCR (self-hosted) that extracts text from images. Optionally a lightweight image classifier to identify screenshots vs memes to prioritize OCR.
4. **Detector Pipeline**

   * Rule-based filters (regexes for known scams, blacklist/whitelist).
   * Link analysis (domain heuristics, entropy, shorteners).
   * Offline LLM inference (text + OCR text + metadata) — returns label, score, and rationale.
5. **Actioner** — based on confidence & policy: auto-delete, auto-mute, quarantine (flag for human), or ignore. Posts audit logs and mod notifications.
6. **Moderator UI / Dashboard** — shows flagged items, model rationale, allow moderator actions (approve/reject), and feedback into retraining pipeline.
7. **Logging & Data Store** — store events, flagged messages, moderator labels for retraining/analytics.
8. **Retraining Pipeline (optional)** — offline labeling and fine-tuning/LLM updates.

---

# 4 — Data flow (message example)

1. Bot receives `MESSAGE_CREATE` with text + attachments.
2. Preprocessor normalizes text; extracts URLs and metadata (author, channel, guild, message age).
3. If attachments present:

   * Push image to OCR queue.
   * OCR extracts text (async but target within seconds).
4. Detector pipeline:

   * Quick rule-based checks run first (fast reject/allow).
   * If inconclusive, collate text + OCR results + link features and call offline LLM inference service.
5. LLM returns classification: `{label: "scam", confidence: 0.94, reasons: ["asks for money via venmo", "uses urgency"]}`.
6. Actioner enforces policy: confidence > 0.9 => delete and DM author (configurable), log event, ping mod channel. 0.5–0.9 => flag to mod dashboard for review. <0.5 ignore or add to monitoring.
7. Moderator reviews and labels; labels stored for retraining.

---

# 5 — Models & stacks (offline)

**OCR**

* Open-source: Tesseract (easy, CPU-friendly).
* Alternatively: self-hosted OCR models (e.g., PaddleOCR or lightweight CRNN implementations) for better robustness on screenshots.
* Preprocessing: upscale small images, binarize, deskew.

**Text detectors**

* **Rule-based layer**: custom regexes, domain blacklists, link heuristics.
* **Embedding + classifier**:

  * Use smaller transformer encoders (e.g., distilled RoBERTa / sentence-transformers converted to onnx/ggml) to produce embeddings and a cheap classifier (logistic/regression).
  * For high precision detection, an LLM is used for reasoning on context.
* **LLM reasoning layer** — offline LLMs (self-hosted) for complex cases:

  * Options: Quantized Llama-family, Mistral, Vicuna forks, or open weights that fit infra. Choose a model that supports local inference (GGML, ONNX, or Triton).
  * Quantization recommended: 4-bit/8-bit quantized models (e.g., using llama.cpp / ggml or bitsandbytes on GPU) to reduce memory.
  * For limited hardware, use a smaller model for classification prompts; for higher-end hosts, use a larger model for better context.

**Model role split**

* Small model (fast) → first LLM pass that produces classification & rationale.
* Large model (slow) → optional second opinion for ambiguous cases or to produce detailed rationale to moderators.

**Prompt design**

* Use instruction-style prompt templates that ask for binary outcome + concise reason + indicators (e.g., mentions of money, urgency, domains, impersonation).
* Keep prompt size bounded; include only preprocessed context and extracted OCR.

---

# 6 — Example heuristics & rule set

**Quick rules (fast path, avoid calling LLM):**

* Presence of `@admin` impersonation patterns + link -> flag.
* Keywords: "gift card", "wire", "venmo", "cashapp", "paypal.me", "dm me", "nft giveaway", "claim now", "verify account" combined with short link -> flag.
* Link points to known scam domain list -> delete.
* Message contains PayID-like patterns (phone numbers + money requests) + new account age < 1 day -> flag.

**Link heuristics**

* Domain age (if possible via local cached list) or domain entropy (many hyphens, suspicious TLDs).
* Shorteners: if link uses known shortener -> expand via safe/own expansion service or flag if expansion fails.

**Obfuscation handling**

* Normalize unicode homoglyphs (replace visually similar characters).
* Remove zero-width chars and soft hyphens.
* Convert common leetspeak to letters for analysis.

---

# 7 — Prompt template (example)

```
SYSTEM: You are a safety classifier for Discord that only answers with JSON. 
TASK: Given the message_text, attached_ocr_text (if any), and metadata, decide if this message is a scam/attempted fraud.

INPUT:
message_text: "<normalized message text>"
ocr_text: "<ocr text or empty>"
metadata: {author_age_days: X, has_links: true/false, links: [...], guild_policies: {...}}

OUTPUT (json):
{
  "label": "scam"|"not_scam"|"suspicious",
  "confidence": 0.0-1.0,
  "indicator_tags": ["payment_request","impersonation","phishing_link","urgent","refund_trick"],
  "short_reason": "one-sentence explanation",
  "evidence": ["contains 'venmo' and asks to DM", "ocr contains 'send to...']
}
```

Keep prompts short; include only essential context. Use a temperature of 0 for deterministic outputs.

---

# 8 — Moderator workflows & UI

**Automated flows**

* High-confidence scam: auto-delete, DM the user with a templated warning, log action, and notify mod channel with evidence.
* Medium-confidence: leave message but move to quarantine by pinning + mod notification, and show in Dashboard queue.
* Low-confidence: monitor; optionally add to "watchlist".

**Moderator Dashboard**

* List of flagged items with: message content, OCR text, author, channel, timestamp, LLM reason, confidence, one-click actions: Approve, Delete & Ban, Warn, Ignore.
* History and retraining label collection (when moderator marks a flagged item, store label and rationale).
* Searchable logs and export for legal/compliance.

**Moderator feedback loop**

* Moderator decisions feed into retraining dataset.
* Provide a CSV export and a labeled dataset for periodic model fine-tuning offline.

---

# 9 — Storage, privacy & compliance

**Data retention**

* Store flagged messages + evidence for a short retention window (configurable per guild, default 30 days). Keep only labels and non-sensitive features longer for retraining (anonymized).

**Encryption & access**

* Encrypt logs at rest.
* Access control for moderation dashboard (OAuth via Discord roles).

**Privacy**

* Avoid storing whole images if not necessary; store OCR text + small thumbnail unless evidence retention required.
* Follow guild rules & local regulations regarding user data; provide admins with opt-out/configs.

---

# 10 — Deployment & infra

**Minimum infra**

* CPU-only deployment is possible for low throughput using small models & Tesseract.
* For larger deployments, recommend GPU instances (NVIDIA) with quantized models and a model-serving stack.

**Suggested components**

* Containerize services via Docker Compose or Kubernetes:

  * `bot` (Python/Node service)
  * `preprocessor` (in-process or sidecar)
  * `ocr` (Tesseract or PaddleOCR container)
  * `llm-inference` (llama.cpp/ggml for CPU or a Triton/ONNX runtime for GPU)
  * `db` (Postgres for logs & labels)
  * `dashboard` (React + backend)
  * `redis` (queues & caching)
* Use a message queue (Redis/Sidekiq/RabbitMQ) to handle OCR and LLM tasks asynchronously to avoid blocking Discord event loop.

**Scaling**

* Horizontal: multiple worker replicas for LLM inference (stateless).
* Caching: embed domain reputations & link expansions to reduce repeated cost.

**Resource notes**

* LLM inference: quantized 7B models can run on decent CPU with acceptable latency; 13B+ will typically need GPU or powerful CPU and careful quantization.
* OCR: CPU-bound but parallelizable.

---

# 11 — Performance & latency targets

* Rule-based quick checks: <50 ms.
* OCR (per image): \~200–1000 ms depending on size & model.
* LLM inference:

  * Small model classification: <300–800 ms on modern CPU for quantized small models.
  * Larger reasoning pass: 1–5 sec (acceptable only for async flagging, not blocking actions).
* Use async pipeline: immediate rule-based action, then LLM/ocr for verification and potential retroactive removal.

---

# 12 — Evaluation & metrics

**Metrics to track**

* True Positive Rate (TPR) on labeled scams.
* False Positive Rate (FPR) — crucial to keep low to avoid moderator fatigue.
* Mean time to moderator decision for flagged messages.
* Precision\@k for top-confidence auto-deletes.
* OCR accuracy on community screenshot types.

**Testing**

* Synthetic dataset: collect known scam messages and images (anonymized).
* A/B test thresholds per guild.
* Simulate obfuscation (homoglyphs, image screenshots) during QA.

---

# 13 — Safety & failure modes

**False positives**

* Risk: accidentally deleting legit messages (e.g., legitimate donation requests).
* Mitigation: conservative auto-delete thresholds; priority to auto-flag instead of delete at medium confidence; allow whitelist by guild & trusted roles.

**False negatives**

* Risk: missing a scam.
* Mitigation: multilayered detection (rules + embedding + LLM + OCR), periodic retraining with moderator labels.

**Adversarial attempts**

* Attackers may use images with stylized text or memes to evade OCR. Improve OCR pipeline (rotate, upscale, multi-threshold binarization) and consider using image classification models trained to spot scam-like images.

**Model drift**

* Scam tactics evolve. Keep a retraining cadence and allow manual blacklist updates from moderators.

---

# 14 — Logging & observability

* Structured logs for each detection: `message_id`, `guild_id`, `channel_id`, `author_id`, `label`, `confidence`, `rules_triggered`, `ocr_text`, `model_version`, `timestamp`.
* Audit trail of moderator actions and appeals.
* Monitor system metrics: inference latency, queue size, OCR errors, model health.
* Alerting on sudden spikes in scam detections (possible targeted campaigns).

---

# 15 — Implementation plan & milestones

**MVP (2–4 weeks)**

* Implement Discord bot skeleton and event handling.
* Rule-based detector + link extraction + basic actioner.
* Tesseract OCR integration (sync/async).
* Simple moderator notifier (Discord mod channel webhook).
* Config per guild (thresholds + whitelist/blacklist).

**Phase 2 (4–8 weeks)**

* Integrate small offline model for embedding-based classification.
* Build simple moderator dashboard and logging (Postgres).
* Implement feedback loop storing moderator labels.

**Phase 3 (8–12 weeks)**

* Integrate LLM inference service (quantized Llama-like model) for rationale-based detection.
* Improve OCR (PaddleOCR or better).
* Add retraining pipeline and monthly scheduled model updates.

**Phase 4 (ongoing)**

* Performance optimization, horizontal scaling, advanced UI features: bulk actions, analytics, appeal handling.

---

# 16 — Configuration & admin commands (example)

Bot commands (moderator only):

* `!scamconfig set auto_delete_confidence 0.9`
* `!scamconfig set mod_channel #moderators`
* `!scam whitelist add example.com`
* `!scam blacklist add frauddomain.tld`
* `!scam stats` — returns detection stats for guild

Moderator quick actions in Discord for flagged messages:

* `✅ Approve (not scam)`
* `❌ Delete & Ban`
* `⚠️ Warn user`
  Each action recorded.

---

# 17 — Sample pseudocode (simplified)

```python
on_message(msg):
    text = normalize(msg.content)
    if quick_rule_block(text, msg):
        action_delete_and_log(msg, reason="rule")
        return
    enqueue_detection_task(msg.id, text, attachments)

worker_process(task):
    ocr_text = ""
    if task.attachments:
        for a in task.attachments: ocr_text += run_ocr(a)
    features = extract_features(task.text, ocr_text, task.links)
    if cheap_classifier_predict(features) >= 0.9:
        delete_message(task.msg_id)
        notify_mods(task, reason="classifier")
        log_event(...)
        return
    llm_out = call_llm(features)
    if llm_out.confidence >= config.auto_delete:
        delete_message(...)
    elif llm_out.confidence >= config.flag_threshold:
        flag_to_mod_dashboard(...)
```

---

# 18 — Example data schema (Postgres)

**flagged\_messages**

* id, guild\_id, channel\_id, message\_id, author\_id, text, ocr\_text, label, confidence, rules\_triggered, model\_version, created\_at

**moderator\_actions**

* id, flagged\_message\_id, moderator\_id, action, reason, created\_at

**domains\_blacklist**

* domain, added\_by, created\_at

---

# 19 — Open design questions & tradeoffs

* **Model selection**: prefer smaller models for cost/latency vs larger models for better reasoning. Strategy: hybrid — small for realtime, larger for offline analysis.
* **OCR accuracy vs cost**: higher-accuracy OCR (e.g., PaddleOCR) is heavier; consider allowing guilds to opt into "deep scan" with higher cost.
* **User privacy**: how long to keep images? Default short retention with opt-in retention for evidence is recommended.
* **Automatic enforcement aggressiveness**: default to conservative auto-deletes to avoid moderator backlash.

---

# 20 — Appendix

**Normalization steps**

* Lowercase, unicode normalization, homoglyph mapping, remove zero-width & soft hyphen, expand common abbreviations.

**Quick regex examples (to use only as part of rule-based layer)**

* Venmo/CashApp detection:

  ```
  /(venmo|cashapp|paypal\.me|payp(al)?\s*me)/i
  ```
* Payment pattern (phone + amount):

  ```
  /\b(\+?\d{7,15}|\(\d{3}\)\s*\d{3}-\d{4})\b.*\$\d{1,5}/
  ```

**Prompting tips**

* Always ask model to output strict JSON.
* Set temperature=0.
* Provide short context only — long messages can be truncated and passed to LLM only when needed.

**Monitoring checklist**

* Weekly review of false positives reported by mods.
* Monthly model retraining schedule using moderator-labeled data.
* Daily health check: queue sizes, inference latency.

---


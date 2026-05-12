# LLM Prompt Injection — Experimental Stand

Reproducible local stand for evaluating prompt injection vulnerabilities
and basic defense mechanisms in open-source large language models.

Developed as part of MIFI Master's thesis (2026):
*Повышение устойчивости больших языковых моделей к инъекционным атакам путём
исследования уязвимостей, разработки методов обнаружения и защиты
и их экспериментальной оценки на воспроизводимом стенде.*

## Author
Maxim Avdenya — M24-505, MIFI, Cryptology and Cybersecurity Dept.

## Stack
- Python 3.14
- Ollama (local model runtime)
- Tested models: Mistral 7B, Llama 3 8B, Phi-3 3.8B, Qwen2 7B

## Quick start
```bash
pip install -r requirements.txt
ollama pull mistral llama3 phi3 qwen2:7b
python src/universal_runner.py
```

## Project structure
- `src/` — main runner and defense modules
- `data/` — attack datasets (JSONL, 3 classes)
- `results/` — experimental outputs (JSON / CSV)

## Test scenarios
- Baseline RAG — 30 scenarios
- Vulnerable RAG with indirect injection — 15 scenarios
- Multi-turn injection — 10 scenarios

Total: 55 scenarios across 4 models.

## Metrics
- **ASR_strict** — strict attack success rate
- **Leakage Rate** — secret value leakage rate
- Dual measurement on raw model output vs. final filtered output

## Defense mechanisms
- Input sanitization — 43 regex patterns
- Output redaction — exact-match secret replacement

## Stability analysis
Additional series of 375 prompts (10 repeats × 15 attacks at t=0.5,
and 5 repeats × 15 attacks × 3 temperatures) confirms stability of
qualitative results across stochastic generation.

## Citation
> Авденя, М. А. Повышение устойчивости больших языковых моделей
> к инъекционным атакам. Магистерская диссертация, НИЯУ МИФИ, 2026.

## License
MIT

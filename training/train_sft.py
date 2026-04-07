"""SFT cold-start training for Sigma rule generation.

Fine-tunes a Gemma 4 model on (threat_description → sigma_rule) pairs
using QLoRA via Unsloth for 2x speed.

Usage::

    # Quick start with defaults (Gemma 4 26B MoE, QLoRA rank 128)
    python -m training.train_sft

    # Use a smaller model for prototyping
    python -m training.train_sft --model google/gemma-4-E4B-it --epochs 5

    # Custom data and output
    python -m training.train_sft \
        --data training/data/sft_pairs.jsonl \
        --output ./checkpoints/sft-sigma-v1 \
        --lora-rank 64 \
        --epochs 3

Requirements::

    pip install unsloth trl datasets pyyaml
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Chat template for Sigma rule generation
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a Sigma detection rule generator for AI agent security. "
    "Given a threat description, generate a complete, valid Sigma rule "
    "in YAML format following the SigmaHQ standard. The rule must include: "
    "title, id (UUID), status, description, author, date, tags (MITRE ATT&CK), "
    "logsource (product: ai_agent, category: agent_events), detection "
    "(with selection blocks and condition), falsepositives, and level."
)


def _format_chat(prompt: str, completion: str) -> list[dict]:
    """Format a training pair as a chat conversation."""
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": completion},
    ]


def load_dataset(data_path: str) -> list[dict]:
    """Load JSONL training pairs and format as chat conversations."""
    pairs = []
    with open(data_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            pairs.append({
                "conversations": _format_chat(item["prompt"], item["completion"]),
            })
    return pairs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SFT fine-tuning for Sigma rule generation"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="google/gemma-4-27b-it",
        help="Base model ID from HuggingFace (default: google/gemma-4-27b-it)",
    )
    parser.add_argument(
        "--data",
        type=str,
        default="training/data/sft_pairs.jsonl",
        help="Training data JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./checkpoints/sft-sigma-v1",
        help="Output directory for the fine-tuned model",
    )
    parser.add_argument(
        "--lora-rank", type=int, default=128,
        help="LoRA rank (default: 128)",
    )
    parser.add_argument(
        "--lora-alpha", type=int, default=256,
        help="LoRA alpha (default: 2x rank)",
    )
    parser.add_argument(
        "--epochs", type=int, default=3,
        help="Number of training epochs (default: 3)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=2,
        help="Per-device batch size (default: 2)",
    )
    parser.add_argument(
        "--grad-accum", type=int, default=4,
        help="Gradient accumulation steps (default: 4)",
    )
    parser.add_argument(
        "--lr", type=float, default=2e-4,
        help="Learning rate (default: 2e-4)",
    )
    parser.add_argument(
        "--max-seq-len", type=int, default=4096,
        help="Maximum sequence length (default: 4096)",
    )
    parser.add_argument(
        "--save-gguf",
        action="store_true",
        help="Also export to GGUF Q4_K_M after training",
    )
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Lazy imports — only needed when actually training
    # -----------------------------------------------------------------------
    from unsloth import FastLanguageModel
    from trl import SFTTrainer, SFTConfig
    from datasets import Dataset

    print(f"Loading model: {args.model}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_seq_len,
        load_in_4bit=True,
        dtype=None,  # auto-detect
    )

    print(f"Applying LoRA (rank={args.lora_rank}, alpha={args.lora_alpha})")
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.0,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        bias="none",
        use_gradient_checkpointing="unsloth",
    )

    # -----------------------------------------------------------------------
    # Load and prepare dataset
    # -----------------------------------------------------------------------
    print(f"Loading training data: {args.data}")
    raw_data = load_dataset(args.data)
    print(f"  {len(raw_data)} training examples")

    dataset = Dataset.from_list(raw_data)

    # -----------------------------------------------------------------------
    # Training
    # -----------------------------------------------------------------------
    training_args = SFTConfig(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        weight_decay=0.01,
        bf16=True,
        logging_steps=5,
        save_strategy="epoch",
        save_total_limit=2,
        seed=42,
        max_seq_length=args.max_seq_len,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=training_args,
    )

    print("Starting SFT training...")
    trainer.train()

    # -----------------------------------------------------------------------
    # Save
    # -----------------------------------------------------------------------
    print(f"Saving model to {args.output}")
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)

    if args.save_gguf:
        gguf_dir = args.output + "-gguf"
        print(f"Exporting GGUF Q4_K_M to {gguf_dir}")
        model.save_pretrained_gguf(
            gguf_dir,
            tokenizer,
            quantization_method="q4_k_m",
        )

    print("Done.")


if __name__ == "__main__":
    main()

"""GRPO training for Sigma rule generation.

Applies Group Relative Policy Optimization to improve rule generation
quality beyond the SFT ceiling. Uses our sigma_reward.py as the
verifiable reward function.

Usage::

    # From an SFT checkpoint
    python -m training.train_grpo \
        --model ./checkpoints/sft-sigma-v1 \
        --prompts training/data/grpo_prompts.jsonl

    # From a base model (skipping SFT — not recommended)
    python -m training.train_grpo \
        --model google/gemma-4-27b-it \
        --prompts training/data/grpo_prompts.jsonl

    # Full configuration
    python -m training.train_grpo \
        --model ./checkpoints/sft-sigma-v1 \
        --prompts training/data/grpo_prompts.jsonl \
        --output ./checkpoints/grpo-sigma-v1 \
        --group-size 16 \
        --steps 3000 \
        --batch-size 4

Requirements::

    pip install trl[vllm] datasets pyyaml unsloth
    # OR for multi-node:
    pip install openrlhf vllm datasets pyyaml
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from training.sigma_reward import score_rule
from training.train_sft import SYSTEM_PROMPT


def _build_prompt_dataset(prompts_path: str) -> list[dict]:
    """Load GRPO prompt dataset.

    Expected JSONL format: {"prompt": "...", ...}
    Each prompt is a threat description for the model to generate a rule from.
    """
    prompts = []
    with open(prompts_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            prompts.append(item)
    return prompts


def reward_function(completions: list[str], prompts: list[str] | None = None, **kwargs) -> list[float]:
    """Reward function for GRPO.

    Called by TRL's GRPOTrainer with a batch of generated completions.
    Each completion should be a Sigma rule in YAML format.

    Returns a list of scalar rewards in [0.0, 1.0].
    """
    if prompts is None:
        prompts = [""] * len(completions)

    rewards = []
    for completion, prompt in zip(completions, prompts):
        # Extract the text content from the completion
        text = completion if isinstance(completion, str) else str(completion)
        reward = score_rule(text, prompt)
        rewards.append(float(reward))
    return rewards


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRPO training for Sigma rule generation"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="./checkpoints/sft-sigma-v1",
        help="Model to start from (SFT checkpoint or HF model ID)",
    )
    parser.add_argument(
        "--prompts",
        type=str,
        default="training/data/grpo_prompts.jsonl",
        help="JSONL file with threat description prompts",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./checkpoints/grpo-sigma-v1",
        help="Output directory",
    )
    parser.add_argument(
        "--group-size", type=int, default=16,
        help="GRPO group size — completions sampled per prompt (default: 16)",
    )
    parser.add_argument(
        "--steps", type=int, default=3000,
        help="Total training steps (default: 3000)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=4,
        help="Per-device prompt batch size (default: 4)",
    )
    parser.add_argument(
        "--lr", type=float, default=5e-6,
        help="Learning rate (default: 5e-6, lower than SFT)",
    )
    parser.add_argument(
        "--kl-coef", type=float, default=0.04,
        help="KL penalty coefficient (default: 0.04)",
    )
    parser.add_argument(
        "--max-new-tokens", type=int, default=2048,
        help="Max tokens to generate per completion (default: 2048)",
    )
    parser.add_argument(
        "--max-seq-len", type=int, default=4096,
        help="Maximum total sequence length (default: 4096)",
    )
    parser.add_argument(
        "--lora-rank", type=int, default=128,
        help="LoRA rank (default: 128)",
    )
    parser.add_argument(
        "--use-vllm",
        action="store_true",
        default=True,
        help="Use vLLM for fast generation (default: True)",
    )
    parser.add_argument(
        "--no-vllm",
        action="store_true",
        help="Disable vLLM, use standard generation",
    )
    parser.add_argument(
        "--save-gguf",
        action="store_true",
        help="Export to GGUF Q4_K_M after training",
    )
    args = parser.parse_args()

    use_vllm = args.use_vllm and not args.no_vllm

    # -----------------------------------------------------------------------
    # Lazy imports
    # -----------------------------------------------------------------------
    from unsloth import FastLanguageModel
    from trl import GRPOTrainer, GRPOConfig
    from datasets import Dataset

    # -----------------------------------------------------------------------
    # Load model
    # -----------------------------------------------------------------------
    print(f"Loading model: {args.model}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_seq_len,
        load_in_4bit=True,
        dtype=None,
    )

    print(f"Applying LoRA (rank={args.lora_rank})")
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_rank,
        lora_alpha=args.lora_rank * 2,
        lora_dropout=0.0,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        bias="none",
        use_gradient_checkpointing="unsloth",
    )

    # -----------------------------------------------------------------------
    # Load prompt dataset
    # -----------------------------------------------------------------------
    print(f"Loading prompts: {args.prompts}")
    raw_prompts = _build_prompt_dataset(args.prompts)
    print(f"  {len(raw_prompts)} prompts")

    # Format prompts as chat messages for the model
    formatted = []
    for item in raw_prompts:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": item["prompt"]},
        ]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        formatted.append({"prompt": text})

    dataset = Dataset.from_list(formatted)

    # -----------------------------------------------------------------------
    # GRPO config
    # -----------------------------------------------------------------------
    grpo_config = GRPOConfig(
        output_dir=args.output,
        max_steps=args.steps,
        per_device_train_batch_size=args.batch_size,
        num_generations=args.group_size,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        weight_decay=0.01,
        bf16=True,
        logging_steps=10,
        save_steps=500,
        save_total_limit=3,
        seed=42,
        max_completion_length=args.max_new_tokens,
        # KL penalty
        beta=args.kl_coef,
        # Generation sampling parameters
        temperature=0.8,
        top_p=0.95,
        # vLLM for fast generation
        use_vllm=use_vllm,
    )

    # -----------------------------------------------------------------------
    # Train
    # -----------------------------------------------------------------------
    trainer = GRPOTrainer(
        model=model,
        tokenizer=tokenizer,
        reward_funcs=reward_function,
        args=grpo_config,
        train_dataset=dataset,
    )

    print(f"Starting GRPO training ({args.steps} steps, group_size={args.group_size})")
    print(f"  Effective batch: {args.batch_size} prompts × {args.group_size} completions = {args.batch_size * args.group_size} generations/step")
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

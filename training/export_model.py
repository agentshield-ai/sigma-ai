"""Export a trained model to GGUF and create an Ollama Modelfile.

Converts a fine-tuned checkpoint to quantized GGUF format for local
deployment via llama.cpp or Ollama.

Usage::

    # Export with default Q4_K_M quantization
    python -m training.export_model --model ./checkpoints/grpo-sigma-v1

    # Export multiple quantizations
    python -m training.export_model \
        --model ./checkpoints/grpo-sigma-v1 \
        --quants q4_k_m q6_k q8_0

    # Export and create Ollama Modelfile
    python -m training.export_model \
        --model ./checkpoints/grpo-sigma-v1 \
        --ollama

Requirements::

    pip install unsloth
    # For Ollama import: ollama must be installed locally
"""

from __future__ import annotations

import argparse
from pathlib import Path

from training.train_sft import SYSTEM_PROMPT

OLLAMA_MODELFILE_TEMPLATE = """\
FROM {gguf_path}

SYSTEM \"\"\"{system_prompt}\"\"\"

PARAMETER temperature 0.3
PARAMETER top_p 0.9
PARAMETER stop "<end_of_turn>"

TEMPLATE \"\"\"{{{{- if .System }}}}
<start_of_turn>system
{{{{ .System }}}}<end_of_turn>
{{{{- end }}}}
<start_of_turn>user
{{{{ .Prompt }}}}<end_of_turn>
<start_of_turn>model
{{{{ .Response }}}}<end_of_turn>\"\"\"
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Export model to GGUF + Ollama")
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to fine-tuned checkpoint",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory (default: <model>-gguf)",
    )
    parser.add_argument(
        "--quants",
        nargs="+",
        default=["q4_k_m"],
        help="Quantization methods (default: q4_k_m)",
    )
    parser.add_argument(
        "--ollama",
        action="store_true",
        help="Create Ollama Modelfile for each quantization",
    )
    parser.add_argument(
        "--ollama-name",
        type=str,
        default="agentshield-sigma",
        help="Ollama model name (default: agentshield-sigma)",
    )
    parser.add_argument(
        "--max-seq-len",
        type=int,
        default=4096,
        help="Max sequence length for export (default: 4096)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output) if args.output else Path(args.model + "-gguf")
    output_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Lazy imports
    # -----------------------------------------------------------------------
    from unsloth import FastLanguageModel

    print(f"Loading model: {args.model}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_seq_len,
        load_in_4bit=True,
        dtype=None,
    )

    for quant in args.quants:
        quant_dir = output_dir / quant
        print(f"Exporting {quant} to {quant_dir}")
        model.save_pretrained_gguf(
            str(quant_dir),
            tokenizer,
            quantization_method=quant,
        )

        # Find the exported GGUF file
        gguf_files = list(quant_dir.glob("*.gguf"))
        if not gguf_files:
            print(f"  Warning: no .gguf file found in {quant_dir}")
            continue

        gguf_path = gguf_files[0]
        print(f"  Exported: {gguf_path} ({gguf_path.stat().st_size / 1e9:.1f} GB)")

        if args.ollama:
            modelfile_path = quant_dir / "Modelfile"
            modelfile_content = OLLAMA_MODELFILE_TEMPLATE.format(
                gguf_path=gguf_path.name,
                system_prompt=SYSTEM_PROMPT,
            )
            modelfile_path.write_text(modelfile_content, encoding="utf-8")
            print(f"  Modelfile: {modelfile_path}")

            tag = f"{args.ollama_name}:{quant.replace('_', '-')}"
            print(f"  To import: cd {quant_dir} && ollama create {tag} -f Modelfile")

    # Print summary
    print("\n--- Export Summary ---")
    print(f"Source: {args.model}")
    print(f"Output: {output_dir}")
    print(f"Quantizations: {', '.join(args.quants)}")
    if args.ollama:
        print(f"\nTo run locally:")
        for quant in args.quants:
            tag = f"{args.ollama_name}:{quant.replace('_', '-')}"
            print(f"  cd {output_dir / quant} && ollama create {tag} -f Modelfile")
            print(f"  ollama run {tag}")


if __name__ == "__main__":
    main()

# Business Intelligence: High-Precision SVG Generation

This directory showcases how to "industrialize" Gemma 3 12B for specialized business needs, specifically focusing on deterministic, high-precision data visualization.

## Included Showcase
* **[SVG Chart Generation](./gemma3_svg_chart_generation.ipynb)**: A complete workflow using specialized LoRA adapters to transform JSON data into valid, production-ready SVG charts.

## Key Innovations
* **4-Stage Validation Gate**: A robust pipeline that ensures XML integrity and geometric accuracy, preventing "coordinate hallucinations" common in standard LLM outputs.
* **Local-First / MLX Optimized**: Built to run performantly on Apple Silicon, demonstrating that high-utility fine-tuning is accessible on consumer-grade hardware.
* **Domain-Specific LoRAs**: Leverages 12 per-type adapters (Bar, Funnel, Waterfall, etc.) for superior geometric reasoning.

**Model Credits:** [John-Williams-ATL/svg-chart-lora](https://huggingface.co/John-Williams-ATL/svg-chart-lora)

# Tutorials

Notebooks for Gemma models and variants.

| Notebook Name | Description |
|:--| --- |
| [Agentic_RAG.ipynb](Agentic_RAG.ipynb) | Build an Agentic RAG system that intelligently decides when to call functions, uses a Qdrant based RAG pipeline, and falls back to Google Search. Trace and monitor with OPIK. |
| [Data_Parallel_Inference_JAX_TPU_v5e8.ipynb](Data_Parallel_Inference_JAX_TPU_v5e8.ipynb) | Data parallel inference with Gemma 3 across a Kaggle TPU v5e-8 mesh, using the Keras 3 JAX backend and the Keras Distribution API. |
| [Image_Segmentation.ipynb](Image_Segmentation.ipynb) | Image Segmentation Task with Gemma 4 |
| [On_Device_AI.ipynb](On_Device_AI.ipynb) | Build a fully on-device RAG pipeline using Lite-RT and Qdrant Edge |
| [RAG_with_EmbeddingGemma.ipynb](RAG_with_EmbeddingGemma.ipynb) | Build simple RAG with [EmbeddingGemma](https://ai.google.dev/gemma/docs/embeddinggemma) |
| [Translator_of_Old_Korean_Literature.ipynb](Translator_of_Old_Korean_Literature.ipynb) | Fine-tuning Gemma to translate old Korean literature |

## Inference Capabilities

Explore Gemma's capabilities across different modalities:

| Notebook Name | Description |
|:--| --- |
| [Text - Basic](../docs/capabilities/text/basic.ipynb) | Basic text generation and prompting with Gemma 4. |
| [Text - Function Calling](../docs/capabilities/text/function-calling-gemma4.ipynb) | Leverage Gemma 4 for tool use and function calling. |
| [Vision - Image](../docs/capabilities/vision/image.ipynb) | Visual understanding and captioning with Gemma 4. |
| [Vision - Video](../docs/capabilities/vision/video.ipynb) | Video understanding and analysis with Gemma 4. |
| [Audio](../docs/capabilities/audio.ipynb) | Explore audio processing and understanding. |
| [Thinking](../docs/capabilities/thinking.ipynb) | Reasoning capabilities. |

## Fine-tuning

Examples of fine-tuning Gemma models:

| Notebook Name | Description |
|:--| --- |
| [Text Fine-tuning with QLoRA](../docs/core/huggingface_text_finetune_qlora.ipynb) | Efficiently fine-tune Gemma 4 for text tasks using QLoRA. |
| [Vision Fine-tuning with QLoRA](../docs/core/huggingface_vision_finetune_qlora.ipynb) | Efficiently fine-tune Gemma 4 for vision tasks using QLoRA. |

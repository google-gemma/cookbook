
# Welcome to the Gemma Cookbook
This is a collection of guides and examples for [Google Gemma](https://ai.google.dev/gemma/).

> **Disclaimer:** Gemma is a family of developer-focused models built by Google DeepMind. This cookbook is a collection of guides and examples for Google Gemma. Please keep in mind that Gemma is an open model and can hallucinate as you build on examples in this cookbook.

## Get started with the Gemma models
Gemma is a family of lightweight, generative artificial intelligence (AI) open models, built from the same research and technology used to create the Gemini models. The Gemma model family includes:
* Gemma\
  The core models of the Gemma family.
  * [Gemma](https://ai.google.dev/gemma/docs/core/model_card)\
    For a variety of text generation tasks and can be further tuned for specific use cases
  * [Gemma 2](https://ai.google.dev/gemma/docs/core/model_card_2)\
    Higher-performing and more efficient, available in 2B, 9B, 27B parameter sizes
  * [Gemma 3](https://ai.google.dev/gemma/docs/core/model_card_3)\
    Longer context window and handling text and image input, available in 1B, 4B, 12B, and 27B parameter sizes
  * [Gemma 3n](https://ai.google.dev/gemma/docs/gemma-3n/model_card) \
    Designed for efficient execution on low-resource devices. Handling text, image, video, and audio input, available in E2B and E4B parameter sizes
  * [Gemma 4](https://ai.google.dev/gemma/docs/core/model_card_4)\
    Well-suited for reasoning, agentic workflows, coding, and multimodal understanding, available in E2B, E4B, 26B A4B, and 31B parameter sizes.
* Gemma variants
  * [CodeGemma](https://ai.google.dev/gemma/docs/codegemma)\
    Fine-tuned for a variety of coding tasks
  * [DataGemma](https://ai.google.dev/gemma/docs/datagemma)\
    Fine-tuned for using Data Commons to address AI hallucinations
  * [FunctionGemma](https://ai.google.dev/gemma/docs/functiongemma)\
    Fine-tuned on Gemma 3 270M IT checkpoint for function calling
  * [MedGemma](https://developers.google.com/health-ai-developer-foundations/medgemma)
    The MedGemma collection contains Google's most capable open models for medical text and image comprehension, built on Gemma 3. Developers can use MedGemma to accelerate building healthcare-based AI applications. MedGemma comes in two variants: a 4B multimodal version and a 27B text-only version.
  * [PaliGemma](https://ai.google.dev/gemma/docs/paligemma/model-card)\
    Vision Language Model\
    For a deeper analysis of images and provide useful insights
  * [PaliGemma 2](https://ai.google.dev/gemma/docs/paligemma/model-card-2)\
    VLM which incorporates the capabilities of the Gemma 2 models
  * [RecurrentGemma](https://ai.google.dev/gemma/docs/recurrentgemma)\
    Based on [Griffin](https://arxiv.org/abs/2402.19427) architecture\
    For a variety of text generation tasks
  * [ShieldGemma](https://ai.google.dev/gemma/docs/shieldgemma/model_card)\
    Fine-tuned for evaluating the safety of text prompt input and text output responses against a set of defined safety policies
  * [ShieldGemma 2](https://ai.google.dev/gemma/docs/shieldgemma/model_card_2)\
    Fine-tuned on Gemma 3 4B IT checkpoint for image safety classification
  * [T5Gemma](https://deepmind.google/models/gemma/t5gemma)\
    A collection of encoder-decoder models that provide a strong quality-inference efficiency tradeoff
  * [TranslateGemma](https://huggingface.co/collections/google/translategemma)\
    A collection of open model designed to handle translation tasks across 55 languages
  * [TxGemma](https://deepmind.google/models/gemma/txgemma)\
    A collection of open models designed to improve the efficiency of therapeutic development
  * [VaultGemma](https://deepmind.google/models/gemma/vaultgemma)\
    An open model trained from the ground up using differential privacy to prevent memorization and leaking of training data examples

You can find the Gemma models on the Hugging Face Hub, Kaggle, Google Cloud Vertex AI Model Garden, and [ai.nvidia.com](https://ai.nvidia.com).

## Table of Notebooks
* [Gemma](Gemma/README.md)
* [CodeGemma](CodeGemma/README.md)
* [FunctionGemma](FunctionGemma/README.md)
* [PaliGemma](PaliGemma/README.md)
* [MedGemma](MedGemma/README.md)
* [MedGemma on Google-Health](https://github.com/Google-Health/medgemma/tree/main/notebooks) : Google-Health has additional notebooks for using MedGemma
* [TxGemma](TxGemma/README.md)
* [Workshops and technical talks](Workshops/README.md)
* [Research](Research/): Notebooks for research focused models
* [Showcase complex end-to-end use cases](Demos/README.md)
* [Gemma on Google Cloud](https://github.com/GoogleCloudPlatform/generative-ai/tree/main/open-models) : GCP open models has additional notebooks for using Gemma

## Get help
Ask a Gemma cookbook-related question on the [developer forum](https://discuss.ai.google.dev/c/gemma/10), or open an [issue](https://github.com/google-gemini/gemma-cookbook/issues) on GitHub.

## Wish list
If you want to see additional cookbooks implemented for specific features/integrations, please open a new issue with [“Feature Request” template](https://github.com/google-gemini/gemma-cookbook/issues/new?template=feature_request.yml).

If you want to make contributions to the Gemma Cookbook project, you are welcome to pick any idea in the [“Wish List”](https://github.com/google-gemini/gemma-cookbook/labels/wishlist) and implement it.

## Contributing
Contributions are always welcome. Please read [contributing](https://github.com/google-gemini/gemma-cookbook/blob/main/CONTRIBUTING.md) before implementation.

Thank you for developing with Gemma! We’re excited to see what you create.

## Translation of this repository
* [Traditional Chinese](https://github.com/doggy8088/gemma-cookbook)
* [Simplified Chinese](https://github.com/xiaoxiong1006/gemma-cookbook)

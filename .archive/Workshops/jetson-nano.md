# Run Gemma on NVIDIA Jetson Orin Nano

The NVIDIA Jetson Orin Nano developer kit is a small but powerful computer
capable of running open models, making it a great way to experiment with
on-device inference.

However, for optimal performance it should be updated to the
latest version of the NVIDIA JetPack stack.

## Why update?

tl,dr: for much higher performance.

Jetson Orin Nano kits typically come flashed at the factory with an older
version of NVIDIA JetPack.

In December 2024, NVIDIA released the JetPack 6.2 update, which adds new power
modes to the Jetson Orin Nano which unlock much greater levels of performance,
as seen in the following table.


Benchmark performance in tokens/sec on Jetson Orin Nano 8GB:
| Model | Orin Nano 8GB (original) | Orin Nano 8GB (Super Mode) | Perf Gain (x)|
|:------|:-------------------------|:---------------------------|:-------------|
|Gemma 2 2B|21.5|35.0|1.63|
|Gemma 2 9B|7.20|9.20|1.28|
|PaliGemma2 3B|13.7|21.6|1.58|

For more information, see
https://developer.nvidia.com/blog/nvidia-jetpack-6-2-brings-super-mode-to-nvidia-jetson-orin-nano-and-jetson-orin-nx-modules/

## Updating your dev kit

NVIDIA has prepared a full guide for this process which you can find here.

https://www.jetson-ai-lab.com/initial_setup_jon.html

Note that you will need a microSD card of at least 64gb capacity, and a computer
with a microSD reader.

## Running Gemma on your dev kit

### Getting started
Most of your interacting with Gemma on your dev kit will happen using the
terminal, using tools such as cURL and wget.

Go ahead and install cURL on the dev kit before you do anything else.

NOTE: the default username and password for a Jetson Orin Nano is
`nvidia` / `nvidia`

1. Open Terminal app

    Shortcut : Ctrl + Alt + T

2. Install curl

    $ sudo apt install curl

### Ollama

Ollama provides a simplified and user-friendly way to run and manage large
language models locally.

It streamlines setup, model management, and interaction, with a focus on
ease of use and extensibility, making LLMs accessible to a wider range of users.

The below is a quick guide to running Ollama and Gemma 3 on your Jetson Orin
Nano.

First, install Ollama:

    $ curl -fsSL https://ollama.com/install.sh | sh


This will install Ollama and make it accessible in your system path as `ollama`.

Next, try Ollama out with some text inference using Gemma 3 (Ollama will fetch
and cache the model on first use).

    $ ollama run gemma3:1b “Write me a poem about the Kraken.”

# More information

For a video demonstration of what's possible, see [Demo: Gemma 2 2B on a Jetson Orin Nano
](https://www.youtube.com/watch?v=Kd7VJ-TKb8I&list=PLOU2XLYxmsIKOyXflnuPK-qe32hZLc2HB&index=12).

For more information on using Ollama, see the [Ollama documentation](https://gemma.ai/deployment/ollama/) 
on ai.google.dev.


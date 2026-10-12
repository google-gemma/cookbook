# Gemma 4: Fixing Ollama Web Search

When using **Gemma 4** with the Ollama Web Search tool (or within wrappers like OpenWebUI), you might encounter an issue where the model attempts a search but then "sees nothing" or acts as if no query was submitted.

This happens because Gemma 4 uses a strict structured token format (`<|tool_call|>` and `<|tool_response|>`) for tools. If Ollama's default prompt template doesn't explicitly instruct the model to use these tags or if it strips the returned results from the template, Gemma 4 will drop the context.

## Solution

We have provided a custom `Modelfile` that injects the required structured tags into the system template, ensuring web search payloads are correctly returned to Gemma.

### Usage

1. Build the custom model locally:
```bash
ollama create gemma4-search-fixed -f Modelfile
```

2. Run it with the web search tool:
```bash
ollama run gemma4-search-fixed
```

3. (If using OpenWebUI): Select `gemma4-search-fixed` as your default model and enable the Web Search toggle. The tool results will now be correctly interpreted by Gemma.

# Run a fine-tuned Gemma 3 270M model in the browser with MediaPipe LLM Inference API

This app demonstrates how to generate emojis from a text input using a fine-tuned Gemma 3 270M model running directly in the browser. For this demo you'll just change one line of code to point to your MediaPipe Task model bundle.

## Run the demo
1. Download the app files in this directory and include your .task model bundle in the local app folder.
2. In the worker.js file, update the `modelPath` to point to the .task file.
3. Open terminal on your computer and navigate (`cd`) to the app folder.
4. To run the app, you need a local web server. For development and testing, it is recommended to use a secure (HTTPS) server, as WebGPU may not be available in non-secure contexts.
    1. **For a secure server:**
        1. If you don't have a local certificate, create one by running this command in your terminal at the root of this project (/app-mediapipe):
            ```bash
            openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=US/ST=CA/L=Mountain View/O=Dev/CN=localhost"
            ```
        2. Start the server with the following command:
            ```bash
            npx http-server -S -c-1 -p 8080
            ```
    2. **For a non-secure server:**
        ```bash
        npx serve
        ```
5. Open the provided `localhost` address in your browser to run the app.

## How it works
This demo sets up a simple web server to host a frontend where users can enter a text prompt. This starts a generation process in a web worker to avoid blocking the main UI thread. The worker uses a bundled version of the MediaPipe Tasks GenAI package ([@mediapipe/tasks-genai](https://www.npmjs.com/package/@mediapipe/tasks-genai)) to generate a response from the model and send it back to the user.

**Requirements:** Browser with [WebGPU support](https://caniuse.com/webgpu). Note that some platforms, like iOS Safari, require a secure context (HTTPS) to enable WebGPU.

**Device Limitations:** Running language models in the browser is memory-intensive. While this demo may work on high-end desktop machines, some memory-constrained devices, especially on iOS, may fail to load the model and cause the page to crash. This is due to strict memory limits imposed by the operating system on browser tabs. Even when running with 16-bit float precision, the Gemma 270M model can exceed these limits.

## Resources
* [Notebook: Fine-tune Gemma 3 270M](https://github.com/google-gemini/gemma-cookbook/blob/main/Demos/Emoji-Gemma-on-Web/resources/Fine_tune_Gemma_3_270M_for_emoji_generation.ipynb)
* [Notebook: Convert Gemma 3 270M for use with MediaPipe](https://github.com/google-gemini/gemma-cookbook/blob/main/Demos/Emoji-Gemma-on-Web/resources/Convert_Gemma_3_270M_to_LiteRT_for_MediaPipe_LLM_Inference_API.ipynb)
* [MediaPipe LLM Inference Web documentation](https://ai.google.dev/edge/mediapipe/solutions/genai/llm_inference/web_js)

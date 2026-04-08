// Set up DOM references
const generateBtn = document.getElementById("generate-btn");
const promptInput = document.getElementById("prompt-input");
const responseOutput = document.getElementById("response-output");
const statusMessageContainer = document.getElementById("status-message");

const workerPath = './worker.js';
let worker;
let modelReady = false;

// Handle the click-to-copy event for an emoji translation result
function handleEmojiButtonClick(result) {
  navigator.clipboard.writeText(result);
  statusMessageContainer.textContent = `Copied to clipboard: ${result}`;
  console.log(`[UI] Copied "${result}" to clipboard.`);
}

// Create and append a button for an emoji translation result
function createEmojiButton(result) {
  const button = document.createElement("button");
  button.textContent = result;
  button.onclick = () => handleEmojiButtonClick(result);
  responseOutput.appendChild(button);
}

// Check for WebGPU availability and displays an error message if it's not available
function checkWebGPU() {
  if (!navigator.gpu) {
    let message = `
      This application requires WebGPU to run the model in your browser.
      Please update your browser to enable WebGPU support, try a different browser (like Chrome or Edge, version 113+), or ensure your GPU drivers are up to date.</br></br>
      For more details, read the <a href="https://github.com/gpuweb/gpuweb/wiki/Implementation-Status" target="_blank" style="color: #286aac">WebGPU Implementation Status</a>.
    `;

    if (!window.isSecureContext) {
      message += `
        <br/><br/>
        <strong>Note:</strong> WebGPU requires a secure context. Please access this page over HTTPS or from 'localhost'. Accessing a local server via its IP address also requires an HTTPS setup in many instances (e.g. iOS26 Safari).
      `;
    }

    statusMessageContainer.innerHTML = message;
    generateBtn.disabled = true;
    return false;
  }
  return true;
}

// Main function to run worker
async function initializeModelInWorker() {
  console.log("[UI] Initializing application...");

  // Create a simulated progress loader that clears once the model loads
  if (!checkWebGPU()) {
    return;
  }
  let loadingInterval;
  let progress = 0;
  statusMessageContainer.textContent = "Loading model (0%)";
  loadingInterval = setInterval(() => {
    if (progress < 99) {
      progress++;
    }
    statusMessageContainer.textContent = `Loading model (${progress}%)`;
  }, 70);

  // Create a new worker to run the model in a separate thread
  worker = new Worker(workerPath);
  console.log("[UI] Worker created.");

  // Listen for messages from the worker
  worker.onmessage = (event) => {
    const { type, data } = event.data;
    console.log("[UI] Received message from worker:", { type, data });

    switch (type) {
      case "loaded":
        clearInterval(loadingInterval); // Stop the fake loader
        statusMessageContainer.textContent = `Loading model (100%)`; // Show 100% briefly
        modelReady = true;
        generateBtn.disabled = false;             // Enable the generation button upon model load
        setTimeout(() => {
          statusMessageContainer.innerHTML = ``;  // Then empty status message
        }, 500);
        break;

      case "result":
        const line = data.trim();
        if (line) {
          createEmojiButton(line);
        }
        break;

      case "complete":
        responseComplete();
        break;
      case "error":
        clearInterval(loadingInterval);
        console.error("Worker error:", data);
        if (modelReady) {
          // Error during generation
          generateBtn.classList.remove('generating');
          statusMessageContainer.textContent =
            "Failed to generate response. Check the console for errors.";
          generateBtn.disabled = false; // Re-enable button
        } else {
          // Error during model loading
          statusMessageContainer.textContent = "Failed to load model. Please refresh the page.";
        }
        break;
    }
  };

  // Start loading the model in the worker
  console.log('[UI] Sending "load" message to worker.');
  worker.postMessage({ type: "load" });
}

function responseComplete() {
  generateBtn.classList.remove('generating');
  generateBtn.disabled = false;

  if (responseOutput.childElementCount === 0) {
    statusMessageContainer.textContent = "No results";
  } else {
    // Clear the status message if we have results
    statusMessageContainer.textContent = "Click to copy emojis";
    // For accessibility, move focus to the first result so keyboard users can navigate them.
    responseOutput.firstChild.focus();
  }
}

function resetUI() {
  console.log("[UI] Resetting UI state.");
  generateBtn.classList.add('generating');
  generateBtn.disabled = true;
  responseOutput.innerHTML = ""; // Clear previous buttons
  statusMessageContainer.textContent = "Generating..."; // Set generating status
}

async function generateResponse() {
  const prompt = promptInput.value.trim();
  if (!prompt) {
    statusMessageContainer.textContent = "Please enter a prompt.";
    return;
  }

  if (!worker || !modelReady) {
    statusMessageContainer.textContent = "Model is not ready yet. Please wait.";
    return;
  }

  resetUI();

  // Send prompt to worker to start generation
  console.log(
    `[UI] Sending "generate" message to worker with prompt: "${prompt}"`
  );
  worker.postMessage({ type: "generate", data: { prompt } });
}

// After the script is loaded, initialize the text generator.
async function initializeAndAttachListeners() {
  console.log("[UI] Starting initialization and attaching listeners.");

  await initializeModelInWorker();

  generateBtn.addEventListener("click", generateResponse);

  // Add event listener for "Enter" key press in the prompt input field
  promptInput.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && !event.shiftKey && !generateBtn.disabled) {
      console.log('[UI] "Enter" key pressed, triggering generation.');
      event.preventDefault(); // Prevents the default action (form submission/new line)
      generateResponse();
    }
  });
}

initializeAndAttachListeners();

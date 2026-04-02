package com.example.gemmaappimage

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import com.google.mediapipe.framework.image.BitmapImageBuilder
import com.google.mediapipe.tasks.genai.llminference.GraphOptions
import com.google.mediapipe.tasks.genai.llminference.LlmInference
import com.google.mediapipe.tasks.genai.llminference.LlmInferenceSession
import java.io.File

private const val TAG = "GemmaModel"

// Default values for LLM models
private object LLMConstants {
    const val MODEL_PATH = "/data/local/tmp/llm/gemma-3n-E2B-it-int4.task"
    const val DEFAULT_MAX_TOKEN = 4096
    const val DEFAULT_TOPK = 64
    const val DEFAULT_TOPP = 0.95f
    const val DEFAULT_TEMPERATURE = 1.0f
    const val MAX_IMAGE_COUNT = 1
    val DEFAULT_BACKEND = LlmInference.Backend.GPU
}

typealias ResultListener = (partialResult: String, done: Boolean) -> Unit

class GemmaModel private constructor(context: Context) {
    private lateinit var llmInference: LlmInference
    private lateinit var llmInferenceSession: LlmInferenceSession

    init {
        if (!modelExists()) {
            Log.d(TAG, "Model not found at path: ${LLMConstants.MODEL_PATH}")
            //throw IllegalArgumentException("Model not found at path: ${LLMConstants.MODEL_PATH}")
        } else {

            // Set the configuration options for the LLM Inference task
            val taskOptions = LlmInference.LlmInferenceOptions.builder()
                .setModelPath(LLMConstants.MODEL_PATH)
                .setMaxTokens(LLMConstants.DEFAULT_MAX_TOKEN)
                .setPreferredBackend(LLMConstants.DEFAULT_BACKEND)
                .setMaxNumImages(LLMConstants.MAX_IMAGE_COUNT)
                .build()

            // Create an instance of the LLM Inference task
            llmInference = LlmInference.createFromOptions(context, taskOptions)
            createSession()
        }
    }

    fun close() {
        if (!modelExists()) {
            Log.d(TAG, "Model not found at path: ${LLMConstants.MODEL_PATH}")
            return
        }

        llmInferenceSession.close()
        llmInference.close()
    }

    fun resetSession() {
        if (!modelExists()) {
            Log.d(TAG, "Model not found at path: ${LLMConstants.MODEL_PATH}")
            return
        }

        llmInferenceSession.close()
        createSession()
    }

    private fun createSession() {
        llmInferenceSession =
            LlmInferenceSession.createFromOptions(
                llmInference,
                LlmInferenceSession.LlmInferenceSessionOptions.builder()
                    .setTopK(LLMConstants.DEFAULT_TOPK)
                    .setTopP(LLMConstants.DEFAULT_TOPP)
                    .setTemperature(LLMConstants.DEFAULT_TEMPERATURE)
                    .setGraphOptions(
                        GraphOptions.builder()
                            .setEnableVisionModality(true)
                            .build()
                    )
                    .build(),
            )
    }

    fun generateResponseAsync(
        bitmap: Bitmap,
        prompt: String,
        resultListener: ResultListener
    ) {
        if (!modelExists()) {
            throw Exception("Model not found at path: ${LLMConstants.MODEL_PATH}")
        }

        llmInferenceSession.addQueryChunk(prompt)
        llmInferenceSession.addImage(BitmapImageBuilder(bitmap).build())
        llmInferenceSession.generateResponseAsync(resultListener)
    }

    fun cancelGenerateResponseAsync() {
        if (!modelExists()) {
            throw Exception("Model not found at path: ${LLMConstants.MODEL_PATH}")
        }

        llmInferenceSession.cancelGenerateResponseAsync()
    }

    companion object {
        private var instance: GemmaModel? = null

        fun getInstance(context: Context): GemmaModel {
            return if (instance != null) {
                instance!!
            } else {
                GemmaModel(context).also { instance = it }
            }
        }

        fun resetInstance(context: Context): GemmaModel {
            return GemmaModel(context).also { instance = it }
        }

        fun modelExists(): Boolean {
            return File(LLMConstants.MODEL_PATH).exists()
        }
    }
}
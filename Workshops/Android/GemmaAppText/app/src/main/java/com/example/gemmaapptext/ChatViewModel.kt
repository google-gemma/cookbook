package com.example.gemmaapptext

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.CreationExtras
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

private const val TAG = "ChatViewModel"

class ChatViewModel(
    private val llmModel: GemmaModel
) : ViewModel() {
    private val _uiState: MutableStateFlow<UiState> =
        MutableStateFlow(UiState.Initial)
    val uiState: StateFlow<UiState> =
        _uiState.asStateFlow()

    fun resetSession() {
        llmModel.resetSession()
    }

    fun sendPrompt(
        prompt: String,
    ) {
        _uiState.value = UiState.Loading

        viewModelScope.launch(Dispatchers.Default) {
            try {
                var response = ""
                llmModel.generateResponseAsync(prompt) { partialResult, done ->
                    response += partialResult
                    if (done) {
                        _uiState.value = UiState.Success(response)
                    } else {
                        _uiState.value = UiState.Generating(response)
                    }
                }
            } catch (e: Exception) {
                _uiState.value = UiState.Error(e.localizedMessage ?: "")
            }
        }
    }

    fun stopResponse() {
        Log.d(TAG, "Stopping response for model...")
        viewModelScope.launch(Dispatchers.Default) {
            llmModel.cancelGenerateResponseAsync()
        }
        Log.d(TAG, "Stopping done.")
    }

    companion object {
        fun getFactory(context: Context) = object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>, extras: CreationExtras): T {
                val inferenceModel = GemmaModel.getInstance(context)
                @Suppress("UNCHECKED_CAST")
                return ChatViewModel(inferenceModel) as T
            }
        }
    }
}
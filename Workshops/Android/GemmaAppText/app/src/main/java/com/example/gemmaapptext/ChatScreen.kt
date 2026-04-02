package com.example.gemmaapptext

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.gemmaapptext.ui.theme.GemmaAppTextTheme

@Composable
fun ChatScreen() {
    val placeholderPrompt = stringResource(R.string.prompt_placeholder)
    val placeholderResult = stringResource(R.string.result_placeholder)
    var prompt by rememberSaveable { mutableStateOf(placeholderPrompt) }
    var result by rememberSaveable { mutableStateOf(placeholderResult) }

    val chatViewModel: ChatViewModel = viewModel(factory = ChatViewModel.getFactory(LocalContext.current.applicationContext))
    val uiState by chatViewModel.uiState.collectAsState()

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding)
        ) {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(16.dp)
            )

            Row(
                modifier = Modifier.padding(all = 16.dp)
            ) {
                TextField(
                    value = prompt,
                    label = { Text(stringResource(R.string.label_prompt)) },
                    onValueChange = { prompt = it },
                    modifier = Modifier
                        .weight(0.8f)
                        .padding(end = 16.dp)
                        .align(Alignment.CenterVertically)
                )

                if (uiState is UiState.Generating) {
                    Button(
                        onClick = {
                            chatViewModel.stopResponse()
                        },
                        enabled = prompt.isNotEmpty(),
                        modifier = Modifier
                            .align(Alignment.CenterVertically)
                    ) {
                        Text(text = stringResource(R.string.action_stop))
                    }
                } else {
                    Button(
                        onClick = {
                            chatViewModel.resetSession()
                            chatViewModel.sendPrompt(prompt)
                        },
                        enabled = prompt.isNotEmpty(),
                        modifier = Modifier
                            .align(Alignment.CenterVertically)
                    ) {
                        Text(text = stringResource(R.string.action_go))
                    }
                }

            }
            if (uiState is UiState.Loading) {
                CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
            } else {
                var textColor = MaterialTheme.colorScheme.onSurface
                if (uiState is UiState.Error) {
                    textColor = MaterialTheme.colorScheme.error
                    result = (uiState as UiState.Error).errorMessage
                } else if (uiState is UiState.Generating) {
                    textColor = MaterialTheme.colorScheme.onSurface
                    result = (uiState as UiState.Generating).partialResult
                } else if (uiState is UiState.Success) {
                    textColor = MaterialTheme.colorScheme.onSurface
                    result = (uiState as UiState.Success).outputText
                }
                val scrollState = rememberScrollState()
                Text(
                    text = result,
                    textAlign = TextAlign.Start,
                    color = textColor,
                    modifier = Modifier
                        .padding(16.dp)
                        .fillMaxSize()
                        .verticalScroll(scrollState)
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    GemmaAppTextTheme {
        ChatScreen()
    }
}

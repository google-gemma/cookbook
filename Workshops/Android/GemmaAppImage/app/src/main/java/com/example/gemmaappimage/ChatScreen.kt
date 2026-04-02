package com.example.gemmaappimage

import android.graphics.BitmapFactory
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
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
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.gemmaappimage.ui.theme.GemmaAppImageTheme

val images = arrayOf(
    R.drawable.surprise,
    R.drawable.kitchen,
    R.drawable.sunset,
)

val imageDescriptions = arrayOf(
    R.string.surprise_description,
    R.string.kitchen_description,
    R.string.sunset_description,
)

@Composable
fun ChatScreen() {
    val selectedImage = remember { mutableIntStateOf(0) }
    val placeholderPrompt = stringResource(R.string.prompt_placeholder)
    val placeholderResult = stringResource(R.string.result_placeholder)
    var prompt by rememberSaveable { mutableStateOf(placeholderPrompt) }
    var result by rememberSaveable { mutableStateOf(placeholderResult) }
    val context = LocalContext.current.applicationContext

    val chatViewModel: ChatViewModel = viewModel(factory = ChatViewModel.getFactory(context))
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

            LazyRow(
                modifier = Modifier.fillMaxWidth()
            ) {
                itemsIndexed(images) { index, image ->
                    var imageModifier = Modifier
                        .padding(start = 8.dp, end = 8.dp)
                        .requiredSize(200.dp)
                        .clickable {
                            selectedImage.intValue = index
                        }
                    if (index == selectedImage.intValue) {
                        imageModifier =
                            imageModifier.border(
                                BorderStroke(
                                    4.dp,
                                    MaterialTheme.colorScheme.primary
                                )
                            )
                    }
                    Image(
                        painter = painterResource(image),
                        contentDescription = stringResource(imageDescriptions[index]),
                        modifier = imageModifier
                    )
                }
            }
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
                            chatViewModel.stopRespones()
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
                            val bitmap = BitmapFactory.decodeResource(
                                context.resources,
                                images[selectedImage.intValue]
                            )
                            chatViewModel.resetSession()
                            chatViewModel.sendPrompt(bitmap, prompt)
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
    GemmaAppImageTheme {
        ChatScreen()
    }
}

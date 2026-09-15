package ai.leasegate.mobile.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors

/**
 * Full-screen camera overlay that decodes a TOTP QR code with on-device
 * ML Kit. Nothing leaves the process. Completes with the `otpauth://` URI,
 * or null when dismissed/denied.
 */
@androidx.annotation.OptIn(ExperimentalGetImage::class)
@Composable
fun QrScanOverlay(onResult: (String?) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var asked by remember { mutableStateOf(false) }
    var decoding by remember { mutableStateOf(true) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { allowed ->
        granted = allowed
        if (!allowed) onResult(null)
    }

    LaunchedEffect(Unit) {
        if (!granted && !asked) {
            asked = true
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Surface(Modifier.fillMaxSize(), color = Color.Black) {
        Box(Modifier.fillMaxSize()) {
            if (granted) {
                val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
                val scanner = remember { BarcodeScanning.getClient() }
                DisposableEffect(Unit) {
                    onDispose {
                        scanner.close()
                        analysisExecutor.shutdown()
                    }
                }
                AndroidView(
                    factory = { viewContext ->
                        PreviewView(viewContext).apply {
                            val providerFuture = ProcessCameraProvider.getInstance(viewContext)
                            providerFuture.addListener(
                                {
                                    val provider = providerFuture.get()
                                    val preview = Preview.Builder().build().also {
                                        it.surfaceProvider = surfaceProvider
                                    }
                                    val analysis = ImageAnalysis.Builder()
                                        .setBackpressureStrategy(
                                            ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST,
                                        )
                                        .build()
                                    analysis.setAnalyzer(analysisExecutor) { proxy ->
                                        val media = proxy.image
                                        if (media == null || !decoding) {
                                            proxy.close()
                                            return@setAnalyzer
                                        }
                                        val image = InputImage.fromMediaImage(
                                            media,
                                            proxy.imageInfo.rotationDegrees,
                                        )
                                        scanner.process(image)
                                            .addOnSuccessListener { barcodes ->
                                                if (!decoding) return@addOnSuccessListener
                                                for (barcode in barcodes) {
                                                    val raw = barcode.rawValue ?: continue
                                                    if (barcode.format == Barcode.FORMAT_QR_CODE &&
                                                        raw.startsWith("otpauth://")
                                                    ) {
                                                        decoding = false
                                                        onResult(raw)
                                                        return@addOnSuccessListener
                                                    }
                                                }
                                            }
                                            .addOnCompleteListener { proxy.close() }
                                    }
                                    try {
                                        provider.unbindAll()
                                        provider.bindToLifecycle(
                                            lifecycleOwner,
                                            CameraSelector.DEFAULT_BACK_CAMERA,
                                            preview,
                                            analysis,
                                        )
                                    } catch (_: Exception) {
                                        onResult(null)
                                    }
                                },
                                ContextCompat.getMainExecutor(viewContext),
                            )
                        }
                    },
                    modifier = Modifier.fillMaxSize(),
                )
            } else {
                Column(
                    Modifier.fillMaxSize(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Icon(
                        Icons.Filled.QrCodeScanner,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(56.dp),
                    )
                    Text(
                        "Camera access is needed to read a QR code.",
                        color = Color.White,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(24.dp),
                    )
                    if (!asked) CircularProgressIndicator()
                }
            }
            IconButton(
                onClick = { onResult(null) },
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(16.dp),
            ) {
                Icon(Icons.Filled.Close, contentDescription = "Cancel", tint = Color.White)
            }
        }
    }
}

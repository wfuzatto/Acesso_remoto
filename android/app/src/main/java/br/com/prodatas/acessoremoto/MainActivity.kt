package br.com.prodatas.acessoremoto

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import okhttp3.*
import okio.ByteString
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : ComponentActivity() {
    private val client = OkHttpClient()
    private var socket: WebSocket? = null
    private var sessionId: String? = null
    private var pendingPassword: String? = null

    private var status by mutableStateOf("Desconectado")
    private var frame by mutableStateOf<Bitmap?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { RemoteScreen() } }
    }

    @Composable
    private fun RemoteScreen() {
        var relay by remember { mutableStateOf("ws://10.0.2.2:8080") }
        var accessId by remember { mutableStateOf("") }
        var unattended by remember { mutableStateOf(false) }
        var password by remember { mutableStateOf("") }

        Column(Modifier.fillMaxSize()) {
            Column(Modifier.padding(12.dp)) {
                OutlinedTextField(relay, { relay = it }, label = { Text("Servidor relay") }, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Row {
                    OutlinedTextField(
                        accessId,
                        { accessId = it.filter(Char::isDigit).take(9) },
                        label = { Text("ID de acesso") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { connect(relay, accessId, unattended, password); password = "" }) { Text("Conectar") }
                }
                Row(Modifier.padding(top = 6.dp)) {
                    Checkbox(unattended, { unattended = it })
                    Text("Acesso não supervisionado", modifier = Modifier.padding(top = 12.dp))
                }
                if (unattended) {
                    OutlinedTextField(password, { password = it }, label = { Text("Senha") }, modifier = Modifier.fillMaxWidth())
                }
                Text(status, modifier = Modifier.padding(top = 6.dp))
            }

            Box(Modifier.fillMaxSize().background(Color.Black)) {
                val current = frame
                if (current != null) {
                    Image(
                        bitmap = current.asImageBitmap(),
                        contentDescription = "Tela remota",
                        contentScale = ContentScale.Fit,
                        modifier = Modifier.fillMaxSize()
                            .pointerInput(current.width, current.height) {
                                detectTapGestures { p ->
                                    val x = (p.x / size.width).coerceIn(0f, 1f)
                                    val y = (p.y / size.height).coerceIn(0f, 1f)
                                    sendInput("mouseDown", x, y)
                                    sendInput("mouseUp", x, y)
                                }
                            }
                            .pointerInput(current.width, current.height) {
                                detectDragGestures { change, _ ->
                                    val x = (change.position.x / size.width).coerceIn(0f, 1f)
                                    val y = (change.position.y / size.height).coerceIn(0f, 1f)
                                    sendInput("move", x, y)
                                }
                            }
                    )
                }
            }
        }
    }

    private fun connect(relay: String, accessId: String, unattended: Boolean, password: String) {
        if (accessId.length != 9) { status = "ID deve ter 9 dígitos"; return }
        pendingPassword = if (unattended) password else null
        status = "Conectando..."
        socket?.close(1000, "new connection")
        socket = client.newWebSocket(Request.Builder().url(relay).build(), object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                send(JSONObject().put("type", "register.viewer").put("platform", "android").put("name", android.os.Build.MODEL))
                send(JSONObject().put("type", "connection.request").put("accessId", accessId).put("unattended", unattended))
                runOnUiThread { status = if (unattended) "Autenticando..." else "Aguardando aceite..." }
            }

            override fun onMessage(ws: WebSocket, text: String) {
                handleJson(JSONObject(text))
            }

            override fun onMessage(ws: WebSocket, bytes: ByteString) {
                val raw = bytes.toByteArray()
                if (raw.size <= 36) return
                val sid = raw.copyOfRange(0, 36).toString(Charsets.US_ASCII)
                if (sid != sessionId) return
                val bitmap = BitmapFactory.decodeByteArray(raw, 36, raw.size - 36) ?: return
                runOnUiThread { frame = bitmap }
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                runOnUiThread { status = "Falha: ${t.message}" }
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                runOnUiThread { status = "Desconectado"; frame = null }
            }
        })
    }

    private fun handleJson(j: JSONObject) {
        when (j.optString("type")) {
            "connection.pending" -> sessionId = j.optString("sessionId")
            "auth.challenge" -> {
                sessionId = j.optString("sessionId")
                val password = pendingPassword ?: return
                val salt = Base64.getDecoder().decode(j.getString("salt"))
                val nonce = Base64.getDecoder().decode(j.getString("nonce"))
                val iterations = j.getInt("iterations")
                val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
                val verifier = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(verifier, "HmacSHA256"))
                val proof = Base64.getEncoder().encodeToString(mac.doFinal(nonce))
                send(JSONObject().put("type", "auth.response").put("sessionId", sessionId).put("proof", proof))
            }
            "connection.accepted" -> {
                sessionId = j.optString("sessionId")
                pendingPassword = null
                runOnUiThread { status = "Conectado - toque para clicar e arraste para mover" }
            }
            "connection.error" -> runOnUiThread {
                status = when (j.optString("code")) {
                    "HOST_OFFLINE" -> "Computador remoto offline"
                    "HOST_BUSY" -> "Computador remoto ocupado"
                    "AUTH_FAILED" -> "Senha incorreta"
                    else -> "Erro de conexão"
                }
            }
            "session.closed" -> runOnUiThread { sessionId = null; frame = null; status = "Sessão encerrada" }
        }
    }

    private fun sendInput(kind: String, x: Float, y: Float) {
        val sid = sessionId ?: return
        send(JSONObject().put("type", "input").put("sessionId", sid).put("kind", kind).put("x", x).put("y", y).put("button", "left"))
    }

    private fun send(json: JSONObject) { socket?.send(json.toString()) }

    override fun onDestroy() {
        socket?.close(1000, "app closed")
        client.dispatcher.executorService.shutdown()
        super.onDestroy()
    }
}

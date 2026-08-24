using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Imaging;

namespace AcessoRemoto.Viewer;

public partial class MainWindow : Window
{
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private ClientWebSocket? _socket;
    private CancellationTokenSource? _cts;
    private string? _sessionId;
    private string? _passwordForAttempt;
    private long _lastMouseMoveTicks;

    public MainWindow()
    {
        InitializeComponent();
        Closed += (_, _) => _cts?.Cancel();
    }

    private void UnattendedChanged(object sender, RoutedEventArgs e)
        => PasswordBox.IsEnabled = UnattendedCheck.IsChecked == true;

    private async void ConnectClicked(object sender, RoutedEventArgs e)
    {
        var accessId = new string(AccessIdBox.Text.Where(char.IsDigit).ToArray());
        if (accessId.Length != 9)
        {
            MessageBox.Show("Informe o ID de acesso com 9 dígitos.");
            return;
        }

        if (UnattendedCheck.IsChecked == true && string.IsNullOrEmpty(PasswordBox.Password))
        {
            MessageBox.Show("Informe a senha do acesso não supervisionado.");
            return;
        }

        _passwordForAttempt = PasswordBox.Password;
        PasswordBox.Clear();
        await ConnectAndRequestAsync(accessId, UnattendedCheck.IsChecked == true);
    }

    private async Task ConnectAndRequestAsync(string accessId, bool unattended)
    {
        try
        {
            _cts?.Cancel();
            _socket?.Dispose();
            _cts = new CancellationTokenSource();
            _socket = new ClientWebSocket();
            StatusText.Text = "Conectando ao relay...";
            var relay = Environment.GetEnvironmentVariable("ACESSO_REMOTO_RELAY") ?? "ws://127.0.0.1:8080";
            await _socket.ConnectAsync(new Uri(relay), _cts.Token);
            await SendJsonAsync(new { type = "register.viewer", platform = "windows", name = Environment.MachineName });
            _ = ReceiveLoopAsync(_cts.Token);
            await SendJsonAsync(new { type = "connection.request", accessId, unattended });
            StatusText.Text = unattended ? "Autenticando..." : "Aguardando aceite no computador remoto...";
        }
        catch (Exception ex)
        {
            StatusText.Text = "Falha";
            MessageBox.Show(ex.Message, "Acesso Remoto");
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        if (_socket is null) return;
        var buffer = new byte[256 * 1024];
        try
        {
            while (_socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                using var ms = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await _socket.ReceiveAsync(buffer, ct);
                    if (result.MessageType == WebSocketMessageType.Close) return;
                    ms.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);

                if (result.MessageType == WebSocketMessageType.Binary)
                {
                    var packet = ms.ToArray();
                    if (packet.Length > 36)
                    {
                        var sid = Encoding.ASCII.GetString(packet, 0, 36);
                        if (sid == _sessionId) ShowJpeg(packet.AsSpan(36).ToArray());
                    }
                    continue;
                }

                using var doc = JsonDocument.Parse(ms.ToArray());
                await HandleMessageAsync(doc.RootElement.Clone());
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            await Dispatcher.InvokeAsync(() => StatusText.Text = $"Desconectado: {ex.Message}");
        }
    }

    private async Task HandleMessageAsync(JsonElement msg)
    {
        var type = msg.GetProperty("type").GetString();
        switch (type)
        {
            case "connection.pending":
                _sessionId = msg.GetProperty("sessionId").GetString();
                break;

            case "auth.challenge":
                _sessionId = msg.GetProperty("sessionId").GetString();
                await RespondToChallengeAsync(msg);
                break;

            case "connection.accepted":
                _sessionId = msg.GetProperty("sessionId").GetString();
                _passwordForAttempt = null;
                await Dispatcher.InvokeAsync(() =>
                {
                    StatusText.Text = "Conectado - controle remoto ativo";
                    RemoteImage.Focus();
                });
                break;

            case "connection.error":
                var code = msg.TryGetProperty("code", out var c) ? c.GetString() : "ERROR";
                _passwordForAttempt = null;
                await Dispatcher.InvokeAsync(() => StatusText.Text = code switch
                {
                    "HOST_OFFLINE" => "Computador remoto offline",
                    "HOST_BUSY" => "Computador remoto ocupado",
                    "AUTH_FAILED" => "Senha incorreta",
                    _ => $"Erro: {code}"
                });
                break;

            case "session.closed":
                _sessionId = null;
                await Dispatcher.InvokeAsync(() =>
                {
                    StatusText.Text = "Sessão encerrada";
                    RemoteImage.Source = null;
                });
                break;
        }
    }

    private async Task RespondToChallengeAsync(JsonElement msg)
    {
        if (_passwordForAttempt is null || _sessionId is null) return;
        try
        {
            var salt = Convert.FromBase64String(msg.GetProperty("salt").GetString()!);
            var nonce = Convert.FromBase64String(msg.GetProperty("nonce").GetString()!);
            var iterations = msg.GetProperty("iterations").GetInt32();
            var verifier = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(_passwordForAttempt), salt, iterations,
                HashAlgorithmName.SHA256, 32);
            using var hmac = new HMACSHA256(verifier);
            var proof = Convert.ToBase64String(hmac.ComputeHash(nonce));
            await SendJsonAsync(new { type = "auth.response", sessionId = _sessionId, proof });
        }
        catch
        {
            await Dispatcher.InvokeAsync(() => StatusText.Text = "Falha na autenticação");
        }
    }

    private void ShowJpeg(byte[] jpeg)
    {
        Dispatcher.Invoke(() =>
        {
            using var stream = new MemoryStream(jpeg);
            var image = new BitmapImage();
            image.BeginInit();
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.StreamSource = stream;
            image.EndInit();
            image.Freeze();
            RemoteImage.Source = image;
        });
    }

    private async void RemoteMouseMove(object sender, MouseEventArgs e)
    {
        if (_sessionId is null || e.LeftButton != MouseButtonState.Pressed && e.RightButton != MouseButtonState.Pressed) return;
        var now = Environment.TickCount64;
        if (now - _lastMouseMoveTicks < 20) return;
        _lastMouseMoveTicks = now;
        var point = MapPoint(e.GetPosition(RemoteImage));
        if (point is { } p) await SendInputAsync("move", p.x, p.y);
    }

    private async void RemoteMouseDown(object sender, MouseButtonEventArgs e)
    {
        RemoteImage.Focus();
        var point = MapPoint(e.GetPosition(RemoteImage));
        if (point is { } p) await SendInputAsync("mouseDown", p.x, p.y, e.ChangedButton == MouseButton.Right ? "right" : "left");
    }

    private async void RemoteMouseUp(object sender, MouseButtonEventArgs e)
    {
        var point = MapPoint(e.GetPosition(RemoteImage));
        if (point is { } p) await SendInputAsync("mouseUp", p.x, p.y, e.ChangedButton == MouseButton.Right ? "right" : "left");
    }

    private (double x, double y)? MapPoint(Point point)
    {
        if (RemoteImage.Source is not BitmapSource source || RemoteImage.ActualWidth <= 0 || RemoteImage.ActualHeight <= 0) return null;
        var sourceRatio = source.PixelWidth / (double)source.PixelHeight;
        var controlRatio = RemoteImage.ActualWidth / RemoteImage.ActualHeight;
        double renderWidth, renderHeight, offsetX, offsetY;
        if (sourceRatio > controlRatio)
        {
            renderWidth = RemoteImage.ActualWidth;
            renderHeight = renderWidth / sourceRatio;
            offsetX = 0;
            offsetY = (RemoteImage.ActualHeight - renderHeight) / 2;
        }
        else
        {
            renderHeight = RemoteImage.ActualHeight;
            renderWidth = renderHeight * sourceRatio;
            offsetX = (RemoteImage.ActualWidth - renderWidth) / 2;
            offsetY = 0;
        }
        var x = (point.X - offsetX) / renderWidth;
        var y = (point.Y - offsetY) / renderHeight;
        if (x < 0 || x > 1 || y < 0 || y > 1) return null;
        return (x, y);
    }

    private async void WindowKeyDown(object sender, KeyEventArgs e)
    {
        if (_sessionId is null || !RemoteImage.IsKeyboardFocusWithin) return;
        var vk = KeyInterop.VirtualKeyFromKey(e.Key == Key.System ? e.SystemKey : e.Key);
        if (vk > 0) await SendJsonAsync(new { type = "input", sessionId = _sessionId, kind = "keyDown", key = vk });
        e.Handled = true;
    }

    private async void WindowKeyUp(object sender, KeyEventArgs e)
    {
        if (_sessionId is null || !RemoteImage.IsKeyboardFocusWithin) return;
        var vk = KeyInterop.VirtualKeyFromKey(e.Key == Key.System ? e.SystemKey : e.Key);
        if (vk > 0) await SendJsonAsync(new { type = "input", sessionId = _sessionId, kind = "keyUp", key = vk });
        e.Handled = true;
    }

    private Task SendInputAsync(string kind, double x, double y, string? button = null)
        => SendJsonAsync(new { type = "input", sessionId = _sessionId, kind, x, y, button });

    private async Task SendJsonAsync(object value)
    {
        if (_socket?.State != WebSocketState.Open) return;
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value));
        await _sendLock.WaitAsync();
        try { await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None); }
        finally { _sendLock.Release(); }
    }
}

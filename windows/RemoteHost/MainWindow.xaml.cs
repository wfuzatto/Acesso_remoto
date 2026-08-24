using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;

namespace AcessoRemoto.Host;

public partial class MainWindow : Window
{
    private readonly string _configPath;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private ClientWebSocket? _socket;
    private CancellationTokenSource? _connectionCts;
    private HostConfig _config;
    private string? _activeSessionId;
    private string? _pendingNonce;
    private int _failedAuthAttempts;

    public MainWindow()
    {
        InitializeComponent();
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AcessoRemoto");
        Directory.CreateDirectory(dir);
        _configPath = Path.Combine(dir, "host.json");
        _config = LoadConfig();
        RelayUrlBox.Text = _config.RelayUrl;
        UnattendedCheck.IsChecked = _config.UnattendedEnabled;
        UnattendedPasswordBox.IsEnabled = _config.UnattendedEnabled;
        Loaded += async (_, _) => await ConnectAsync();
        Closed += (_, _) => _connectionCts?.Cancel();
    }

    private HostConfig LoadConfig()
    {
        try
        {
            if (File.Exists(_configPath))
                return JsonSerializer.Deserialize<HostConfig>(File.ReadAllText(_configPath)) ?? HostConfig.CreateDefault();
        }
        catch { }
        return HostConfig.CreateDefault();
    }

    private void UnattendedChanged(object sender, RoutedEventArgs e)
        => UnattendedPasswordBox.IsEnabled = UnattendedCheck.IsChecked == true;

    private async void ConnectClicked(object sender, RoutedEventArgs e) => await ConnectAsync();

    private void SaveClicked(object sender, RoutedEventArgs e)
    {
        _config.RelayUrl = RelayUrlBox.Text.Trim();
        _config.UnattendedEnabled = UnattendedCheck.IsChecked == true;

        if (_config.UnattendedEnabled && !string.IsNullOrWhiteSpace(UnattendedPasswordBox.Password))
        {
            var salt = RandomNumberGenerator.GetBytes(32);
            const int iterations = 310_000;
            var verifier = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(UnattendedPasswordBox.Password), salt, iterations,
                HashAlgorithmName.SHA256, 32);
            _config.PasswordSalt = Convert.ToBase64String(salt);
            _config.PasswordVerifier = Convert.ToBase64String(verifier);
            _config.PasswordIterations = iterations;
            UnattendedPasswordBox.Clear();
        }

        if (_config.UnattendedEnabled && string.IsNullOrEmpty(_config.PasswordVerifier))
        {
            MessageBox.Show("Defina uma senha antes de habilitar acesso não supervisionado.", "Acesso Remoto");
            return;
        }

        File.WriteAllText(_configPath, JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true }));
        MessageBox.Show("Configurações salvas.", "Acesso Remoto");
    }

    private async Task ConnectAsync()
    {
        try
        {
            _connectionCts?.Cancel();
            _socket?.Dispose();
            _connectionCts = new CancellationTokenSource();
            _socket = new ClientWebSocket();
            ConnectionStatusText.Text = "Conectando...";
            var uri = new Uri(RelayUrlBox.Text.Trim());
            await _socket.ConnectAsync(uri, _connectionCts.Token);
            ConnectionStatusText.Text = "Conectado ao relay";
            await SendJsonAsync(new
            {
                type = "register.host",
                deviceId = _config.DeviceId,
                platform = "windows",
                name = Environment.MachineName
            });
            _ = ReceiveLoopAsync(_connectionCts.Token);
        }
        catch (Exception ex)
        {
            ConnectionStatusText.Text = "Falha ao conectar";
            MessageBox.Show(ex.Message, "Falha de conexão");
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        if (_socket is null) return;
        var buffer = new byte[1024 * 256];
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

                if (result.MessageType != WebSocketMessageType.Text) continue;
                using var doc = JsonDocument.Parse(ms.ToArray());
                await HandleMessageAsync(doc.RootElement.Clone());
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            await Dispatcher.InvokeAsync(() => ConnectionStatusText.Text = $"Conexão encerrada: {ex.Message}");
        }
    }

    private async Task HandleMessageAsync(JsonElement msg)
    {
        var type = msg.GetProperty("type").GetString();
        switch (type)
        {
            case "registered":
                var accessId = msg.GetProperty("accessId").GetString() ?? "";
                await Dispatcher.InvokeAsync(() => AccessIdText.Text = FormatAccessId(accessId));
                break;

            case "connection.request":
                await HandleConnectionRequestAsync(msg);
                break;

            case "auth.response":
                await HandleAuthResponseAsync(msg);
                break;

            case "session.authorized":
                _activeSessionId = msg.GetProperty("sessionId").GetString();
                _failedAuthAttempts = 0;
                await Dispatcher.InvokeAsync(() => SessionBanner.Visibility = Visibility.Visible);
                if (_activeSessionId is not null) _ = ScreenLoopAsync(_activeSessionId, _connectionCts?.Token ?? CancellationToken.None);
                break;

            case "input":
                if (_activeSessionId == msg.GetProperty("sessionId").GetString()) ApplyInput(msg);
                break;

            case "session.closed":
                _activeSessionId = null;
                await Dispatcher.InvokeAsync(() => SessionBanner.Visibility = Visibility.Collapsed);
                break;
        }
    }

    private async Task HandleConnectionRequestAsync(JsonElement msg)
    {
        var sessionId = msg.GetProperty("sessionId").GetString()!;
        var unattended = msg.TryGetProperty("unattended", out var u) && u.GetBoolean();
        var viewerName = "Dispositivo remoto";
        var viewerPlatform = "desconhecido";
        if (msg.TryGetProperty("viewer", out var viewer))
        {
            if (viewer.TryGetProperty("name", out var n)) viewerName = n.GetString() ?? viewerName;
            if (viewer.TryGetProperty("platform", out var p)) viewerPlatform = p.GetString() ?? viewerPlatform;
        }

        if (unattended)
        {
            if (!_config.UnattendedEnabled || string.IsNullOrEmpty(_config.PasswordVerifier) || _failedAuthAttempts >= 5)
            {
                await SendJsonAsync(new { type = "connection.reject", sessionId });
                return;
            }

            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            _pendingNonce = nonce;
            await SendJsonAsync(new
            {
                type = "auth.challenge", sessionId,
                salt = _config.PasswordSalt,
                iterations = _config.PasswordIterations,
                nonce
            });
            return;
        }

        var accepted = false;
        await Dispatcher.InvokeAsync(() =>
        {
            var result = MessageBox.Show(
                $"{viewerName} ({viewerPlatform}) quer controlar este computador.\n\nDeseja permitir a conexão?",
                "Solicitação de acesso remoto", MessageBoxButton.YesNo, MessageBoxImage.Question);
            accepted = result == MessageBoxResult.Yes;
        });

        await SendJsonAsync(new { type = accepted ? "connection.accept" : "connection.reject", sessionId });
    }

    private async Task HandleAuthResponseAsync(JsonElement msg)
    {
        var sessionId = msg.GetProperty("sessionId").GetString()!;
        var proofText = msg.GetProperty("proof").GetString() ?? "";
        var ok = false;
        try
        {
            if (_pendingNonce is not null && _config.PasswordVerifier is not null)
            {
                var verifier = Convert.FromBase64String(_config.PasswordVerifier);
                var nonce = Convert.FromBase64String(_pendingNonce);
                using var hmac = new HMACSHA256(verifier);
                var expected = hmac.ComputeHash(nonce);
                var provided = Convert.FromBase64String(proofText);
                ok = expected.Length == provided.Length && CryptographicOperations.FixedTimeEquals(expected, provided);
            }
        }
        catch { ok = false; }

        _pendingNonce = null;
        if (!ok) _failedAuthAttempts++;
        await SendJsonAsync(new { type = "auth.result", sessionId, ok });
    }

    private async Task ScreenLoopAsync(string sessionId, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _activeSessionId == sessionId && _socket?.State == WebSocketState.Open)
        {
            try
            {
                var jpeg = CapturePrimaryScreen();
                var prefix = Encoding.ASCII.GetBytes(sessionId);
                var packet = new byte[prefix.Length + jpeg.Length];
                Buffer.BlockCopy(prefix, 0, packet, 0, prefix.Length);
                Buffer.BlockCopy(jpeg, 0, packet, prefix.Length, jpeg.Length);
                await SendBinaryAsync(packet, ct);
                await Task.Delay(100, ct);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(500, ct); }
        }
    }

    private static byte[] CapturePrimaryScreen()
    {
        var bounds = System.Windows.Forms.Screen.PrimaryScreen?.Bounds ?? new Rectangle(0, 0, 1280, 720);
        using var original = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format24bppRgb);
        using (var g = Graphics.FromImage(original)) g.CopyFromScreen(bounds.Left, bounds.Top, 0, 0, bounds.Size);

        var width = Math.Min(1280, original.Width);
        var height = (int)Math.Round(original.Height * (width / (double)original.Width));
        using var scaled = new Bitmap(width, height, PixelFormat.Format24bppRgb);
        using (var g = Graphics.FromImage(scaled)) g.DrawImage(original, 0, 0, width, height);
        using var ms = new MemoryStream();
        var encoder = ImageCodecInfo.GetImageEncoders().First(e => e.FormatID == ImageFormat.Jpeg.Guid);
        using var ep = new EncoderParameters(1);
        ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 65L);
        scaled.Save(ms, encoder, ep);
        return ms.ToArray();
    }

    private void ApplyInput(JsonElement msg)
    {
        if (!msg.TryGetProperty("kind", out var kindElement)) return;
        var kind = kindElement.GetString();
        if (kind is "move" or "mouseDown" or "mouseUp")
        {
            var x = Math.Clamp(msg.GetProperty("x").GetDouble(), 0, 1);
            var y = Math.Clamp(msg.GetProperty("y").GetDouble(), 0, 1);
            var screen = System.Windows.Forms.Screen.PrimaryScreen?.Bounds ?? new Rectangle(0, 0, 1920, 1080);
            SetCursorPos(screen.Left + (int)(x * (screen.Width - 1)), screen.Top + (int)(y * (screen.Height - 1)));
            if (kind != "move")
            {
                var button = msg.TryGetProperty("button", out var b) ? b.GetString() : "left";
                var flag = (button, kind) switch
                {
                    ("right", "mouseDown") => 0x0008u,
                    ("right", "mouseUp") => 0x0010u,
                    (_, "mouseDown") => 0x0002u,
                    _ => 0x0004u
                };
                mouse_event(flag, 0, 0, 0, UIntPtr.Zero);
            }
        }
        else if (kind is "keyDown" or "keyUp")
        {
            var vk = (byte)Math.Clamp(msg.GetProperty("key").GetInt32(), 0, 255);
            keybd_event(vk, 0, kind == "keyUp" ? 0x0002u : 0u, UIntPtr.Zero);
        }
    }

    private async Task SendJsonAsync(object value)
    {
        if (_socket?.State != WebSocketState.Open) return;
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value));
        await _sendLock.WaitAsync();
        try { await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None); }
        finally { _sendLock.Release(); }
    }

    private async Task SendBinaryAsync(byte[] bytes, CancellationToken ct)
    {
        if (_socket?.State != WebSocketState.Open) return;
        await _sendLock.WaitAsync(ct);
        try { await _socket.SendAsync(bytes, WebSocketMessageType.Binary, true, ct); }
        finally { _sendLock.Release(); }
    }

    private async void DisconnectSessionClicked(object sender, RoutedEventArgs e)
    {
        if (_activeSessionId is { } id) await SendJsonAsync(new { type = "session.close", sessionId = id });
        _activeSessionId = null;
        SessionBanner.Visibility = Visibility.Collapsed;
    }

    private static string FormatAccessId(string value)
        => value.Length == 9 ? $"{value[..3]} {value[3..6]} {value[6..]}" : value;

    [DllImport("user32.dll")] private static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] private static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
}

public sealed class HostConfig
{
    public string DeviceId { get; set; } = Guid.NewGuid().ToString("N");
    public string RelayUrl { get; set; } = "ws://127.0.0.1:8080";
    public bool UnattendedEnabled { get; set; }
    public string? PasswordSalt { get; set; }
    public string? PasswordVerifier { get; set; }
    public int PasswordIterations { get; set; } = 310_000;
    public static HostConfig CreateDefault() => new();
}

// 1.24 local plaza server for 5.188.32.116 (C# 5; compiled with RFHandshakeProbe.cs).
//
// Evidence: every local run's client log has "ProudManager.cpp(98): P2P Connected : <n>"
// right after login, and rf-boss-baseline shows the client opening TCP 5.188.32.116:33343
// 13 s after login and keeping it for the whole session. v1.23 did not redirect .116, so that
// connection reached the live official server. 1.24 owns .116 locally and answers only the
// core handshake observed in rf-boss-baseline (rf_proudnet_frames.py, rf_proudnet_handshake.py):
//
//   frame = 13 57 | scalar size (prefix 1/2/4 + LE int) | payload; payload[0] = opcode
//   C 2E                      -> S policy XML (NUL-terminated) + S 04 hint (38 settings bytes
//                                exactly as captured + byte array with OUR RSA-1024 public key)
//   C 05 (encrypted keys)     -> S 06            (we decrypt with our private key and record it)
//   C 07 (protocol GUID/ver)  -> S 0A host ID, new server GUID, empty byte array, the client's
//                                address as seen (ANSI string + LE16 port)
//   C 1A ping (2 doubles)     -> S 1C (client's first double + our time in seconds)
//   C 01 RMI 0xFA01 (3 s)     -> S 01 RMI 0xFBFC  (200/212 pairs in the capture)
//   C 1B, C 01 RMI 0xFA13     -> nothing (no reply in the capture)
// Everything else (game RMIs, relays, UDP hole punching) is recorded and NOT answered.
//
// TCP 3416 and UDP 34162 on .116 are recorded only (their bytes are opaque/unknown).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace RFLocalHandshake
{
    public sealed class PlazaServer
    {
        public const string PlazaAddress = "5.188.32.116";
        public const int PlazaPort = 33343;
        private const int MaxPayload = 1 << 20;       // bounded buffer per frame
        private const int FrameBudgetMs = 5000;       // an incomplete frame must finish in 5 s
        private static readonly byte[] Magic = { 0x13, 0x57 };
        private static readonly byte[] PolicyXml = Encoding.ASCII.GetBytes(
            "<?xml version=\"1.0\"?><cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\" /></cross-domain-policy>\0");
        // 38 settings bytes of the captured 04 hint (server configuration, no key material),
        // generated from rf-boss-baseline bytes 1..38 (1.25: v1.24 had a hand-copied version with two
        // zero bytes inserted before the 10.0 double and two dropped at the end, so every setting
        // after byte 12 was misaligned; the v1.24 client closed 55 ms after receiving that hint).
        private static readonly byte[] HintSettings = {
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x40, 0x00, 0x00,
            0x3c, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        private readonly object gate = new object();
        private readonly IPAddress bindAddress;
        private readonly int port;
        private readonly string expectedClientSha256;   // null = no peer check (offline tests only)
        private readonly RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
        private readonly byte[] publicKeyDer;
        private readonly Stopwatch clock = Stopwatch.StartNew();
        private TcpListener listener;
        private Thread acceptThread;
        private volatile bool stop;
        private bool stopped;
        private int nextHostId = 3;   // the capture's first client host ID was 3
        private int connectionNumber;
        private readonly List<Socket> open = new List<Socket>();
        private readonly List<string> lines = new List<string>();
        private int endedConnections;
        public string LogPath { get; set; }

        public PlazaServer(IPAddress bindAddress, int port, string expectedClientSha256)
        {
            this.bindAddress = bindAddress;
            this.port = port;
            this.expectedClientSha256 = expectedClientSha256;
            publicKeyDer = EncodePublicKey(rsa.ExportParameters(false));
        }

        public bool Ready { get; private set; }
        public int LocalPort { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
        public int EndedConnections { get { lock (gate) { return endedConnections; } } }
        // Connections that reached 0A ConnectSuccess (the client may then log "P2P Connected").
        public int ConnectSuccessCount { get { lock (gate) { return connectSuccessCount; } } }
        private int connectSuccessCount;
        public byte[] HintPayload() { return Hint(); }
        public string[] Lines { get { lock (gate) { return lines.ToArray(); } } }
        public byte[] PublicKeyDer { get { return (byte[])publicKeyDer.Clone(); } }

        // PKCS#1 RSAPublicKey DER, 140 bytes for a 1024-bit modulus with e = 65537 (captured size).
        private static byte[] EncodePublicKey(RSAParameters p)
        {
            if (p.Modulus.Length != 128 || p.Modulus[0] < 0x80 || p.Exponent.Length != 3) throw new InvalidOperationException("rsa_shape");
            List<byte> der = new List<byte> { 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00 };
            der.AddRange(p.Modulus);
            der.AddRange(new byte[] { 0x02, 0x03 });
            der.AddRange(p.Exponent);
            return der.ToArray();
        }

        public void Start()
        {
            listener = new TcpListener(bindAddress, port);
            listener.Server.ExclusiveAddressUse = true;
            listener.Start();
            acceptThread = new Thread(AcceptLoop) { IsBackground = true, Name = "rf-plaza-accept" };
            acceptThread.Start();
            Ready = true;
        }

        public void Stop(string reason)
        {
            lock (gate) { if (stopped) return; stopped = true; }
            stop = true;
            try { if (listener != null) listener.Stop(); } catch (Exception) { }
            lock (gate) { foreach (Socket s in open) { try { s.Close(); } catch (Exception) { } } }
            if (acceptThread != null && acceptThread != Thread.CurrentThread) acceptThread.Join(3000);
            Ready = false;
            Log("{\"event\":\"plaza_shutdown\",\"utc\":\"" + DateTime.UtcNow.ToString("o") + "\",\"reason\":\"" + Clean(reason) + "\",\"connections\":" + EndedConnections + "}", false);
        }

        private void AcceptLoop()
        {
            while (!stop)
            {
                Socket socket;
                try { socket = listener.AcceptSocket(); }
                catch (Exception) { if (stop) return; continue; }
                Thread t = new Thread(() => Serve(socket)) { IsBackground = true, Name = "rf-plaza-conn" };
                t.Start();
            }
        }

        private void Log(string line, bool connectionLine)
        {
            lock (gate)
            {
                if (connectionLine) { endedConnections++; lines.Add(line); if (lines.Count > 500) lines.RemoveAt(0); }
                if (string.IsNullOrEmpty(LogPath)) return;
                try { File.AppendAllText(LogPath, line + Environment.NewLine, new UTF8Encoding(false)); } catch (Exception) { }
            }
        }

        private static string Clean(string s)
        {
            StringBuilder t = new StringBuilder();
            foreach (char c in s ?? "") t.Append(char.IsLetterOrDigit(c) || c == '_' || c == '/' || c == ':' || c == '=' || c == ',' || c == '.' ? c : '_');
            return t.ToString();
        }

        // One client connection (each with its own framing, host ID and counters).
        private void Serve(Socket socket)
        {
            int number;
            lock (gate) { number = ++connectionNumber; open.Add(socket); }
            Stopwatch watch = Stopwatch.StartNew();
            string end = "client_closed";
            string peer = "not_checked";
            int hostId = 0;
            string rsaResult = "not_received";
            Dictionary<string, int> counts = new Dictionary<string, int>();
            string firstUnanswered = "";
            int unanswered = 0, replies = 0;
            // 1.25 stage timeline (ms since accept, -1 = not reached) and the last server frame.
            long hintAt = -1, keyAt = -1, keyAckAt = -1, requestAt = -1, successAt = -1, activeAt = -1, lastReplyAt = -1;
            string lastSent = "none";
            string acceptedUtc = DateTime.UtcNow.ToString("o");
            try
            {
                socket.NoDelay = true;
                if (expectedClientSha256 != null)
                {
                    peer = PeerCheck.Describe((IPEndPoint)socket.LocalEndPoint, (IPEndPoint)socket.RemoteEndPoint, expectedClientSha256);
                    if (peer != "game_verified") { end = "peer_refused"; return; }
                }
                NetworkStream stream = new NetworkStream(socket, false);
                stream.WriteTimeout = 2000;
                while (!stop)
                {
                    byte[] payload = ReadFrame(socket, stream);
                    if (payload == null) { end = "client_closed"; break; }
                    if (payload.Length == 0) { end = "empty_frame"; break; }
                    int op = payload[0];
                    string key = op == 0x01 && payload.Length >= 3 ? "rmi_" + (payload[1] | (payload[2] << 8)).ToString("x4") : "op_" + op.ToString("x2");
                    int seen; counts.TryGetValue(key, out seen); counts[key] = seen + 1;
                    byte[] reply = null;
                    bool extra = false;
                    if (successAt >= 0 && activeAt < 0) activeAt = watch.ElapsedMilliseconds;
                    if (op == 0x2e) { Send(stream, PolicyXml, false); reply = Hint(); hintAt = watch.ElapsedMilliseconds; }
                    else if (op == 0x05) { keyAt = watch.ElapsedMilliseconds; rsaResult = TryDecryptSessionKey(payload); reply = new byte[] { 0x06 }; keyAckAt = keyAt; }
                    else if (op == 0x07)
                    {
                        requestAt = watch.ElapsedMilliseconds;
                        lock (gate) { hostId = nextHostId++; }
                        reply = ConnectSuccess(hostId, (IPEndPoint)socket.RemoteEndPoint);
                        successAt = watch.ElapsedMilliseconds;
                        lock (gate) { connectSuccessCount++; }
                        Log("{\"event\":\"plaza_connect_success\",\"connection\":" + number + ",\"utc\":\"" + DateTime.UtcNow.ToString("o") + "\",\"host_id\":" + hostId + ",\"session_key\":\"" + Clean(rsaResult) + "\"}", false);
                    }
                    else if (op == 0x1a && payload.Length == 17)
                    {
                        reply = new byte[17];
                        reply[0] = 0x1c;
                        Array.Copy(payload, 1, reply, 1, 8);
                        Array.Copy(BitConverter.GetBytes(clock.Elapsed.TotalSeconds), 0, reply, 9, 8);
                    }
                    else if (key == "rmi_fa01") reply = new byte[] { 0x01, 0xfc, 0xfb };
                    else if (op == 0x1b || key == "rmi_fa13") extra = true;   // observed without reply
                    if (reply != null) { Send(stream, reply, true); replies++; lastReplyAt = watch.ElapsedMilliseconds; lastSent = "op_" + reply[0].ToString("x2"); }
                    else if (!extra)
                    {
                        unanswered++;
                        if (firstUnanswered.Length == 0) firstUnanswered = key + "/len" + payload.Length;
                    }
                }
                if (stop) end = "server_stopped";
            }
            catch (IOException) { end = stop ? "server_stopped" : "client_reset_or_timeout"; }
            catch (SocketException) { end = stop ? "server_stopped" : "client_reset"; }
            catch (ObjectDisposedException) { end = "server_stopped"; }
            catch (InvalidDataException ex) { end = Clean(ex.Message); }
            finally
            {
                lock (gate) { open.Remove(socket); }
                try { socket.Close(); } catch (Exception) { }
                List<string> countText = new List<string>();
                foreach (KeyValuePair<string, int> pair in counts) countText.Add("\"" + pair.Key + "=" + pair.Value + "\"");
                countText.Sort(StringComparer.Ordinal);
                Log("{\"event\":\"plaza_connection_end\",\"connection\":" + number + ",\"ended_utc\":\"" + DateTime.UtcNow.ToString("o") +
                    "\",\"duration_ms\":" + watch.ElapsedMilliseconds + ",\"end_reason\":\"" + Clean(end) + "\",\"peer\":\"" + Clean(peer) +
                    "\",\"host_id\":" + hostId + ",\"session_key\":\"" + Clean(rsaResult) + "\",\"replies\":" + replies +
                    ",\"accepted_utc\":\"" + acceptedUtc + "\",\"stage\":\"" + (activeAt >= 0 ? "client_active_after_connect_success" :
                        successAt >= 0 ? "connect_success_sent" : keyAt >= 0 ? "session_key_acked" : hintAt >= 0 ? "hint_sent" : "accepted") +
                    "\",\"t_hint_ms\":" + hintAt + ",\"t_key_ms\":" + keyAt + ",\"t_key_ack_ms\":" + keyAckAt + ",\"t_request_ms\":" + requestAt +
                    ",\"t_connect_success_ms\":" + successAt + ",\"t_first_activity_after_success_ms\":" + activeAt +
                    ",\"last_server_frame\":\"" + lastSent + "\",\"ms_from_last_reply_to_end\":" + (lastReplyAt < 0 ? -1 : watch.ElapsedMilliseconds - lastReplyAt) +
                    ",\"unanswered\":" + unanswered + ",\"first_unanswered\":\"" + Clean(firstUnanswered) + "\",\"counts\":[" +
                    string.Join(",", countText) + "]}", true);
            }
        }

        // Reads one frame; null at a clean close before a frame starts. Idle never expires;
        // a started frame must complete within FrameBudgetMs.
        private byte[] ReadFrame(Socket socket, NetworkStream stream)
        {
            while (!socket.Poll(1000000, SelectMode.SelectRead)) { if (stop) throw new ObjectDisposedException("plaza"); }
            Stopwatch frame = Stopwatch.StartNew();
            byte[] head = new byte[3];
            if (!ReadExact(stream, head, 0, 1, frame, true)) return null;
            ReadExact(stream, head, 1, 2, frame, false);
            if (head[0] != Magic[0] || head[1] != Magic[1]) throw new InvalidDataException("bad_magic");
            int width = head[2];
            if (width != 1 && width != 2 && width != 4) throw new InvalidDataException("bad_size_prefix");
            byte[] sizeBytes = new byte[4];
            ReadExact(stream, sizeBytes, 0, width, frame, false);
            long size = BitConverter.ToUInt32(sizeBytes, 0);
            if (size > MaxPayload) throw new InvalidDataException("frame_too_large");
            byte[] payload = new byte[size];
            ReadExact(stream, payload, 0, payload.Length, frame, false);
            return payload;
        }

        private bool ReadExact(NetworkStream stream, byte[] buffer, int offset, int count, Stopwatch frame, bool allowCleanClose)
        {
            int done = 0;
            while (done < count)
            {
                int left = FrameBudgetMs - (int)frame.ElapsedMilliseconds;
                if (left <= 0) throw new InvalidDataException("incomplete_frame_timeout");
                stream.ReadTimeout = left;
                int n;
                try { n = stream.Read(buffer, offset + done, count - done); }
                catch (IOException ex)
                {
                    SocketException inner = ex.InnerException as SocketException;
                    if (inner != null && inner.SocketErrorCode == SocketError.TimedOut) throw new InvalidDataException("incomplete_frame_timeout");
                    throw;
                }
                if (n == 0)
                {
                    if (allowCleanClose && done == 0) return false;
                    throw new InvalidDataException("closed_mid_frame");
                }
                done += n;
            }
            return true;
        }

        private static void Send(NetworkStream stream, byte[] payload, bool framed)
        {
            if (!framed) { stream.Write(payload, 0, payload.Length); return; }
            byte[] frame = Frame(payload);
            stream.Write(frame, 0, frame.Length);
        }

        public static byte[] Frame(byte[] payload)
        {
            List<byte> f = new List<byte>(payload.Length + 7) { 0x13, 0x57 };
            if (payload.Length < 0x80) { f.Add(1); f.Add((byte)payload.Length); }
            else if (payload.Length < 0x8000) { f.Add(2); f.Add((byte)payload.Length); f.Add((byte)(payload.Length >> 8)); }
            else { f.Add(4); f.AddRange(BitConverter.GetBytes(payload.Length)); }
            f.AddRange(payload);
            return f.ToArray();
        }

        private byte[] Hint()
        {
            List<byte> p = new List<byte> { 0x04 };
            p.AddRange(HintSettings);
            p.Add(2); p.Add((byte)publicKeyDer.Length); p.Add((byte)(publicKeyDer.Length >> 8));
            p.AddRange(publicKeyDer);
            return p.ToArray();   // 182 bytes, as captured
        }

        // 05 = byte array (scalar length) holding the RSA-encrypted session key, then a second
        // byte array (16 bytes in the capture). Only the outcome is recorded, never key bytes.
        private string TryDecryptSessionKey(byte[] payload)
        {
            try
            {
                int at = 1;
                int width = payload[at++];
                if (width != 2 && width != 1) return "unexpected_layout";
                int length = width == 2 ? payload[at] | (payload[at + 1] << 8) : payload[at];
                at += width;
                if (length != 128 || at + length > payload.Length) return "unexpected_length_" + length;
                byte[] cipher = new byte[128];
                Array.Copy(payload, at, cipher, 0, 128);
                byte[] reversed = (byte[])cipher.Clone();
                Array.Reverse(reversed);
                string[] names = { "pkcs1", "pkcs1_reversed", "oaep", "oaep_reversed" };
                byte[][] inputs = { cipher, reversed, cipher, reversed };
                for (int n = 0; n < 4; n++)
                {
                    try
                    {
                        byte[] key = rsa.Decrypt(inputs[n], n >= 2);
                        int keyLength = key.Length;
                        Array.Clear(key, 0, key.Length);
                        return "decrypted_" + names[n] + "_" + keyLength + "_bytes";
                    }
                    catch (CryptographicException) { }
                }
                return "decrypt_failed";
            }
            catch (Exception) { return "parse_failed"; }
        }

        private static byte[] ConnectSuccess(int hostId, IPEndPoint client)
        {
            List<byte> p = new List<byte> { 0x0a };
            p.AddRange(BitConverter.GetBytes(hostId));
            p.AddRange(Guid.NewGuid().ToByteArray());
            p.Add(1); p.Add(0);                                   // empty byte array (as captured)
            byte[] ip = Encoding.ASCII.GetBytes(client.Address.ToString());
            p.Add(1); p.Add(1); p.Add((byte)ip.Length);           // ANSI string, 1-byte length
            p.AddRange(ip);
            p.Add((byte)client.Port); p.Add((byte)(client.Port >> 8));
            return p.ToArray();
        }
    }

    public static class PlazaSelfTest
    {
        private static void Expect(bool ok, string name, List<string> passed)
        {
            if (!ok) throw new InvalidOperationException("plaza_selftest_failed: " + name);
            passed.Add(name);
        }

        private static byte[] ReadFrame(NetworkStream s)
        {
            byte[] head = ReadN(s, 3);
            if (head[0] != 0x13 || head[1] != 0x57) throw new InvalidOperationException("plaza_selftest_failed: magic");
            byte[] size = new byte[4];
            Array.Copy(ReadN(s, head[2]), size, head[2]);
            return ReadN(s, BitConverter.ToInt32(size, 0));
        }

        private static byte[] ReadN(NetworkStream s, int n)
        {
            byte[] b = new byte[n];
            for (int done = 0; done < n;)
            {
                int r = s.Read(b, done, n - done);
                if (r == 0) throw new IOException("closed");
                done += r;
            }
            return b;
        }

        private static bool ClosedWithin(NetworkStream s, int ms)
        {
            s.ReadTimeout = ms;
            try { return s.Read(new byte[1], 0, 1) == 0; }
            catch (IOException) { return true; }
        }

        public static string Run(string logPath)
        {
            List<string> passed = new List<string>();
            PlazaServer server = new PlazaServer(IPAddress.Loopback, 0, null) { LogPath = logPath };
            server.Start();
            try
            {
                using (TcpClient c = new TcpClient())
                {
                    c.Connect(IPAddress.Loopback, server.LocalPort);
                    NetworkStream s = c.GetStream();
                    s.ReadTimeout = 3000;
                    byte[] policyRequest = PlazaServer.Frame(new byte[] { 0x2e });
                    foreach (byte b in policyRequest) { s.WriteByte(b); Thread.Sleep(20); }   // fragmented
                    byte[] xml = ReadN(s, 110);
                    Expect(Encoding.ASCII.GetString(xml).StartsWith("<?xml") && xml[109] == 0, "policy_xml_after_2e", passed);
                    byte[] hint = ReadFrame(s);
                    Expect(hint.Length == 182 && hint[0] == 0x04 && hint[39] == 2 && hint[40] == 0x8c && hint[42] == 0x30, "hint_182_bytes_with_der_key", passed);
                    RSAParameters p = new RSAParameters();
                    p.Modulus = new byte[128]; Array.Copy(hint, 42 + 7, p.Modulus, 0, 128);
                    p.Exponent = new byte[3]; Array.Copy(hint, 42 + 137, p.Exponent, 0, 3);
                    byte[] sessionKey = new byte[16];
                    using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(sessionKey);
                    byte[] encrypted;
                    using (RSACryptoServiceProvider clientRsa = new RSACryptoServiceProvider()) { clientRsa.ImportParameters(p); encrypted = clientRsa.Encrypt(sessionKey, false); }
                    List<byte> keyMessage = new List<byte> { 0x05, 0x02, 0x80, 0x00 };
                    keyMessage.AddRange(encrypted);
                    keyMessage.AddRange(new byte[] { 0x01, 0x10 }); keyMessage.AddRange(new byte[16]);
                    byte[] versionMessage = { 0x07, 0x01, 0x00, 0x30, 0xae, 0x85, 0x42, 0x65, 0x6e, 0x24, 0x4b, 0xad, 0x6c, 0xc5, 0xd5, 0x09, 0x13, 0x01, 0xca, 0x74, 0x01, 0x03, 0x00 };
                    // Coalesced: key message and version message in one write.
                    List<byte> both = new List<byte>(PlazaServer.Frame(keyMessage.ToArray()));
                    both.AddRange(PlazaServer.Frame(versionMessage));
                    s.Write(both.ToArray(), 0, both.Count);
                    byte[] ok = ReadFrame(s);
                    Expect(ok.Length == 1 && ok[0] == 0x06, "session_key_ack_06", passed);
                    byte[] success = ReadFrame(s);
                    Expect(success[0] == 0x0a && BitConverter.ToInt32(success, 1) == 3 && success.Length == 1 + 4 + 16 + 2 + 3 + 9 + 2 &&
                        Encoding.ASCII.GetString(success, 26, 9) == "127.0.0.1", "connect_success_host3_client_address", passed);
                    byte[] ping = new byte[17]; ping[0] = 0x1a; Array.Copy(BitConverter.GetBytes(1234.5), 0, ping, 1, 8);
                    byte[] heartbeat = { 0x01, 0x01, 0xfa, 0, 0, 0, 0, 0, 0, 0, 0 };
                    List<byte> burst = new List<byte>();
                    foreach (byte[] m in new[] { new byte[] { 0x1b }, new byte[] { 0x01, 0x13, 0xfa, 0, 0, 0, 0 }, new byte[] { 0x01, 0xec, 0x03, 0x32, 0, 0, 0 }, ping, heartbeat })
                        burst.AddRange(PlazaServer.Frame(m));
                    s.Write(burst.ToArray(), 0, burst.Count);
                    byte[] pong = ReadFrame(s);
                    Expect(pong.Length == 17 && pong[0] == 0x1c && BitConverter.ToDouble(pong, 1) == 1234.5, "ping_1a_echoed_in_1c_no_reply_to_1b_fa13_03ec", passed);
                    byte[] beat = ReadFrame(s);
                    Expect(beat.Length == 3 && beat[0] == 1 && beat[1] == 0xfc && beat[2] == 0xfb, "heartbeat_fa01_answered_fbfc", passed);
                    // A second, concurrent connection gets its own host ID.
                    using (TcpClient c2 = new TcpClient())
                    {
                        c2.Connect(IPAddress.Loopback, server.LocalPort);
                        NetworkStream s2 = c2.GetStream(); s2.ReadTimeout = 3000;
                        byte[] v = PlazaServer.Frame(versionMessage);
                        s2.Write(v, 0, v.Length);
                        Expect(BitConverter.ToInt32(ReadFrame(s2), 1) == 4, "second_connection_host4", passed);
                    }
                    // Partial frame: header only, then silence -> closed after the 5 s frame budget.
                    s.Write(new byte[] { 0x13, 0x57, 0x01, 0x10, 0x01 }, 0, 5);
                    Stopwatch w = Stopwatch.StartNew();
                    Expect(ClosedWithin(s, 9000) && w.ElapsedMilliseconds >= 4500, "partial_frame_closed_after_budget", passed);
                }
                using (TcpClient c3 = new TcpClient())
                {
                    c3.Connect(IPAddress.Loopback, server.LocalPort);
                    NetworkStream s3 = c3.GetStream();
                    s3.Write(new byte[] { 0x13, 0x57, 0x04, 0x00, 0x00, 0x20, 0x00 }, 0, 7);   // 2 MB > limit
                    Expect(ClosedWithin(s3, 3000), "oversize_frame_closed", passed);
                }
                using (TcpClient c4 = new TcpClient())
                {
                    c4.Connect(IPAddress.Loopback, server.LocalPort);
                    Thread.Sleep(2500);                                                         // idle is fine
                    NetworkStream s4 = c4.GetStream(); s4.ReadTimeout = 3000;
                    byte[] hb = PlazaServer.Frame(new byte[] { 0x01, 0x01, 0xfa, 0, 0, 0, 0, 0, 0, 0, 0 });
                    s4.Write(hb, 0, hb.Length);
                    Expect(ReadFrame(s4).Length == 3, "idle_connection_still_served", passed);
                }
                Thread.Sleep(500);
            }
            finally { server.Stop("selftest"); }
            string[] lines = File.ReadAllLines(logPath);
            string first = Array.Find(lines, l => l.Contains("plaza_connection_end") && l.Contains("\"connection\":1,"));
            Expect(Array.Exists(lines, l => l.Contains("plaza_connect_success") && l.Contains("\"host_id\":3")), "connect_success_logged_live", passed);
            Expect(first != null && first.Contains("\"stage\":\"client_active_after_connect_success\"") && !first.Contains("\"t_connect_success_ms\":-1") &&
                first.Contains("\"last_server_frame\":\"op_01\""), "stage_timeline_logged", passed);
            Expect(first != null && first.Contains("\"session_key\":\"decrypted_pkcs1_16_bytes\"") && first.Contains("\"host_id\":3") &&
                first.Contains("\"first_unanswered\":\"rmi_03ec/len7\"") && first.Contains("\"unanswered\":1") &&
                first.Contains("\"end_reason\":\"incomplete_frame_timeout\""), "connection_log_line", passed);
            Expect(Array.Exists(lines, l => l.Contains("frame_too_large")) && lines[lines.Length - 1].Contains("plaza_shutdown"), "oversize_and_shutdown_logged", passed);
            return passed.Count + " plaza checks passed: " + string.Join(", ", passed);
        }
    }

    // TCP 3416 / UDP 34162 on .116: accept and count only (no protocol is known for them).
    public sealed class OpaqueRecorder
    {
        private readonly object gate = new object();
        private TcpListener tcp;
        private UdpClient udp;
        private volatile bool stop;
        private bool stopped;
        private readonly List<Socket> open = new List<Socket>();
        public int TcpConnections, TcpBytesIn, UdpDatagrams, UdpBytesIn;
        public string LogPath { get; set; }

        public void Start(IPAddress address, int tcpPort, int udpPort)
        {
            tcp = new TcpListener(address, tcpPort);
            tcp.Server.ExclusiveAddressUse = true;
            tcp.Start();
            new Thread(() =>
            {
                while (!stop)
                {
                    Socket s;
                    try { s = tcp.AcceptSocket(); } catch (Exception) { if (stop) return; continue; }
                    lock (gate) { TcpConnections++; open.Add(s); }
                    new Thread(() => Drain(s)) { IsBackground = true }.Start();
                }
            }) { IsBackground = true, Name = "rf-3416" }.Start();
            udp = new UdpClient(new IPEndPoint(address, udpPort));
            new Thread(() =>
            {
                IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
                while (!stop)
                {
                    try { byte[] d = udp.Receive(ref from); lock (gate) { UdpDatagrams++; UdpBytesIn += d.Length; } }
                    catch (Exception) { if (stop) return; }
                }
            }) { IsBackground = true, Name = "rf-34162" }.Start();
        }

        private void Drain(Socket s)
        {
            byte[] buffer = new byte[4096];
            try { int n; while (!stop && (n = s.Receive(buffer)) > 0) lock (gate) { TcpBytesIn += n; } }
            catch (Exception) { }
            finally { lock (gate) { open.Remove(s); } try { s.Close(); } catch (Exception) { } }
        }

        public void Stop()
        {
            lock (gate) { if (stopped) return; stopped = true; }
            stop = true;
            try { if (tcp != null) tcp.Stop(); } catch (Exception) { }
            try { if (udp != null) udp.Close(); } catch (Exception) { }
            lock (gate) { foreach (Socket s in open) { try { s.Close(); } catch (Exception) { } } }
            if (!string.IsNullOrEmpty(LogPath))
                try
                {
                    File.AppendAllText(LogPath, "{\"event\":\"opaque_ports_summary\",\"tcp3416_connections\":" + TcpConnections +
                        ",\"tcp3416_bytes_in\":" + TcpBytesIn + ",\"udp34162_datagrams\":" + UdpDatagrams + ",\"udp34162_bytes_in\":" + UdpBytesIn + "}" +
                        Environment.NewLine, new UTF8Encoding(false));
                }
                catch (Exception) { }
        }
    }

    // Owning process of a local TCP connection (iphlpapi GetExtendedTcpTable), then name +
    // SHA-256 of its image, so only the exact game build is served.
    public static class PeerCheck
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Row { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid; }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

        public static int OwningPid(IPEndPoint clientLocal, IPEndPoint clientRemote)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);   // TCP_TABLE_OWNER_PID_ALL
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, 2, 5, 0) != 0) return -1;
                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf(typeof(Row));
                for (int n = 0; n < count; n++)
                {
                    Row row = (Row)Marshal.PtrToStructure(new IntPtr(buffer.ToInt64() + 4 + n * rowSize), typeof(Row));
                    int lport = (int)(((row.LocalPort & 0xff) << 8) | ((row.LocalPort >> 8) & 0xff));
                    int rport = (int)(((row.RemotePort & 0xff) << 8) | ((row.RemotePort >> 8) & 0xff));
                    if (new IPAddress(row.LocalAddr).Equals(clientLocal.Address) && lport == clientLocal.Port &&
                        new IPAddress(row.RemoteAddr).Equals(clientRemote.Address) && rport == clientRemote.Port)
                        return (int)row.OwningPid;
                }
                return -1;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        // serverLocal/serverRemote are the server socket's endpoints; the client's row is the mirror.
        public static string Describe(IPEndPoint serverLocal, IPEndPoint serverRemote, string expectedSha256)
        {
            int pid = OwningPid(serverRemote, serverLocal);
            if (pid <= 0) return "owner_not_found";
            try
            {
                using (Process p = Process.GetProcessById(pid))
                {
                    if (!string.Equals(p.ProcessName, "rumblefighter", StringComparison.OrdinalIgnoreCase)) return "not_game_process";
                    string path = p.MainModule.FileName;
                    using (SHA256 sha = SHA256.Create())
                    using (FileStream f = File.OpenRead(path))
                    {
                        string hash = BitConverter.ToString(sha.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
                        return hash == expectedSha256.ToLowerInvariant() ? "game_verified" : "game_hash_mismatch";
                    }
                }
            }
            catch (Exception) { return "owner_unreadable"; }
        }
    }
}

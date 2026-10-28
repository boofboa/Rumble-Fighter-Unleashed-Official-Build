// Original, bounded local compatibility experiment. Not a playable server.
// One initialization frame may be replayed from the user's hash-pinned capture.
// This does not generate or validate fresh GameGuard authentication.
// Built by Windows PowerShell Add-Type; compatible with C# 5 / .NET Framework.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace RFLocalHandshake
{
    public sealed class ProbeHeader
    {
        public int FrameType { get; set; }
        public int Action { get; set; }
        public int TotalBytes { get; set; }
        // 1.13: milliseconds since the probe started listening (see ProbeResult.StartedUtc).
        public int AtMs { get; set; }
        public int ReplyAtMs { get; set; }  // -1 when no reply was written for this header
        public int ReplyBytes { get; set; }
    }

    // 1.19 main-menu fixture: exact server frames from ONE official session
    // (rf-boss-baseline), built by rf_make_lobby_fixture.py into private/fixtures.
    public sealed class LobbyFixture
    {
        public byte[] B3 { get; set; }   // reply to 30/B2 (LoginCheck)
        public byte[] BB { get; set; }   // reply to 30/BA
        public byte[] BD { get; set; }   // reply to 30/BC
        public Dictionary<string, byte[]> Pages { get; set; }  // 30/CC body hex -> 30/CD frame
        public byte[] RewardRecord { get; set; }  // 1.20: 49-byte inventory record, catalog 3043117
    }

    // 1.23 console control handling. Ctrl+C / Ctrl+Break only request a graceful stop (the
    // PowerShell loop then stops the server, writes the report and runs the verified network
    // cleanup). Closing the window (X), logoff or shutdown gives the process ~5 s: the handler
    // stops the server itself (closes sockets, logs server_shutdown) and returns; the separate
    // watchdog process then performs the journal-verified network cleanup.
    public static class ConsoleGuard
    {
        private delegate bool HandlerRoutine(int controlType);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);

        private static HandlerRoutine handler;   // kept referenced so it is never collected
        private static Probe probe;
        private static volatile bool stopRequested;
        private static volatile string stopEvent = "";

        private static PlazaServer plaza;
        private static OpaqueRecorder recorder;

        // 1.24: the plaza listeners are stopped by the close handler too.
        public static void Attach(PlazaServer plazaServer, OpaqueRecorder opaque) { plaza = plazaServer; recorder = opaque; }

        public static bool StopRequested { get { return stopRequested; } }
        public static string StopEvent { get { return stopEvent; } }

        // Installs once; later calls only attach the server the handler should stop.
        public static bool Install(Probe server)
        {
            probe = server;
            if (handler != null) return true;
            // A process started by a parent that ignores Ctrl+C inherits that flag, and its
            // handlers then never see Ctrl+C. Restore normal Ctrl+C processing first.
            SetConsoleCtrlHandler(null, false);
            handler = Handle;
            return SetConsoleCtrlHandler(handler, true);
        }

        public static void Uninstall()
        {
            if (handler != null) SetConsoleCtrlHandler(handler, false);
            handler = null; probe = null;
        }

        // Offline tests call the same code path without a real console event.
        public static bool SimulateForTest(Probe server, int controlType)
        {
            probe = server; stopRequested = false; stopEvent = "";
            return Handle(controlType);
        }

        private static bool Handle(int controlType)
        {
            switch (controlType)
            {
                case 0: stopEvent = "ctrl_c"; stopRequested = true; return true;
                case 1: stopEvent = "ctrl_break"; stopRequested = true; return true;
                case 2: case 5: case 6:
                    stopEvent = controlType == 2 ? "console_close" : controlType == 5 ? "logoff" : "system_shutdown";
                    stopRequested = true;
                    Probe server = probe;
                    if (server != null) { try { server.Stop(stopEvent); } catch (Exception) { } }
                    PlazaServer plazaServer = plaza;
                    if (plazaServer != null) { try { plazaServer.Stop(stopEvent); } catch (Exception) { } }
                    OpaqueRecorder opaque = recorder;
                    if (opaque != null) { try { opaque.Stop(); } catch (Exception) { } }
                    return true;
                default: return false;
            }
        }
    }

    // 1.20 offline end-to-end test stream: serves scripted client bytes in small
    // fragments (to exercise partial reads) and records everything the server writes.
    internal sealed class ScriptedStream : Stream
    {
        private readonly byte[] input;
        private int position;
        public readonly MemoryStream Output = new MemoryStream();
        public ScriptedStream(byte[] input) { this.input = input; }
        public override bool CanRead { get { return true; } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanTimeout { get { return true; } }
        public override int ReadTimeout { get; set; }
        public override int WriteTimeout { get; set; }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int take = Math.Min(Math.Min(count, 7), input.Length - position);  // 7-byte fragments; 0 = closed
            Array.Copy(input, position, buffer, offset, take);
            position += take;
            return take;
        }
        public override void Write(byte[] buffer, int offset, int count) { Output.Write(buffer, offset, count); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
    }

    public sealed class ProbeResult
    {
        public string Status { get; set; }
        public int RequestType { get; set; }
        public int RequestAction { get; set; }
        public int RequestBytes { get; set; }
        public bool HeaderParsed { get; set; }
        public bool PeerAuthorized { get; set; }
        public int AcceptedAfterStartMs { get; set; }
        public int FirstByteAfterAcceptMs { get; set; }
        public int SocketErrorCode { get; set; }
        public int ReplyBytes { get; set; }
        public bool ReplyWritten { get; set; }
        public int LoginRequestType { get; set; }
        public int LoginRequestAction { get; set; }
        public int LoginRequestBytes { get; set; }
        public bool LoginHeaderParsed { get; set; }
        public bool LoginFrameReceived { get; set; }
        public int LoginReplyBytes { get; set; }
        public bool LoginReplyWritten { get; set; }
        public bool LocalFixtureMatched { get; set; }
        public string LoginReplyKind { get; set; }
        public int PostLoginRequestBytes { get; set; }
        public ProbeHeader[] PostLoginHeaders { get; set; }
        public int ClockReplyCount { get; set; }
        public int PostLoginReplyBytes { get; set; }
        public string PostLoginStopReason { get; set; }
        public bool CaptureFixtureLoaded { get; set; }
        public bool GameGuardReplayWritten { get; set; }
        public int GameGuardReplayBytes { get; set; }
        public bool StartupAckWritten { get; set; }
        public int StartupAckBytes { get; set; }
        public bool LocalCashReplyWritten { get; set; }
        public int LocalCashReplyBytes { get; set; }
        public int PropertyRequestCount { get; set; }
        public int PropertyOwnerMatchCount { get; set; }
        public int PropertyReplyCount { get; set; }
        public int PropertyReplyBytes { get; set; }
        public bool GiftFromReplyWritten { get; set; }
        public int GiftFromReplyBytes { get; set; }
        public bool GiftToReplyWritten { get; set; }
        public int GiftToReplyBytes { get; set; }
        public bool BuddyRequestBodyZero { get; set; }
        public bool BuddyReplyWritten { get; set; }
        public int BuddyReplyBytes { get; set; }
        public bool AvatarListReplyWritten { get; set; }
        public bool EquippedAvatarReplyWritten { get; set; }
        public bool AvatarEquipmentReplyWritten { get; set; }
        public bool LoginEmailFieldMatched { get; set; }
        public bool LoginPasswordFieldMatched { get; set; }
        public bool LocalLoginAccepted { get; set; }
        public int AvatarA2AckCount { get; set; }
        public int AvatarA4AckCount { get; set; }
        public int AvatarA6AckCount { get; set; }
        public int AvatarA6TrailingByte { get; set; }
        public string StartedUtc { get; set; }
        public int LoginReplyAtMs { get; set; }
        public int ConnectionEndedAtMs { get; set; }
        public string FixtureKind { get; set; }
        public int GradeReplyCount { get; set; }
        public int B4ReplyCount { get; set; }
        public int GuardAnswerCount { get; set; }
        public int GuardAnswerBytes { get; set; }
        public int GradeUpRequestedId { get; set; }
        public int[] GradeUpRequestedIds { get; set; }
        public string[] AddItemBodies { get; set; }
        public int AddItemFailureReplies { get; set; }
        public int AddItemUnansweredCount { get; set; }
        public int AddItemUnrecognizedFailures { get; set; }
        public string FirstUnansweredRequest { get; set; }
        public int UnansweredRequestCount { get; set; }
        public bool LobbyFixtureLoaded { get; set; }
        public bool LoginCheckReplyWritten { get; set; }
        public int MenuBaReplies { get; set; }
        public int MenuBcReplies { get; set; }
        public int MenuCcReplies { get; set; }
        public string[] MenuCcUnmatchedBodies { get; set; }
        public int LastRequestAtMs { get; set; }
        public int LevelUpGrantFailureReplies { get; set; }
        public int QuestUpdateReplies { get; set; }
        public string[] QuestUpdateBodies { get; set; }
        public int MainMenuEnteredAtMs { get; set; }
        public int SessionNumber { get; set; }
        public int CashReplies { get; set; }
        public int LobbyEnteredAtMs { get; set; }
        public int RoomListReplies { get; set; }
        public int LastRoomListAtMs { get; set; }
        public int B6Replies { get; set; }
        public bool Channel95Claimed { get; set; }
        public bool RewardRecordServed { get; set; }
        public ProbeHeader[] RecentHeaders { get; set; }
        public string[] RequestCounts { get; set; }
        public bool LoginIdEmpty { get; set; }
        public bool LoginIdHasAt { get; set; }
        public bool LoginIdCaseInsensitiveMatch { get; set; }
        public bool LoginIdContainsInvented { get; set; }
        public bool SyntheticSocketCheck { get; set; }
        public string ErrorCode { get; set; }
        // 1.24 account-backed lobby actions.
        public string AccountSource { get; set; }
        public int UserInfoReplies { get; set; }
        public int ItemCheckReplies { get; set; }
        public int ItemCheckEndMismatches { get; set; }
        public int AvatarSelects { get; set; }
        public int EquipChanges { get; set; }
        public int UnequipChanges { get; set; }
        public int LobbyActionRejects { get; set; }
        public string[] LobbyActionRejectReasons { get; set; }
        public int AccountSaveFailures { get; set; }
        public int KeepaliveCount { get; set; }
        public int PurchaseReplies { get; set; }
        public int PurchaseObservedRecords { get; set; }
        public int PackageRefusals { get; set; }
    }

    public sealed class Probe
    {
        private const string Vip = "5.188.32.117";
        private const int Port = 7000;
        // 1.16: 240 s (was 120 s) so the connection can stay open through the client's own
        // 30 s query timeout after an unanswered request.
        private const int TotalBudgetMs = 240000;
        private const int FrameBudgetMs = 5000;
        // 1.10: room for buddy, avatar list, equipped avatar, one equipment request
        // and the next header, plus clocks.
        private const int PostLoginHeaderLimit = int.MaxValue;   // 1.23: no cumulative request cap
        private const int GradeRequestLimit = int.MaxValue;   // 1.23: no cumulative request cap
        private const int GuardAnswerLimit = int.MaxValue;   // 1.23: no cumulative request cap
        private const int GradeUpLimit = int.MaxValue;   // 1.23: no cumulative request cap
        private const int MenuRepeatLimit = int.MaxValue;   // 1.23: no cumulative request cap
        private const int UnsupportedObserveLimit = int.MaxValue;   // 1.23: no cumulative request cap
        private const int UnsupportedBodyLimit = 1024;
        private const int PropertyRequestLimit = int.MaxValue;   // 1.23: no cumulative request cap
        private readonly object gate = new object();
        private readonly ManualResetEvent authorization = new ManualResetEvent(false);
        private ProbeResult result = NewResult();

        private static ProbeResult NewResult()
        {
            return new ProbeResult { Status = "not_started", ErrorCode = "",
            AcceptedAfterStartMs = -1, FirstByteAfterAcceptMs = -1,
            LoginReplyKind = "none", PostLoginHeaders = new ProbeHeader[0], PostLoginStopReason = "",
            AvatarA6TrailingByte = -1, GradeUpRequestedId = -1, GradeUpRequestedIds = new int[0], AddItemBodies = new string[0], MenuCcUnmatchedBodies = new string[0],
            LobbyEnteredAtMs = -1, LastRoomListAtMs = -1, LastRequestAtMs = -1, Channel95Claimed = true,
            QuestUpdateBodies = new string[0], MainMenuEnteredAtMs = -1,
            FirstUnansweredRequest = "", LoginReplyAtMs = -1, ConnectionEndedAtMs = -1, StartedUtc = "",
            FixtureKind = "local_class_rod_exo", SessionNumber = 0,
            AccountSource = "none", LobbyActionRejectReasons = new string[0] };
        }
        private bool classFixture = true;

        // 1.13: true (default) = one class inventory item referenced by avatar slot 0;
        // false = the v1.12 empty inventory and all-zero equipment, for comparison.
        public bool ClassFixture
        {
            get { lock (gate) { return classFixture; } }
            set
            {
                lock (gate)
                {
                    if (started) throw new InvalidOperationException("fixture_after_start");
                    classFixture = value;
                    result.FixtureKind = value ? "local_class_rod_exo" : "v1_12_empty_character";
                }
            }
        }
        // 1.24: authoritative account state. With a store, every login loads the saved file
        // (created from the baseline fixture on first use) and every accepted My Info change is
        // written back before it is acknowledged. Without a store (offline tests) the baseline
        // lives in memory for the session. The empty-character comparison mode uses neither.
        private AccountStore accountStore;
        private AccountState account;   // this connection's view; replaced after each saved change

        public AccountStore Accounts
        {
            get { lock (gate) { return accountStore; } }
            set { lock (gate) { if (started) throw new InvalidOperationException("store_after_start"); accountStore = value; } }
        }

        public AccountState SessionAccount { get { lock (gate) { return account; } } }

        // 1.26: observed item records (private/fixtures/item-records.v1.tsv) used for purchases.
        private ItemCatalog itemRecords;
        public ItemCatalog ItemRecords { get { lock (gate) { return itemRecords; } } set { lock (gate) { itemRecords = value; } } }

        // 1.27: one session-log line per unanswered or refused request, written immediately (the
        // session summary only appears when the client disconnects). Login frames never reach here;
        // bodies of at most 64 bytes are logged as hex (game requests: item/avatar/room numbers).
        private void LogRequestLive(string eventName, int type, int action, int length, byte[] body, string note)
        {
            string hex = body.Length <= 64 ? BitConverter.ToString(body).Replace("-", "").ToLowerInvariant() : "omitted_" + body.Length + "_bytes";
            lock (gate)
            {
                AppendLogLocked("{\"event\":" + Json(eventName) + ",\"session\":" + sessionNumber + ",\"utc\":" + Json(DateTime.UtcNow.ToString("o")) +
                    ",\"at_ms\":" + overall.ElapsedMilliseconds + ",\"request\":" + Json(type.ToString("x2") + "/" + action.ToString("x2")) +
                    ",\"total_bytes\":" + length + ",\"body_hex\":" + Json(hex) + ",\"note\":" + Json(note) + "}");
            }
        }

        // Names any LE32 in the body that is an owned instance (offset, instance, catalog), so a
        // request about an inventory item can be tied to that item without guessing its layout.
        private string DescribeOwnedReference(byte[] body)
        {
            AccountState s = SessionAccount;
            if (s == null) return "";
            List<string> hits = new List<string>();
            for (int o = 0; o + 4 <= body.Length && hits.Count < 4; o++)
            {
                ItemRecord r = s.FindItem(Le32(body, o));
                if (r != null) hits.Add("+" + o + ":instance " + r.Instance + " catalog " + r.Catalog);
            }
            return string.Join("; ", hits.ToArray());
        }

        // Append-only purchase ledger beside the profile (<profile>.purchases.log).
        private void AppendPurchaseLedger(int catalog, int itemEnd, int flag, int instance, bool observed)
        {
            AccountStore store;
            int session;
            lock (gate) { store = accountStore; session = sessionNumber; }
            if (store == null) return;
            try
            {
                File.AppendAllText(store.FilePath + ".purchases.log", DateTime.UtcNow.ToString("o") + " session=" + session +
                    " catalog=" + catalog + " item_end=" + itemEnd + " flag=" + flag + " instance=" + instance +
                    " record=" + (observed ? "observed" : "reference_shape") + " charged=0" + Environment.NewLine, new UTF8Encoding(false));
            }
            catch (Exception) { lock (gate) { result.AccountSaveFailures++; } }
        }

        private AccountState LoadSessionAccount()
        {
            bool useClass; byte[] reward; AccountStore store;
            lock (gate)
            {
                useClass = classFixture;
                reward = lobbyFixture != null && EffectiveClaimed95() ? lobbyFixture.RewardRecord : null;
                store = accountStore;
            }
            if (!useClass) return null;
            AccountState baseline = AccountState.CreateBaseline(reward);
            AccountState loaded;
            try { loaded = store == null ? baseline : store.LoadOrCreate(baseline); }
            catch (Exception) { throw new ProbeFailure("account_store_unreadable", 0); }
            lock (gate) { account = loaded; result.AccountSource = store == null ? "in_memory_baseline" : "store"; }
            return loaded;
        }

        // Load -> change -> validate -> atomic save (store) or in-memory change (tests). The
        // reply is sent only when this returns null, i.e. after the change is durable.
        private string MutateAccount(Func<AccountState, string> change)
        {
            AccountState current; AccountStore store;
            lock (gate) { current = account; store = accountStore; }
            if (current == null) return "account_unavailable";
            if (store == null) return change(current);
            string reason;
            try
            {
                reason = store.Update(change);
                if (reason == null)
                {
                    AccountState fresh = store.Load();
                    lock (gate) { account = fresh; }
                }
            }
            catch (Exception)
            {
                lock (gate) { result.AccountSaveFailures++; }
                return "account_save_failed";
            }
            return reason;
        }

        private TcpListener listener;
        private TcpClient active;
        private Thread worker;
        private volatile bool stop;
        private volatile bool completed;
        private volatile bool ready;
        private int pendingPort;
        private string pendingAddress = "";
        private bool approved;
        private long pendingDecisionDeadlineMs;
        private Stopwatch overall;
        private bool started;
        private byte[] capturedInitialization;

        public bool Ready { get { return ready; } }
        public bool Completed { get { return completed; } }
        public int PendingPort { get { lock (gate) { return pendingPort; } } }
        public string PendingAddress { get { lock (gate) { return pendingAddress; } } }
        public ProbeResult Result
        {
            get
            {
                lock (gate)
                {
                    return new ProbeResult {
                        Status = result.Status, RequestType = result.RequestType,
                        RequestAction = result.RequestAction, RequestBytes = result.RequestBytes,
                        HeaderParsed = result.HeaderParsed, PeerAuthorized = result.PeerAuthorized,
                        AcceptedAfterStartMs = result.AcceptedAfterStartMs,
                        FirstByteAfterAcceptMs = result.FirstByteAfterAcceptMs,
                        SocketErrorCode = result.SocketErrorCode,
                        ReplyBytes = result.ReplyBytes, ReplyWritten = result.ReplyWritten,
                        LoginRequestType = result.LoginRequestType,
                        LoginRequestAction = result.LoginRequestAction,
                        LoginRequestBytes = result.LoginRequestBytes,
                        LoginHeaderParsed = result.LoginHeaderParsed,
                        LoginFrameReceived = result.LoginFrameReceived,
                        LoginReplyBytes = result.LoginReplyBytes,
                        LoginReplyWritten = result.LoginReplyWritten,
                        LocalFixtureMatched = result.LocalFixtureMatched,
                        LoginReplyKind = result.LoginReplyKind,
                        PostLoginRequestBytes = result.PostLoginRequestBytes,
                        PostLoginHeaders = CopyHeaders(result.PostLoginHeaders),
                        ClockReplyCount = result.ClockReplyCount,
                        PostLoginReplyBytes = result.PostLoginReplyBytes,
                        PostLoginStopReason = result.PostLoginStopReason,
                        CaptureFixtureLoaded = result.CaptureFixtureLoaded,
                        GameGuardReplayWritten = result.GameGuardReplayWritten,
                        GameGuardReplayBytes = result.GameGuardReplayBytes,
                        StartupAckWritten = result.StartupAckWritten,
                        StartupAckBytes = result.StartupAckBytes,
                        LocalCashReplyWritten = result.LocalCashReplyWritten,
                        LocalCashReplyBytes = result.LocalCashReplyBytes,
                        PropertyRequestCount = result.PropertyRequestCount,
                        PropertyOwnerMatchCount = result.PropertyOwnerMatchCount,
                        PropertyReplyCount = result.PropertyReplyCount,
                        PropertyReplyBytes = result.PropertyReplyBytes,
                        GiftFromReplyWritten = result.GiftFromReplyWritten,
                        GiftFromReplyBytes = result.GiftFromReplyBytes,
                        GiftToReplyWritten = result.GiftToReplyWritten,
                        GiftToReplyBytes = result.GiftToReplyBytes,
                        BuddyRequestBodyZero = result.BuddyRequestBodyZero,
                        BuddyReplyWritten = result.BuddyReplyWritten,
                        BuddyReplyBytes = result.BuddyReplyBytes,
                        AvatarListReplyWritten = result.AvatarListReplyWritten,
                        EquippedAvatarReplyWritten = result.EquippedAvatarReplyWritten,
                        AvatarEquipmentReplyWritten = result.AvatarEquipmentReplyWritten,
                        LoginEmailFieldMatched = result.LoginEmailFieldMatched,
                        LoginPasswordFieldMatched = result.LoginPasswordFieldMatched,
                        LocalLoginAccepted = result.LocalLoginAccepted,
                        AvatarA2AckCount = result.AvatarA2AckCount,
                        AvatarA4AckCount = result.AvatarA4AckCount,
                        AvatarA6AckCount = result.AvatarA6AckCount,
                        AvatarA6TrailingByte = result.AvatarA6TrailingByte,
                        StartedUtc = result.StartedUtc, LoginReplyAtMs = result.LoginReplyAtMs,
                        ConnectionEndedAtMs = result.ConnectionEndedAtMs, FixtureKind = result.FixtureKind,
                        GradeReplyCount = result.GradeReplyCount, B4ReplyCount = result.B4ReplyCount,
                        GuardAnswerCount = result.GuardAnswerCount, GuardAnswerBytes = result.GuardAnswerBytes,
                        GradeUpRequestedId = result.GradeUpRequestedId,
                        GradeUpRequestedIds = (int[])result.GradeUpRequestedIds.Clone(),
                        AddItemBodies = (string[])result.AddItemBodies.Clone(),
                        AddItemFailureReplies = result.AddItemFailureReplies,
                        AddItemUnansweredCount = result.AddItemUnansweredCount,
                        AddItemUnrecognizedFailures = result.AddItemUnrecognizedFailures,
                        FirstUnansweredRequest = result.FirstUnansweredRequest,
                        UnansweredRequestCount = result.UnansweredRequestCount,
                        LobbyFixtureLoaded = result.LobbyFixtureLoaded,
                        LoginCheckReplyWritten = result.LoginCheckReplyWritten,
                        MenuBaReplies = result.MenuBaReplies, MenuBcReplies = result.MenuBcReplies,
                        MenuCcReplies = result.MenuCcReplies,
                        MenuCcUnmatchedBodies = (string[])result.MenuCcUnmatchedBodies.Clone(),
                        LastRequestAtMs = result.LastRequestAtMs, LobbyEnteredAtMs = result.LobbyEnteredAtMs,
                        LevelUpGrantFailureReplies = result.LevelUpGrantFailureReplies,
                        QuestUpdateReplies = result.QuestUpdateReplies,
                        QuestUpdateBodies = (string[])result.QuestUpdateBodies.Clone(),
                        MainMenuEnteredAtMs = result.MainMenuEnteredAtMs,
                        SessionNumber = result.SessionNumber, CashReplies = result.CashReplies,
                        RoomListReplies = result.RoomListReplies, LastRoomListAtMs = result.LastRoomListAtMs,
                        B6Replies = result.B6Replies, Channel95Claimed = result.Channel95Claimed,
                        RewardRecordServed = result.RewardRecordServed,
                        RecentHeaders = CopyHeaders(recentHeaders.ToArray()),
                        RequestCounts = SnapshotCounts(),
                        LoginIdEmpty = result.LoginIdEmpty,
                        LoginIdHasAt = result.LoginIdHasAt,
                        LoginIdCaseInsensitiveMatch = result.LoginIdCaseInsensitiveMatch,
                        LoginIdContainsInvented = result.LoginIdContainsInvented,
                        SyntheticSocketCheck = result.SyntheticSocketCheck, ErrorCode = result.ErrorCode,
                        AccountSource = result.AccountSource, UserInfoReplies = result.UserInfoReplies,
                        ItemCheckReplies = result.ItemCheckReplies, ItemCheckEndMismatches = result.ItemCheckEndMismatches,
                        AvatarSelects = result.AvatarSelects, EquipChanges = result.EquipChanges,
                        UnequipChanges = result.UnequipChanges, LobbyActionRejects = result.LobbyActionRejects,
                        LobbyActionRejectReasons = (string[])result.LobbyActionRejectReasons.Clone(),
                        AccountSaveFailures = result.AccountSaveFailures, KeepaliveCount = result.KeepaliveCount,
                        PurchaseReplies = result.PurchaseReplies, PurchaseObservedRecords = result.PurchaseObservedRecords,
                        PackageRefusals = result.PackageRefusals
                    };
                }
            }
        }

        // Call only after the PS wrapper verifies that Vip is locally owned.
        public void Start()
        {
            lock (gate)
            {
                if (started || completed || stop) throw new InvalidOperationException("already_started");
                if (!IsInitializationShape(capturedInitialization))
                    throw new InvalidOperationException("capture_fixture_required");
                started = true;
            }
            string startupStage = "self_test";
            try
            {
                SelfTest();
                listener = new TcpListener(IPAddress.Parse(Vip), Port);
                listener.ExclusiveAddressUse = true;
                startupStage = "bind";
                listener.Start(4);
                startupStage = "synthetic_connect";
                // A socket-only preflight, explicitly separate from game evidence.
                using (TcpClient synthetic = new TcpClient(AddressFamily.InterNetwork))
                {
                    IAsyncResult ar = synthetic.BeginConnect(IPAddress.Parse(Vip), Port, null, null);
                    try
                    {
                        if (!ar.AsyncWaitHandle.WaitOne(2000)) throw new IOException("socket_preflight_timeout");
                        synthetic.EndConnect(ar);
                    }
                    finally { ar.AsyncWaitHandle.Close(); }
                    if (!listener.Pending()) throw new IOException("socket_preflight_not_local");
                    using (TcpClient accepted = listener.AcceptTcpClient())
                    {
                        IPEndPoint expected = (IPEndPoint)synthetic.Client.LocalEndPoint;
                        IPEndPoint actual = (IPEndPoint)accepted.Client.RemoteEndPoint;
                        if (!expected.Equals(actual)) throw new IOException("socket_preflight_peer_mismatch");
                    }
                }
                lock (gate)
                {
                    result.SyntheticSocketCheck = true; result.Status = "waiting_for_game";
                    result.StartedUtc = DateTime.UtcNow.ToString("o");
                }
                overall = Stopwatch.StartNew();
                ready = true;
                worker = new Thread(Run);
                worker.IsBackground = true;
                worker.Start();
            }
            catch (Exception ex)
            {
                lock (gate) { ClearCapturedInitializationLocked(); }
                if (listener != null) listener.Stop();
                completed = true;
                lock (gate)
                {
                    result.Status = "preflight_failed";
                    result.ErrorCode = startupStage + "_failed";
                    SocketException socketError = ex as SocketException;
                    if (socketError != null) result.SocketErrorCode = socketError.NativeErrorCode;
                }
                throw new InvalidOperationException("local_socket_check_failed");
            }
        }

        private static bool IsInitializationShape(byte[] frame)
        {
            return frame != null && frame.Length == 68 &&
                frame[0] == 0 && frame[1] == 0x48 && frame[2] == 0 && frame[3] == 68 &&
                frame[4] == 0x81 && frame[5] == 0 && frame[6] == 60 && frame[7] == 0;
        }

        // The caller owns and must clear the returned array after the setter clones it.
        // Only the selected frame is decrypted; preceding stream data is never read
        // into the cipher. Fixed offsets are valid only for this exact capture hash.
        public static byte[] LoadCapturedInitialization(string path)
        {
            byte[] raw = null;
            byte[] selected = null;
            byte[] skip = null;
            try
            {
                using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (file.Length != 64868) throw new InvalidOperationException("capture_size_mismatch");
                    raw = new byte[64868];
                    int position = 0;
                    while (position < raw.Length)
                    {
                        int read = file.Read(raw, position, raw.Length - position);
                        if (read <= 0) throw new InvalidOperationException("capture_read_incomplete");
                        position += read;
                    }
                    if (file.ReadByte() != -1) throw new InvalidOperationException("capture_size_mismatch");
                }
                if (Sha256(raw) != "c3702693136b5fb7699dcc3c8d4582912f30cc543fe57cbf12a2a8f1f3dfdfe7")
                    throw new InvalidOperationException("capture_hash_mismatch");
                selected = new byte[68];
                Array.Copy(raw, 3082, selected, 0, selected.Length);
                skip = new byte[872];
                Cipher sourceCipher = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                sourceCipher.Apply(skip, 0, skip.Length);
                sourceCipher.Apply(selected, 0, selected.Length);
                if (!IsInitializationShape(selected))
                    throw new InvalidOperationException("capture_frame_shape_mismatch");
                byte[] answer = selected;
                selected = null;
                return answer;
            }
            catch (InvalidOperationException) { throw; }
            catch (Exception) { throw new InvalidOperationException("capture_load_failed"); }
            finally
            {
                if (raw != null) Array.Clear(raw, 0, raw.Length);
                if (selected != null) Array.Clear(selected, 0, selected.Length);
                if (skip != null) Array.Clear(skip, 0, skip.Length);
            }
        }

        private const string LobbyFixtureSha256 = "4605704f0ee2b9002551039fd1789c43e32423c972b2889284c5368df1b172b6";

        public static LobbyFixture LoadLobbyFixture(string path)
        {
            byte[] data = File.ReadAllBytes(path);
            if (data.Length > 65536 || Sha256(data) != LobbyFixtureSha256)
                throw new InvalidOperationException("lobby_fixture_hash_mismatch");
            return ParseLobbyFixture(data);
        }

        // Structural validation only (the hash is checked by LoadLobbyFixture).
        private static LobbyFixture ParseLobbyFixture(byte[] data)
        {
            if (data == null || data.Length < 8 || data[0] != (byte)'R' || data[1] != (byte)'F' ||
                data[2] != (byte)'L' || data[3] != (byte)'F' || data[4] != (byte)'1' || data[5] != 0)
                throw new InvalidOperationException("lobby_fixture_format_invalid");
            LobbyFixture fixture = new LobbyFixture { Pages = new Dictionary<string, byte[]>() };
            int entries = data[6] | (data[7] << 8);
            int at = 8;
            for (int n = 0; n < entries; n++)
            {
                if (at + 2 > data.Length) throw new InvalidOperationException("lobby_fixture_truncated");
                int kind = data[at], reqLength = data[at + 1];
                at += 2;
                if (at + reqLength + 2 > data.Length) throw new InvalidOperationException("lobby_fixture_truncated");
                byte[] request = new byte[reqLength];
                Array.Copy(data, at, request, 0, reqLength);
                at += reqLength;
                int frameLength = data[at] | (data[at + 1] << 8);
                at += 2;
                if (frameLength < 6 || at + frameLength > data.Length) throw new InvalidOperationException("lobby_fixture_truncated");
                byte[] frame = new byte[frameLength];
                Array.Copy(data, at, frame, 0, frameLength);
                at += frameLength;
                if (kind == 5)
                {
                    // Inventory record, not a frame: 49 bytes, catalog 3043117, non-zero instance.
                    if (reqLength != 0 || frameLength != 49 || Le32(frame, 4) != RewardCatalogId ||
                        Le32(frame, 0) == 0 || fixture.RewardRecord != null)
                        throw new InvalidOperationException("lobby_fixture_entry_invalid");
                    fixture.RewardRecord = frame;
                    continue;
                }
                int type = (frame[0] << 8) | frame[1], total = (frame[2] << 8) | frame[3], action = frame[4] | (frame[5] << 8);
                if (total != frameLength) throw new InvalidOperationException("lobby_fixture_frame_length");
                if (kind == 1 && type == 0x30 && action == 0xb3 && total == 46 && reqLength == 0 && fixture.B3 == null) fixture.B3 = frame;
                else if (kind == 2 && type == 0x30 && action == 0xbb && total == 14 && reqLength == 0 && fixture.BB == null) fixture.BB = frame;
                else if (kind == 3 && type == 0x30 && action == 0xbd && total == 47 && reqLength == 0 && fixture.BD == null) fixture.BD = frame;
                else if (kind == 4 && type == 0x30 && action == 0xcd && total == 1810 && reqLength == 8)
                {
                    string key = BitConverter.ToString(request).Replace("-", "").ToLowerInvariant();
                    if (fixture.Pages.ContainsKey(key)) throw new InvalidOperationException("lobby_fixture_duplicate_page");
                    fixture.Pages[key] = frame;
                }
                else throw new InvalidOperationException("lobby_fixture_entry_invalid");
            }
            if (at != data.Length || fixture.B3 == null || fixture.BB == null || fixture.BD == null || fixture.Pages.Count != 5 ||
                fixture.RewardRecord == null)
                throw new InvalidOperationException("lobby_fixture_incomplete");
            return fixture;
        }

        private LobbyFixture lobbyFixture;
        private bool channel95Claimed = true;

        // 1.20: true (default) = controlled claimed-95 state (grade (1,1,2) + reward record);
        // false = v1.19 state (grade (0,0,2), no reward). Reversible via -Unclaimed95.
        public bool Channel95Claimed
        {
            get { lock (gate) { return channel95Claimed; } }
            set { lock (gate) { if (started) throw new InvalidOperationException("claimed95_after_start"); channel95Claimed = value; } }
        }

        // The claimed state is used only when the reward record is available, so grade and
        // inventory can never disagree; otherwise the v1.19 unclaimed state is served.
        private bool EffectiveClaimed95()
        {
            return channel95Claimed && lobbyFixture != null && lobbyFixture.RewardRecord != null;
        }

        public void SetLobbyFixture(LobbyFixture fixture)
        {
            if (fixture == null || fixture.B3 == null || fixture.BB == null || fixture.BD == null || fixture.Pages == null)
                throw new InvalidOperationException("lobby_fixture_incomplete");
            lock (gate)
            {
                if (started) throw new InvalidOperationException("lobby_fixture_after_start");
                lobbyFixture = fixture;
                result.LobbyFixtureLoaded = true;
            }
        }

        public void SetCapturedInitialization(byte[] frame)
        {
            if (frame == null || frame.Length != 68)
                throw new InvalidOperationException("capture_frame_shape_mismatch");
            byte[] copy = (byte[])frame.Clone();
            try
            {
                if (!IsInitializationShape(copy))
                    throw new InvalidOperationException("capture_frame_shape_mismatch");
                lock (gate)
                {
                    if (started || stop || completed)
                        throw new InvalidOperationException("capture_fixture_already_started");
                    ClearCapturedInitializationLocked();
                    capturedInitialization = copy;
                    copy = null;
                    result.CaptureFixtureLoaded = true;
                }
            }
            finally { if (copy != null) Array.Clear(copy, 0, copy.Length); }
        }

        // Caller holds gate. The result flag records that loading occurred, not
        // that sensitive fixture bytes remain available after their single use.
        private void ClearCapturedInitializationLocked()
        {
            if (capturedInitialization != null)
            {
                Array.Clear(capturedInitialization, 0, capturedInitialization.Length);
                capturedInitialization = null;
            }
        }

        // True means this decision was accepted while the same peer was pending.
        // A rejected or expired decision must not trigger the wrapper's login prompt.
        public bool AuthorizePeer(int remotePort, bool allow)
        {
            lock (gate)
            {
                if (stop || completed || overall == null || pendingPort == 0 ||
                    pendingPort != remotePort || authorization.WaitOne(0) ||
                    overall.ElapsedMilliseconds >= pendingDecisionDeadlineMs)
                    return false;
                approved = allow;
                result.PeerAuthorized = allow;
                authorization.Set();
                return true;
            }
        }

        // 1.20: the active deadline. Startup uses TotalBudgetMs; the first answered room
        // poll (lobby entry) extends it to SessionLifetimeMs from that moment. Only the
        // worker thread reads or writes it.
        // 1.23: no session deadline. A healthy session never expires because time passed;
        // only an incomplete frame (FrameBudgetMs after its first byte) ends a session.
        private long deadlineMs = NoDeadlineMs;
        private const long NoDeadlineMs = long.MaxValue / 4;
        private const long SessionLifetimeMs = 1200000;  // 1.22: 20 minutes from main-menu entry
        private const int SessionHeaderLimit = int.MaxValue;   // 1.23: no cumulative request cap

        private static int RemainingSessionBudgetMs(long elapsedMs, long firstByteMs, long deadline)
        {
            long left = deadline - elapsedMs;
            if (firstByteMs >= 0)
                left = Math.Min(left, FrameBudgetMs - (elapsedMs - firstByteMs));
            else
                left = Math.Min(left, IdlePollMs);   // idle: a polling slice, never an expiry
            return left <= 0 ? 0 : (int)left;
        }

        // Pure deadline arithmetic: idle time before the first byte is permitted
        // within the total budget; afterwards each frame shares five seconds.
        private static int RemainingReadBudgetMs(long elapsedMs, long firstByteMs)
        {
            long left = TotalBudgetMs - elapsedMs;
            if (firstByteMs >= 0)
                left = Math.Min(left, FrameBudgetMs - (elapsedMs - firstByteMs));
            return left <= 0 ? 0 : (int)Math.Min(left, TotalBudgetMs);
        }

        private sealed class ProbeFailure : Exception
        {
            public readonly string Code;
            public readonly int NativeCode;
            public ProbeFailure(string code, int nativeCode) : base(code)
            { Code = code; NativeCode = nativeCode; }
        }

        private static SocketException FindSocketError(Exception error)
        {
            // Inspect types only; never expose messages, paths or stack traces.
            for (int depth = 0; error != null && depth < 4; depth++, error = error.InnerException)
            {
                SocketException socketError = error as SocketException;
                if (socketError != null) return socketError;
            }
            return null;
        }

        private static bool IsReset(SocketException error)
        {
            return error != null && (error.SocketErrorCode == SocketError.ConnectionReset ||
                error.SocketErrorCode == SocketError.ConnectionAborted ||
                error.SocketErrorCode == SocketError.NetworkReset);
        }

        // 1.23 persistent server: accept connections until Stop(). Each connection gets fresh
        // ciphers and fresh protocol state; its end (disconnect, logout, client error,
        // protocol stop) is archived and logged as one client session, and the listener keeps
        // accepting reconnects. Only Stop() ends the server.
        private void Run()
        {
            try
            {
                while (!stop)
                {
                    if (!listener.Pending()) { Thread.Sleep(50); continue; }
                    TcpClient client;
                    try { client = listener.AcceptTcpClient(); }
                    catch (SocketException) { if (stop) break; continue; }
                    catch (ObjectDisposedException) { break; }
                    ServeOneConnection(client);
                }
            }
            catch (Exception)
            {
                lock (gate) { serverEndReason = stop ? serverEndReason : "listener_failed"; }
            }
            finally
            {
                ready = false;
                lock (gate) { ClearCapturedInitializationLocked(); }
                listener.Stop();
                completed = true;
            }
        }

        private void ServeOneConnection(TcpClient client)
        {
            long acceptedAtMs = overall.ElapsedMilliseconds;
            int phase = 0;
            string endReason = "ended";
            lock (gate) { BeginSessionLocked(acceptedAtMs); active = client; activeSocket = client.Client; }
            try
            {
                if (!AwaitAuthorization(client))
                {
                    endReason = "peer_not_authorized";
                    return;
                }
                client.NoDelay = true;
                ServeStream(client.GetStream(), acceptedAtMs, ref phase);
                lock (gate) { endReason = result.Status; }
            }
            catch (Exception ex) { endReason = RecordFailure(ex, phase); }
            finally
            {
                client.Close();
                lock (gate)
                {
                    active = null; activeSocket = null; pendingPort = 0; pendingAddress = "";
                    pendingDecisionDeadlineMs = 0;
                    EndSessionLocked(endReason);
                }
            }
        }

        private bool AwaitAuthorization(TcpClient client)
        {
            IPEndPoint peer = (IPEndPoint)client.Client.RemoteEndPoint;
            int authorizationBudget;
            lock (gate)
            {
                if (stop) throw new ProbeFailure("stopped", 0);
                authorization.Reset(); approved = false;
                pendingDecisionDeadlineMs = overall.ElapsedMilliseconds + 5000;
                authorizationBudget = 5000;
                pendingAddress = peer.Address.ToString(); pendingPort = peer.Port;
                result.AcceptedAfterStartMs = (int)Math.Min(int.MaxValue, overall.ElapsedMilliseconds);
                result.PeerAuthorized = false;
            }
            bool signaled = authorization.WaitOne(authorizationBudget);
            lock (gate)
            {
                bool allowed = signaled && approved && !stop;
                pendingPort = 0; pendingAddress = "";
                pendingDecisionDeadlineMs = 0;
                return allowed;
            }
        }

        private string RecordFailure(Exception ex, int phase)
        {
            lock (gate)
            {
                result.Status = stop ? "stopped" : "connection_ended";
                ProbeFailure failure = ex as ProbeFailure;
                SocketException socketError = FindSocketError(ex);
                string errorCode = failure != null ? failure.Code :
                    IsReset(socketError) ? "socket_reset" : "other_io_error";
                result.ErrorCode = stop || errorCode == "stopped" ? "stopped" :
                    (phase == 2 ? "post_login_" : phase == 1 ? "login_" : "") + errorCode;
                if (phase == 2) result.PostLoginStopReason = stop ? "stopped" : errorCode;
                result.SocketErrorCode = failure != null ? failure.NativeCode :
                    socketError != null ? socketError.NativeErrorCode : 0;
                return result.ErrorCode;
            }
        }

        // Version, login and post-login exchange for one connection (any Stream, so the
        // offline scripted tests drive exactly this code).
        private void ServeStream(Stream stream, long acceptedAtMs, ref int phase)
        {
            byte[] request = new byte[26];
            long firstByteAtMs = -1;
            try
            {
                ReadExact(stream, request, 0, 6, acceptedAtMs, ref firstByteAtMs, 0);
                Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                incoming.Apply(request, 0, 6);
                int type = (request[0] << 8) | request[1];
                int length = (request[2] << 8) | request[3];
                int action = request[4] | (request[5] << 8);
                lock (gate)
                {
                    result.RequestType = type; result.RequestAction = action;
                    result.HeaderParsed = true;
                }
                if (type != 0x10 || action != 0x90 || length != 26)
                {
                    lock (gate) { result.Status = "unexpected_opening_frame"; }
                    return;
                }
                // Read only the version body's 20 bytes. Never log or retain them.
                ReadExact(stream, request, 6, 20, acceptedAtMs, ref firstByteAtMs, 0);
                // The incoming cipher covers the full byte stream, including
                // the version body. Advancing only six bytes desynchronizes login.
                incoming.Apply(request, 6, 20);
                if (stop) throw new ProbeFailure("stopped", 0);
                if (RemainingSessionBudgetMs(overall.ElapsedMilliseconds, firstByteAtMs, deadlineMs) == 0)
                    throw new ProbeFailure("incomplete_frame_timeout", 0);
                byte[] reply = { 0, 0x10, 0, 6, 0x91, 0 };
                Cipher outgoing = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                outgoing.Apply(reply, 0, reply.Length);
                stream.WriteTimeout = WriteBudgetMs;
                stream.Write(reply, 0, reply.Length);
                lock (gate)
                {
                    result.ReplyBytes = 6; result.ReplyWritten = true;
                    result.Status = "version_request_received_reply_written";
                }
                phase = 1;
                byte[] loginRequest = new byte[91];
                byte[] loginReply = null;
                long loginFirstByteAtMs = -1;
                try
                {
                    ReadExact(stream, loginRequest, 0, 6, acceptedAtMs, ref loginFirstByteAtMs, 1);
                    incoming.Apply(loginRequest, 0, 6);
                    int loginType = (loginRequest[0] << 8) | loginRequest[1];
                    int loginLength = (loginRequest[2] << 8) | loginRequest[3];
                    int loginAction = loginRequest[4] | (loginRequest[5] << 8);
                    lock (gate)
                    {
                        result.LoginRequestType = loginType;
                        result.LoginRequestAction = loginAction;
                        result.LoginHeaderParsed = true;
                    }
                    if (loginType != 0x10 || loginAction != 0x84 || loginLength != 91)
                    {
                        lock (gate)
                        {
                            result.Status = "unexpected_login_frame";
                            result.ErrorCode = "login_unexpected_frame";
                        }
                        return;
                    }
                    // Consume exactly the fixed body, decrypt only in this
                    // bounded buffer, and compare only the invented fixture.
                    // Never turn received fields into strings or log them.
                    ReadExact(stream, loginRequest, 6, 85, acceptedAtMs, ref loginFirstByteAtMs, 1);
                    lock (gate) { result.LoginFrameReceived = true; }
                    incoming.Apply(loginRequest, 6, 85);
                    bool exactFixture = MatchesDummyLogin(loginRequest);
                    bool fixtureMatched = AcceptsLocalLogin(loginRequest);
                    // Which invented field matched; booleans only, never values.
                    bool emailMatched = MatchesSlot(loginRequest, 6, 64, DummyEmail);
                    bool passwordMatched = MatchesSlot(loginRequest, 70, 21, DummyPassword);
                    bool[] idFacts = DescribeIdSlot(loginRequest);
                    Array.Clear(loginRequest, 0, loginRequest.Length);
                    lock (gate)
                    {
                        result.LocalFixtureMatched = exactFixture;
                        result.LocalLoginAccepted = fixtureMatched;
                        result.LoginEmailFieldMatched = emailMatched;
                        result.LoginPasswordFieldMatched = passwordMatched;
                        result.LoginIdEmpty = idFacts[0];
                        result.LoginIdHasAt = idFacts[1];
                        result.LoginIdCaseInsensitiveMatch = idFacts[2];
                        result.LoginIdContainsInvented = idFacts[3];
                    }
                    if (stop) throw new ProbeFailure("stopped", 0);
                    if (RemainingSessionBudgetMs(overall.ElapsedMilliseconds, loginFirstByteAtMs, deadlineMs) == 0)
                        throw new ProbeFailure("incomplete_frame_timeout", 0);
                    AccountState loginAccount = fixtureMatched ? LoadSessionAccount() : null;
                    loginReply = !fixtureMatched ? BuildLoginFailure() : loginAccount == null ?
                        BuildLoginSuccess(Guid.NewGuid().ToString("D"), NewLocalToken()) :
                        BuildLoginSuccess(Guid.NewGuid().ToString("D"), NewLocalToken(), loginAccount);
                    lock (gate)
                    {
                        result.LoginReplyKind = fixtureMatched ? "synthetic_success" : "fixed_rejection";
                    }
                    // Continue the outgoing cipher after the six-byte ack.
                    outgoing.Apply(loginReply, 0, loginReply.Length);
                    stream.WriteTimeout = WriteBudgetMs;
                    stream.Write(loginReply, 0, loginReply.Length);
                    lock (gate)
                    {
                        result.LoginReplyBytes = loginReply.Length;
                        result.LoginReplyWritten = true;
                        result.LoginReplyAtMs = (int)Math.Min(int.MaxValue, overall.ElapsedMilliseconds);
                        result.Status = fixtureMatched ? "synthetic_login_success_written" :
                            "login_request_received_reply_written";
                    }
                    if (!fixtureMatched) return;
                    phase = 2;
                    ObservePostLogin(stream, incoming, outgoing, acceptedAtMs);
                }
                finally
                {
                    Array.Clear(loginRequest, 0, loginRequest.Length);
                    if (loginReply != null) Array.Clear(loginReply, 0, loginReply.Length);
                }
            }
            finally { Array.Clear(request, 0, request.Length); }
        }

        private const int WriteBudgetMs = 2000;
        private const int IdlePollMs = 1000;
        private Socket activeSocket;
        private string serverEndReason = "";
        private int sessionNumber;
        private long sessionAcceptedAtMs;
        private string sessionLogPath;
        private readonly List<string> sessionLines = new List<string>();
        private bool shutdownLogged;

        // Optional JSONL log: one line per ended client session, one line at server shutdown.
        public string SessionLogPath
        {
            get { lock (gate) { return sessionLogPath; } }
            set { lock (gate) { sessionLogPath = value; } }
        }

        public int CompletedSessionCount { get { lock (gate) { return sessionLines.Count; } } }

        public string[] SessionLines { get { lock (gate) { return sessionLines.ToArray(); } } }

        // Total ended client sessions (SessionLines keeps only the latest 500).
        public int EndedSessionCount { get { lock (gate) { return endedSessions; } } }
        private int endedSessions;

        // Caller holds gate. Fresh per-connection protocol state; server-level settings kept.
        private void BeginSessionLocked(long acceptedAtMs)
        {
            sessionNumber++;
            sessionAcceptedAtMs = acceptedAtMs;
            ProbeResult previous = result;
            result = NewResult();
            result.SyntheticSocketCheck = previous.SyntheticSocketCheck;
            result.StartedUtc = previous.StartedUtc;
            result.CaptureFixtureLoaded = previous.CaptureFixtureLoaded;
            result.LobbyFixtureLoaded = previous.LobbyFixtureLoaded;
            result.FixtureKind = previous.FixtureKind;
            result.SessionNumber = sessionNumber;
            account = null;
            deadlineMs = NoDeadlineMs;
            lobbyEntered = false;
            sessionStarted = false;
            currentHeader = null;
            recentHeaders.Clear();
            requestCounts.Clear();
        }

        // Caller holds gate.
        private void EndSessionLocked(string endReason)
        {
            if (result.ConnectionEndedAtMs < 0)
                result.ConnectionEndedAtMs = (int)Math.Min(int.MaxValue, overall.ElapsedMilliseconds);
            string line = "{\"event\":\"client_session_end\",\"session\":" + sessionNumber +
                ",\"ended_utc\":" + Json(DateTime.UtcNow.ToString("o")) +
                ",\"accepted_at_ms\":" + sessionAcceptedAtMs +
                ",\"ended_at_ms\":" + result.ConnectionEndedAtMs +
                ",\"end_reason\":" + Json(endReason) +
                ",\"status\":" + Json(result.Status) +
                ",\"peer_authorized\":" + (result.PeerAuthorized ? "true" : "false") +
                ",\"login_reply_kind\":" + Json(result.LoginReplyKind) +
                ",\"main_menu_entered_at_ms\":" + result.MainMenuEnteredAtMs +
                ",\"lobby_entered_at_ms\":" + result.LobbyEnteredAtMs +
                ",\"room_list_replies\":" + result.RoomListReplies +
                ",\"cash_replies\":" + result.CashReplies +
                ",\"quest_update_replies\":" + result.QuestUpdateReplies +
                ",\"unanswered_request_count\":" + result.UnansweredRequestCount +
                ",\"first_unanswered_request\":" + Json(result.FirstUnansweredRequest) +
                ",\"request_counts\":[" + string.Join(",", Array.ConvertAll(SnapshotCounts(), Json)) + "]}";
            endedSessions++;
            sessionLines.Add(line);
            if (sessionLines.Count > 500) sessionLines.RemoveAt(0);
            AppendLogLocked(line);
        }

        // Caller holds gate. Logging never throws into the protocol path.
        private void AppendLogLocked(string line)
        {
            if (string.IsNullOrEmpty(sessionLogPath)) return;
            try { File.AppendAllText(sessionLogPath, line + Environment.NewLine, new UTF8Encoding(false)); }
            catch (Exception) { }
        }

        // Only status/code strings, hex and ISO times reach this; still escaped defensively.
        private static string Json(string value)
        {
            if (value == null) return "null";
            StringBuilder text = new StringBuilder("\"");
            foreach (char c in value)
            {
                if (c == '"' || c == '\\') text.Append('\\').Append(c);
                else if (c < 32 || c > 126) text.Append("\\u").Append(((int)c).ToString("x4"));
                else text.Append(c);
            }
            return text.Append('"').ToString();
        }

        private void ReadExact(Stream stream, byte[] buffer, int offset, int count,
                               long acceptedAtMs, ref long firstByteAtMs, int phase)
        {
            int remaining = count;
            while (remaining > 0)
            {
                if (stop) throw new ProbeFailure("stopped", 0);
                if (firstByteAtMs < 0 && stream is NetworkStream)
                {
                    // Idle between frames: wait for readability (data or peer close) in short
                    // polls so Stop() is honoured; never rely on receive time-outs here.
                    Socket socket;
                    lock (gate) { socket = activeSocket; }
                    if (socket != null && !socket.Poll(IdlePollMs * 1000, SelectMode.SelectRead)) continue;
                }
                int milliseconds = firstByteAtMs < 0 ? FrameBudgetMs :
                    RemainingSessionBudgetMs(overall.ElapsedMilliseconds, firstByteAtMs, deadlineMs);
                string timeoutCode = firstByteAtMs < 0 ? "idle_timeout" : "incomplete_frame_timeout";
                if (milliseconds <= 0) throw new ProbeFailure(timeoutCode, 0);
                stream.ReadTimeout = milliseconds;
                int read;
                try { read = stream.Read(buffer, offset, remaining); }
                catch (IOException ex)
                {
                    SocketException socketError = FindSocketError(ex);
                    int nativeCode = socketError != null ? socketError.NativeErrorCode : 0;
                    if (stop) throw new ProbeFailure("stopped", nativeCode);
                    if (socketError != null && (socketError.SocketErrorCode == SocketError.TimedOut ||
                        socketError.SocketErrorCode == SocketError.WouldBlock))
                        throw new ProbeFailure(timeoutCode, nativeCode);
                    throw new ProbeFailure(IsReset(socketError) ? "socket_reset" : "other_io_error", nativeCode);
                }
                if (read == 0)
                {
                    // Offset is relative to this frame, including preceding header
                    // bytes when this call reads a version, login or property body.
                    int received = offset;
                    throw new ProbeFailure(received == 0 ? "peer_closed_before_header" :
                        received < 6 ? "peer_closed_during_header" : "peer_closed_during_body", 0);
                }
                long receivedAtMs = overall.ElapsedMilliseconds;
                lock (gate)
                {
                    if (firstByteAtMs < 0)
                    {
                        firstByteAtMs = receivedAtMs;
                        if (phase == 0)
                            result.FirstByteAfterAcceptMs = (int)(receivedAtMs - acceptedAtMs);
                    }
                    if (phase == 2) result.PostLoginRequestBytes += read;
                    else if (phase == 1) result.LoginRequestBytes += read;
                    else result.RequestBytes += read;
                }
                offset += read; remaining -= read;
            }
        }

        private static ProbeHeader[] CopyHeaders(ProbeHeader[] headers)
        {
            ProbeHeader[] copy = new ProbeHeader[headers.Length];
            for (int n = 0; n < headers.Length; n++)
                copy[n] = new ProbeHeader { FrameType = headers[n].FrameType,
                    Action = headers[n].Action, TotalBytes = headers[n].TotalBytes,
                    AtMs = headers[n].AtMs, ReplyAtMs = headers[n].ReplyAtMs,
                    ReplyBytes = headers[n].ReplyBytes };
            return copy;
        }

        // Caller holds gate. Attributes a written reply to the most recent request header.
        private void MarkReplyLocked(int bytes)
        {
            if (currentHeader == null) return;
            currentHeader.ReplyAtMs = (int)overall.ElapsedMilliseconds;
            currentHeader.ReplyBytes += bytes;
        }

        // Caller holds gate.
        private string[] SnapshotCounts()
        {
            List<string> counts = new List<string>();
            foreach (KeyValuePair<string, int> pair in requestCounts) counts.Add(pair.Key + "=" + pair.Value);
            counts.Sort(StringComparer.Ordinal);
            return counts.ToArray();
        }

        private ProbeHeader currentHeader;
        private readonly Queue<ProbeHeader> recentHeaders = new Queue<ProbeHeader>();
        private readonly Dictionary<string, int> requestCounts = new Dictionary<string, int>();
        private bool lobbyEntered;
        private bool sessionStarted;

        // 1.22: the session (lifetime and request cap) starts at main-menu entry (LoginCheck
        // answered), not at the first room poll: v1.21 reached the main menu at 167 s of the
        // 240 s startup budget, so a longer stay on the main menu would have timed out.
        // Caller holds gate; only the worker thread changes deadlineMs.
        private void StartSessionLocked()
        {
            if (!sessionStarted)
            {
                sessionStarted = true;
                result.MainMenuEnteredAtMs = (int)overall.ElapsedMilliseconds;
            }
        }

        private static string ClassifyPostLoginHeader(int type, int action, int length)
        {
            if (length < 6) return "invalid_header";
            if (type == 0x48) return "gameguard_header";
            if (type == 0x10 && action == 0x92)
                return length == 6 ? "clock" : "invalid_header";
            return "unsupported_header";
        }

        private static string NextPostLoginStep(int type, int action, int length,
                                               bool replayWritten, bool startupAckWritten,
                                               bool localCashReplyWritten, int propertyRequestCount,
                                               int propertyReplyCount = 0, bool giftFromWritten = false,
                                               bool giftToWritten = false, bool buddyWritten = false,
                                               int avatarStage = 0, int gradeCount = 0, int b4Count = 0,
                                               int guardAnswerCount = 0, int gradeUpCount = 0,
                                               int menuStage = 0, int bcCount = 0, int ccCount = 0,
                                               int b6Count = 0)
        {
            // 1.20 lobby. 10/B6 (body 1 byte, always 01) -> 0x210/B7 body 01 in all 11 captured
            // occurrences; it precedes the 2-second 40/84 room-list polling (body always
            // 0a 00 00 00 00 00 00 46) that marks an idle lobby.
            if (type == 0x10 && action == 0xb6)
            {
                if (length != 7) return "invalid_header";
                return menuStage >= 2 && b6Count < MenuRepeatLimit ? "lobby_b6" : "menu_out_of_order";
            }
            if (type == 0x40 && action == 0x84)
            {
                if (length != 14) return "invalid_header";
                return menuStage >= 1 ? "room_list" : "menu_out_of_order";
            }
            // 1.24: 1F/10 (header only) every 60 s; rf-boss-baseline 3/3 got no server reply and
            // the v1.23 client continued after 10 unanswered ones: a known no-reply message.
            if (type == 0x1f && action == 0x10)
                return length == 6 ? "keepalive_no_reply" : "invalid_header";
            // 1.24: 30/80 GET_USER_INFO (FUNC_Q_GET_USER_INFO): body = 20-byte name; reply 30/81
            // (4/4 in rf-boss-baseline, lobby, opening Create Room). v1.23 left it unanswered.
            if (type == 0x30 && action == 0x80)
            {
                if (length != 26) return "invalid_header";
                return menuStage >= 1 ? "user_info" : "menu_out_of_order";
            }
            // 1.27: 31/86 UNPACK and 31/9A OPEN_BOX (Gemnet names; the client logs "Unpack start" then
            // FUNC_Q_UNPACK NULL after 30 s when unanswered). No capture and no reference contains a
            // success reply or package/box contents, so these are refused explicitly (see handler).
            if (type == 0x31 && (action == 0x86 || action == 0x9a))
            {
                if (length <= 6 || length - 6 > UnsupportedBodyLimit) return "invalid_header";
                return menuStage >= 1 ? "package_refused" : "menu_out_of_order";
            }
            // 1.26: 31/80 BUY_ITEM (Gemnet name and layout; no capture contains a purchase):
            // body = 1 unread byte, LE32 catalog, LE32 item_end. Reply 31/81 (instance, Carats).
            if (type == 0x31 && action == 0x80)
            {
                if (length != 15) return "invalid_header";
                return menuStage >= 1 ? "buy_item" : "menu_out_of_order";
            }
            // 1.24: 30/D6 (body LE32 catalog, LE32 item_end of the owned record) precedes each
            // My Info equip in rf-boss-baseline; 4/4 answered 30/D7 body 01. v1.23 left it
            // unanswered and the equip stopped there.
            if (type == 0x30 && action == 0xd6)
            {
                if (length != 14) return "invalid_header";
                return avatarStage == 3 ? "item_check" : "avatar_out_of_order";
            }
            // 1.22: 30/CE = UpdateQuest (v1.21 log: "Send_Request_UpdateQuest Error" exactly 30 s
            // after the unanswered 30/CE). Both captured exchanges (rf-boss-baseline) answered
            // 30/CF, total 18, body identical to the 12-byte request body.
            if (type == 0x30 && action == 0xce)
            {
                if (length != 18) return "invalid_header";
                return menuStage >= 1 ? "quest_update" : "menu_out_of_order";
            }
            // 1.19 main-menu entry. v1.18 real client: GS_UIMENU -> "LoginCheck Start" sent
            // 30/B2; unanswered -> "Login Complete Error". Guild-less official sessions then
            // send 30/BA, 30/BC and 30/CC x5. All have empty bodies except CC (8 bytes).
            if (type == 0x30 && (action == 0xb2 || action == 0xba || action == 0xbc))
            {
                if (length != 6) return "invalid_header";
                if (action == 0xb2) return gradeCount > 0 && menuStage == 0 ? "login_check" : "menu_out_of_order";
                if (action == 0xba) return menuStage == 1 ? "menu_ba" : "menu_out_of_order";
                return menuStage >= 2 && bcCount < MenuRepeatLimit ? "menu_bc" : "menu_out_of_order";
            }
            if (type == 0x30 && action == 0xcc)
            {
                if (length != 14) return "invalid_header";
                return menuStage >= 3 && ccCount < MenuRepeatLimit ? "menu_cc" : "menu_out_of_order";
            }
            // 1.14: GameGuard answer 48/42 (bodies 110/118 captured). The official server
            // never replied to it in any capture; the client continued with its next request.
            if (type == 0x48 && action == 0x42)
            {
                if (length <= 6 || length > 512) return "invalid_header";
                return replayWritten && guardAnswerCount < GuardAnswerLimit ?
                    "gameguard_answer" : "gameguard_answer_unexpected";
            }
            // Only the observed GG -> startup/status -> cash order is supported.
            // Clocks may occur between these frames; no unsupported body is read.
            if (length < 6) return "invalid_header";
            if (type == 0x48 && action == 0x80 && length == 6)
                return !replayWritten && !startupAckWritten && !localCashReplyWritten ?
                    "gameguard_replay" : "startup_out_of_order";
            if (type == 0x10 && action == 0xd0)
            {
                if (length != 6) return "invalid_header";
                return replayWritten && !startupAckWritten && !localCashReplyWritten ?
                    "startup_ack" : "startup_out_of_order";
            }
            if (type == 0x31 && action == 0x88)
            {
                if (length != 6) return "invalid_header";
                // 1.23: also any time later (the Store sends Get_Cash 31/88 again).
                return replayWritten && startupAckWritten ?
                    "local_cash" : "startup_out_of_order";
            }
            if (type == 0x30 && action == 0x84)
            {
                if (length != 17) return "invalid_header";
                if (!replayWritten || !startupAckWritten || !localCashReplyWritten)
                    return "startup_out_of_order";
                if (giftFromWritten || giftToWritten) return "property_phase_closed";
                return propertyRequestCount < PropertyRequestLimit ?
                    "empty_property" : "property_request_limit";
            }
            if (type == 0x30 && (action == 0x92 || action == 0x90))
            {
                if (length != 6) return "invalid_header";
                if (!replayWritten || !startupAckWritten || !localCashReplyWritten ||
                    propertyReplyCount < 1)
                    return "gift_out_of_order";
                if (action == 0x92)
                    return !giftFromWritten && !giftToWritten ? "gift_from" : "gift_out_of_order";
                return giftFromWritten && !giftToWritten ? "gift_to" : "gift_out_of_order";
            }
            // Both user captures send buddy list 10/A8 (four-byte body) right after the
            // two gift lists; the official server answered once with 10/A9.
            if (type == 0x10 && action == 0xa8)
            {
                if (length != 10) return "invalid_header";
                if (!replayWritten || !startupAckWritten || !localCashReplyWritten ||
                    !giftFromWritten || !giftToWritten || buddyWritten)
                    return "buddy_out_of_order";
                return "empty_buddy_list";
            }
            // All three official captures: after the buddy list, 30/86 (account ID) lists
            // avatars, 40/A0 asks for the equipped one, then 30/88 once per listed avatar.
            // With one local avatar, exactly one 30/88 is expected.
            if (type == 0x30 && action == 0x86)
            {
                if (length != 10) return "invalid_header";
                return buddyWritten && avatarStage == 0 ? "local_avatar_list" : "avatar_out_of_order";
            }
            if (type == 0x40 && action == 0xa0)
            {
                if (length != 6) return "invalid_header";
                return buddyWritten && avatarStage == 1 ? "equipped_avatar" : "avatar_out_of_order";
            }
            if (type == 0x30 && action == 0x88)
            {
                if (length != 10) return "invalid_header";
                return buddyWritten && avatarStage == 2 ? "avatar_equipment" : "avatar_out_of_order";
            }
            // 40/A2 (10), 40/A4 (15), 40/A6 (11): each begins with a listed avatar ID; all 27
            // captured occurrences were answered by one empty 6-byte ack (A3/A5/A7).
            // v1.11 real client sent 40/A6 right after the avatar chain.
            if (type == 0x40 && (action == 0xa2 || action == 0xa4 || action == 0xa6))
            {
                int expected = action == 0xa2 ? 10 : action == 0xa4 ? 15 : 11;
                if (length != expected) return "invalid_header";
                return avatarStage == 3 ? "avatar_update_ack" : "avatar_out_of_order";
            }
            // 1.14: 30/A0 (GET_GRADE in Gemnet naming) follows the avatar chain in every
            // capture; it may repeat (3-8 times per session).
            if (type == 0x30 && action == 0xa0)
            {
                if (length != 6) return "invalid_header";
                return avatarStage == 3 && gradeCount < GradeRequestLimit ?
                    "local_grade_list" : "grade_out_of_order";
            }
            // 1.17: 31/8A ADD_ITEM (Gemnet name), body 10 bytes. In all captures every
            // 31/8A follows a 30/A1 grade reply; body byte 1 is a medal-channel ID.
            if (type == 0x31 && action == 0x8a)
            {
                if (length != 16) return "invalid_header";
                return gradeCount > 0 ? "add_item" : "add_item_out_of_order";
            }
            // 1.15: 31/8C (FUNC_Q_GRADE_UP per the v1.14 dialog; Gemnet comments it as
            // GRADE_UP), 1-byte body = the medal/grade ID the client wants created. Reply
            // format unknown: read the ID for the report, then stop.
            if (type == 0x31 && action == 0x8c)
            {
                if (length != 7) return "invalid_header";
                return gradeCount > 0 && gradeUpCount < GradeUpLimit ? "grade_up_request" : "grade_out_of_order";
            }
            // 1.14: 30/B4 x5 after the first grade reply, body LE32 index 1..5 in order.
            if (type == 0x30 && action == 0xb4)
            {
                if (length != 10) return "invalid_header";
                return gradeCount > 0 && b4Count < 5 ? "zero_b4_status" : "b4_out_of_order";
            }
            return ClassifyPostLoginHeader(type, action, length);
        }

        private void ObservePostLogin(Stream stream, Cipher incoming, Cipher outgoing, long acceptedAtMs)
        {
            byte[] header = new byte[6];
            bool replayWritten = false;
            bool startupAckWritten = false;
            bool localCashReplyWritten = false;
            int propertyRequestCount = 0;
            int propertyReplyCount = 0;
            bool giftFromWritten = false;
            bool giftToWritten = false;
            bool buddyWritten = false;
            int avatarStage = 0; // 1 list, 2 equipped, 3 equipment written
            int gradeCount = 0, b4Count = 0, guardAnswerCount = 0, gradeUpCount = 0, unsupportedCount = 0;
            int menuStage = 0, bcCount = 0, ccCount = 0, b6Count = 0;
            try
            {
                for (int n = 0; n < (sessionStarted ? SessionHeaderLimit : PostLoginHeaderLimit); n++)
                {
                    long firstByteAtMs = -1;
                    ReadExact(stream, header, 0, 6, acceptedAtMs, ref firstByteAtMs, 2);
                    incoming.Apply(header, 0, 6);
                    int type = (header[0] << 8) | header[1];
                    int length = (header[2] << 8) | header[3];
                    int action = header[4] | (header[5] << 8);
                    string classification = NextPostLoginStep(type, action, length,
                        replayWritten, startupAckWritten, localCashReplyWritten, propertyRequestCount,
                        propertyReplyCount, giftFromWritten, giftToWritten, buddyWritten, avatarStage,
                        gradeCount, b4Count, guardAnswerCount, gradeUpCount, menuStage, bcCount, ccCount, b6Count);
                    if ((classification == "login_check" || classification == "menu_ba" ||
                         classification == "menu_bc" || classification == "menu_cc") && lobbyFixture == null)
                        classification = "unsupported_header"; // no fixture: observe, do not answer
                    lock (gate)
                    {
                        // 1.20: first 64 headers in order, then a rolling window of the last 32,
                        // plus per-type counts, so a long session stays bounded.
                        currentHeader = new ProbeHeader {
                            FrameType = type, Action = action, TotalBytes = length,
                            AtMs = (int)overall.ElapsedMilliseconds, ReplyAtMs = -1 };
                        if (result.PostLoginHeaders.Length < 64)
                        {
                            ProbeHeader[] observed = new ProbeHeader[result.PostLoginHeaders.Length + 1];
                            Array.Copy(result.PostLoginHeaders, observed, result.PostLoginHeaders.Length);
                            observed[observed.Length - 1] = currentHeader;
                            result.PostLoginHeaders = observed;
                        }
                        else
                        {
                            recentHeaders.Enqueue(currentHeader);
                            while (recentHeaders.Count > 32) recentHeaders.Dequeue();
                        }
                        string typeKey = type.ToString("x2") + "/" + action.ToString("x2");
                        int seen;
                        requestCounts.TryGetValue(typeKey, out seen);
                        requestCounts[typeKey] = seen + 1;
                        result.LastRequestAtMs = currentHeader.AtMs;
                    }
                    if (classification == "gameguard_replay")
                    {
                        if (stop) throw new ProbeFailure("stopped", 0);
                        if (RemainingSessionBudgetMs(overall.ElapsedMilliseconds, firstByteAtMs, deadlineMs) == 0)
                            throw new ProbeFailure("incomplete_frame_timeout", 0);
                        byte[] replay = null;
                        try
                        {
                            lock (gate)
                            {
                                if (stop) throw new ProbeFailure("stopped", 0);
                                if (!IsInitializationShape(capturedInitialization))
                                    throw new ProbeFailure("capture_fixture_unavailable", 0);
                                // 1.23: the master copy is kept for later sessions (reconnects);
                                // it is cleared when the server stops.
                                replay = (byte[])capturedInitialization.Clone();
                            }
                            outgoing.Apply(replay, 0, replay.Length);
                            int replayBudget = (int)Math.Min(2000,
                                deadlineMs - overall.ElapsedMilliseconds);
                            if (replayBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                            stream.WriteTimeout = replayBudget;
                            stream.Write(replay, 0, replay.Length);
                            replayWritten = true;
                            lock (gate)
                            {
                                MarkReplyLocked(replay.Length);
                                result.GameGuardReplayBytes = replay.Length;
                                result.GameGuardReplayWritten = true;
                                result.PostLoginReplyBytes += replay.Length;
                                result.Status = "captured_gameguard_replay_written";
                            }
                        }
                        finally { if (replay != null) Array.Clear(replay, 0, replay.Length); }
                        // The total header cap still applies after this single replay.
                        continue;
                    }
                    if (classification == "package_refused")
                    {
                        // Explicit refusal in the failure form observed for 31/8A (31/18B, 520 bytes,
                        // LE16 code 10001 + "FAIL(unknown)"; the client logged it and continued).
                        // UNVERIFIED for 31/86 and 31/9A. Nothing is consumed or granted.
                        byte[] packageBody = new byte[length - 6];
                        ReadExact(stream, packageBody, 0, packageBody.Length, acceptedAtMs, ref firstByteAtMs, 2);
                        incoming.Apply(packageBody, 0, packageBody.Length);
                        LogRequestLive("package_request_refused", type, action, length, packageBody, DescribeOwnedReference(packageBody));
                        byte[] refusal = BuildAddItemFailure(AddItemChannel100FailureCode);
                        refusal[4] = (byte)(action + 1); refusal[5] = 0x01;
                        if (stop) throw new ProbeFailure("stopped", 0);
                        outgoing.Apply(refusal, 0, refusal.Length);
                        stream.WriteTimeout = WriteBudgetMs;
                        stream.Write(refusal, 0, refusal.Length);
                        lock (gate)
                        {
                            MarkReplyLocked(refusal.Length);
                            result.PostLoginReplyBytes += refusal.Length;
                            result.PackageRefusals++;
                            result.Status = "package_request_refused";
                        }
                        continue;
                    }
                    if (classification == "keepalive_no_reply")
                    {
                        lock (gate) { result.KeepaliveCount++; result.Status = "keepalive_1f10_no_reply"; }
                        continue;
                    }
                    bool accountAction = classification == "user_info" || classification == "item_check" || classification == "buy_item" ||
                        (classification == "avatar_update_ack" && SessionAccount != null);
                    if (accountAction)
                    {
                        byte[] actionBody = new byte[length - 6];
                        byte[] actionReply = null;
                        string reason = null;
                        try
                        {
                            ReadExact(stream, actionBody, 0, actionBody.Length, acceptedAtMs, ref firstByteAtMs, 2);
                            incoming.Apply(actionBody, 0, actionBody.Length);
                            AccountState current = SessionAccount;
                            if (classification == "user_info")
                            {
                                // Only the logged-in account's own name is answerable; no capture
                                // shows a not-found reply, so other names stay unanswered.
                                string requested = AsciiZ(actionBody, 0, 20);
                                if (current == null) reason = "no_account_state";
                                else if (requested != current.Name) reason = "user_info_other_name";
                                else actionReply = AccountWire.UserInfo(current);
                            }
                            else if (classification == "buy_item")
                            {
                                // Processed exactly once per request; the item is saved before the
                                // reply, and every purchase is appended to the profile's ledger.
                                int catalog = Le32(actionBody, 1), itemEnd = Le32(actionBody, 5), flag = actionBody[0];
                                ItemCatalog records = ItemRecords;
                                byte[] observed = null;
                                if (records != null) records.Records.TryGetValue(catalog, out observed);
                                ItemRecord bought = null;
                                bool fromObserved = false;
                                reason = MutateAccount(s =>
                                {
                                    ItemRecord g; bool o;
                                    string r = s.Purchase(catalog, itemEnd, observed, out g, out o);
                                    bought = g; fromObserved = o;
                                    return r;
                                });
                                if (reason == null && bought != null)
                                {
                                    AccountState after = SessionAccount;
                                    actionReply = AccountWire.BuyReply(after, bought.Instance);
                                    AppendPurchaseLedger(catalog, itemEnd, flag, bought.Instance, fromObserved);
                                    lock (gate) { result.PurchaseReplies++; if (fromObserved) result.PurchaseObservedRecords++; }
                                }
                                else if (reason == null) reason = "purchase_not_recorded";
                            }
                            else if (classification == "item_check")
                            {
                                bool endMatched;
                                if (current == null) reason = "no_account_state";
                                else if (!current.OwnsCatalog(Le32(actionBody, 0), Le32(actionBody, 4), out endMatched))
                                    reason = "item_check_not_owned";
                                else
                                {
                                    actionReply = AccountWire.ItemCheckOk();
                                    if (!endMatched) lock (gate) { result.ItemCheckEndMismatches++; }
                                }
                            }
                            else
                            {
                                int avatarId = Le32(actionBody, 0);
                                if (action == 0xa2) reason = MutateAccount(s => s.SelectAvatar(avatarId));
                                else
                                {
                                    int slot = actionBody[4];
                                    if (action == 0xa4)
                                    {
                                        int instance = Le32(actionBody, 5);
                                        reason = MutateAccount(s => s.Equip(avatarId, slot, instance));
                                    }
                                    else reason = MutateAccount(s => s.Unequip(avatarId, slot));
                                }
                                if (reason == null) actionReply = BuildAvatarUpdateAck(action);
                            }
                            if (actionReply == null)
                            {
                                // No captured failure reply exists for any of these: record the
                                // reason, leave the request unanswered, keep the state unchanged.
                                lock (gate)
                                {
                                    unsupportedCount++;
                                    result.UnansweredRequestCount = unsupportedCount;
                                    result.LobbyActionRejects++;
                                    if (result.FirstUnansweredRequest.Length == 0)
                                        result.FirstUnansweredRequest = type.ToString("x2") + "/" + action.ToString("x2");
                                    if (result.LobbyActionRejectReasons.Length < 16)
                                    {
                                        string[] reasons = new string[result.LobbyActionRejectReasons.Length + 1];
                                        Array.Copy(result.LobbyActionRejectReasons, reasons, reasons.Length - 1);
                                        reasons[reasons.Length - 1] = type.ToString("x2") + "/" + action.ToString("x2") + ":" + reason;
                                        result.LobbyActionRejectReasons = reasons;
                                    }
                                    result.Status = "lobby_action_rejected_unanswered";
                                }
                                continue;
                            }
                            if (stop) throw new ProbeFailure("stopped", 0);
                            outgoing.Apply(actionReply, 0, actionReply.Length);
                            stream.WriteTimeout = WriteBudgetMs;
                            stream.Write(actionReply, 0, actionReply.Length);
                            lock (gate)
                            {
                                MarkReplyLocked(actionReply.Length);
                                result.PostLoginReplyBytes += actionReply.Length;
                                if (classification == "user_info") { result.UserInfoReplies++; result.Status = "user_info_written"; }
                                else if (classification == "item_check") { result.ItemCheckReplies++; result.Status = "item_check_ok_written"; }
                                else if (classification == "buy_item") { result.Status = "purchase_saved_reply_written"; }
                                else
                                {
                                    if (action == 0xa2) { result.AvatarA2AckCount++; result.AvatarSelects++; }
                                    else if (action == 0xa4) { result.AvatarA4AckCount++; result.EquipChanges++; }
                                    else { result.AvatarA6AckCount++; result.UnequipChanges++; result.AvatarA6TrailingByte = actionBody[4]; }
                                    result.Status = "account_avatar_update_saved_ack_written";
                                }
                            }
                        }
                        finally
                        {
                            Array.Clear(actionBody, 0, actionBody.Length);
                            if (actionReply != null) Array.Clear(actionReply, 0, actionReply.Length);
                        }
                        continue;
                    }
                    if (classification == "empty_property")
                    {
                        byte[] propertyRequest = new byte[17];
                        byte[] propertyReply = null;
                        try
                        {
                            Array.Copy(header, propertyRequest, 6);
                            // The header has already started this frame's deadline.
                            // Consume exactly eleven bytes, then advance the same cipher.
                            ReadExact(stream, propertyRequest, 6, 11, acceptedAtMs,
                                ref firstByteAtMs, 2);
                            propertyRequestCount++;
                            lock (gate) { result.PropertyRequestCount = propertyRequestCount; }
                            incoming.Apply(propertyRequest, 6, 11);
                            AccountState propertyAccount = SessionAccount;
                            bool ownerMatches = propertyAccount == null ? MatchesLocalPropertyOwner(propertyRequest) :
                                propertyRequest.Length == 17 && Le32(propertyRequest, 6) == propertyAccount.AccountId;
                            // 1.24: body +7 = page cursor (first 1, then last instance + 1; all
                            // three captures). The rest of the body is not logged.
                            int propertyCursor = Le32(propertyRequest, 13);
                            Array.Clear(propertyRequest, 0, propertyRequest.Length);
                            if (!ownerMatches)
                            {
                                lock (gate)
                                {
                                    result.PostLoginStopReason = "property_owner_mismatch";
                                    result.Status = "local_property_owner_mismatch";
                                }
                                return;
                            }
                            lock (gate) { result.PropertyOwnerMatchCount++; }
                            if (stop) throw new ProbeFailure("stopped", 0);
                            if (RemainingSessionBudgetMs(overall.ElapsedMilliseconds, firstByteAtMs, deadlineMs) == 0)
                                throw new ProbeFailure("incomplete_frame_timeout", 0);
                            propertyReply = propertyAccount != null ? AccountWire.PropertyPage(propertyAccount, propertyCursor) :
                                classFixture ? BuildLocalClassPropertyResponse(EffectiveClaimed95() ? lobbyFixture.RewardRecord : null) :
                                BuildEmptyPropertyResponse();
                            outgoing.Apply(propertyReply, 0, propertyReply.Length);
                            int propertyBudget = (int)Math.Min(2000,
                                deadlineMs - overall.ElapsedMilliseconds);
                            if (propertyBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                            stream.WriteTimeout = propertyBudget;
                            stream.Write(propertyReply, 0, propertyReply.Length);
                            propertyReplyCount++;
                            lock (gate)
                            {
                                MarkReplyLocked(propertyReply.Length);
                                result.PropertyReplyCount = propertyReplyCount;
                                result.Channel95Claimed = classFixture && EffectiveClaimed95();
                                result.RewardRecordServed = classFixture && EffectiveClaimed95();
                                result.PropertyReplyBytes += propertyReply.Length;
                                result.PostLoginReplyBytes += propertyReply.Length;
                                result.Status = "empty_property_reply_written";
                            }
                        }
                        finally
                        {
                            Array.Clear(propertyRequest, 0, propertyRequest.Length);
                            if (propertyReply != null) Array.Clear(propertyReply, 0, propertyReply.Length);
                        }
                        continue;
                    }
                    if (classification == "quest_update")
                    {
                        byte[] questBody = new byte[12];
                        ReadExact(stream, questBody, 0, 12, acceptedAtMs, ref firstByteAtMs, 2);
                        incoming.Apply(questBody, 0, 12);
                        byte[] questReply = BuildQuestUpdateAck(questBody);
                        if (stop) throw new ProbeFailure("stopped", 0);
                        outgoing.Apply(questReply, 0, questReply.Length);
                        int questBudget = (int)Math.Min(2000, deadlineMs - overall.ElapsedMilliseconds);
                        if (questBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                        stream.WriteTimeout = questBudget;
                        stream.Write(questReply, 0, questReply.Length);
                        lock (gate)
                        {
                            MarkReplyLocked(questReply.Length);
                            result.PostLoginReplyBytes += questReply.Length;
                            result.QuestUpdateReplies++;
                            if (result.QuestUpdateBodies.Length < 8)
                            {
                                // Quest IDs/progress only (game data, not account data).
                                string[] bodies = new string[result.QuestUpdateBodies.Length + 1];
                                Array.Copy(result.QuestUpdateBodies, bodies, result.QuestUpdateBodies.Length);
                                bodies[bodies.Length - 1] = BitConverter.ToString(questBody).Replace("-", "").ToLowerInvariant();
                                result.QuestUpdateBodies = bodies;
                            }
                            result.Status = "quest_update_ack_written";
                        }
                        continue;
                    }
                    if (classification == "lobby_b6" || classification == "room_list")
                    {
                        byte[] lobbyBody = new byte[length - 6];
                        ReadExact(stream, lobbyBody, 0, lobbyBody.Length, acceptedAtMs, ref firstByteAtMs, 2);
                        incoming.Apply(lobbyBody, 0, lobbyBody.Length);
                        bool expectedBody = classification == "lobby_b6" ? IsB6Body(lobbyBody) : IsRoomPollBody(lobbyBody);
                        if (!expectedBody)
                        {
                            // Never observed: record by header and leave unanswered.
                            lock (gate)
                            {
                                unsupportedCount++;
                                if (result.FirstUnansweredRequest.Length == 0)
                                    result.FirstUnansweredRequest = type.ToString("x2") + "/" + action.ToString("x2") + "-body";
                                result.UnansweredRequestCount = unsupportedCount;
                            }
                            continue;
                        }
                        byte[] lobbyReply = classification == "lobby_b6" ? BuildB6Reply() : BuildEmptyRoomList();
                        if (stop) throw new ProbeFailure("stopped", 0);
                        outgoing.Apply(lobbyReply, 0, lobbyReply.Length);
                        int lobbyBudget = (int)Math.Min(2000, deadlineMs - overall.ElapsedMilliseconds);
                        if (lobbyBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                        stream.WriteTimeout = lobbyBudget;
                        stream.Write(lobbyReply, 0, lobbyReply.Length);
                        lock (gate)
                        {
                            MarkReplyLocked(lobbyReply.Length);
                            result.PostLoginReplyBytes += lobbyReply.Length;
                            if (classification == "lobby_b6")
                            {
                                b6Count++;
                                result.B6Replies = b6Count;
                                result.Status = "lobby_b6_reply_written";
                            }
                            else
                            {
                                result.RoomListReplies++;
                                result.LastRoomListAtMs = (int)overall.ElapsedMilliseconds;
                                if (!lobbyEntered)
                                {
                                    // Lobby entry: (re)start the session lifetime from now.
                                    lobbyEntered = true;
                                    StartSessionLocked();
                                    result.LobbyEnteredAtMs = (int)overall.ElapsedMilliseconds;
                                }
                                result.Status = "lobby_room_list_written";
                            }
                        }
                        continue;
                    }
                    if (classification == "login_check" || classification == "menu_ba" ||
                        classification == "menu_bc" || classification == "menu_cc")
                    {
                        byte[] menuReply = null;
                        if (classification == "menu_cc")
                        {
                            byte[] page = new byte[8];
                            ReadExact(stream, page, 0, 8, acceptedAtMs, ref firstByteAtMs, 2);
                            incoming.Apply(page, 0, 8);
                            ccCount++;
                            string pageKey = BitConverter.ToString(page).Replace("-", "").ToLowerInvariant();
                            byte[] stored;
                            if (lobbyFixture.Pages.TryGetValue(pageKey, out stored)) menuReply = stored;
                            else
                            {
                                // Category/cursor only; not account data. No invented page.
                                lock (gate)
                                {
                                    if (result.MenuCcUnmatchedBodies.Length < 8)
                                    {
                                        string[] bodies = new string[result.MenuCcUnmatchedBodies.Length + 1];
                                        Array.Copy(result.MenuCcUnmatchedBodies, bodies, result.MenuCcUnmatchedBodies.Length);
                                        bodies[bodies.Length - 1] = pageKey;
                                        result.MenuCcUnmatchedBodies = bodies;
                                    }
                                    result.Status = "menu_cc_page_unmatched_unanswered";
                                }
                                continue;
                            }
                        }
                        else menuReply = classification == "login_check" ? lobbyFixture.B3 :
                            classification == "menu_ba" ? lobbyFixture.BB : lobbyFixture.BD;
                        byte[] wire = (byte[])menuReply.Clone();
                        try
                        {
                            if (stop) throw new ProbeFailure("stopped", 0);
                            outgoing.Apply(wire, 0, wire.Length);
                            int menuBudget = (int)Math.Min(2000, deadlineMs - overall.ElapsedMilliseconds);
                            if (menuBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                            stream.WriteTimeout = menuBudget;
                            stream.Write(wire, 0, wire.Length);
                            lock (gate)
                            {
                                MarkReplyLocked(wire.Length);
                                result.PostLoginReplyBytes += wire.Length;
                                if (classification == "login_check") { menuStage = 1; result.LoginCheckReplyWritten = true; result.Status = "login_check_reply_written"; StartSessionLocked(); }
                                else if (classification == "menu_ba") { menuStage = 2; result.MenuBaReplies++; result.Status = "menu_ba_reply_written"; }
                                else if (classification == "menu_bc") { menuStage = 3; bcCount++; result.MenuBcReplies = bcCount; result.Status = "menu_bc_reply_written"; }
                                else { result.MenuCcReplies++; result.Status = "menu_cc_page_written"; }
                            }
                        }
                        finally { Array.Clear(wire, 0, wire.Length); }
                        continue;
                    }
                    if (classification == "add_item")
                    {
                        byte[] addItem = new byte[10];
                        byte[] failure = null;
                        try
                        {
                            ReadExact(stream, addItem, 0, 10, acceptedAtMs, ref firstByteAtMs, 2);
                            incoming.Apply(addItem, 0, 10);
                            bool levelOne = IsLevelOneRewardGrant(addItem);
                            bool channel100 = IsChannel100Claim(addItem) || levelOne;
                            lock (gate)
                            {
                                // Game data only (medal-channel claim), not account data.
                                if (result.AddItemBodies.Length < 8)
                                {
                                    string[] bodies = new string[result.AddItemBodies.Length + 1];
                                    Array.Copy(result.AddItemBodies, bodies, result.AddItemBodies.Length);
                                    bodies[bodies.Length - 1] = BitConverter.ToString(addItem).Replace("-", "").ToLowerInvariant();
                                    result.AddItemBodies = bodies;
                                }
                            }
                            // 1.28: answer EVERY ADD_ITEM with the observed 31/18B failure (code
                            // 10001 FAIL(unknown)). The channel-100 claim and level-1 reward have
                            // this captured directly; other bodies (e.g. the kind-0 catalog
                            // request the client sends during startup) are extrapolated to the
                            // same frame - same action, the failure the client is proven to
                            // tolerate and continue past - rather than left unanswered. Leaving
                            // them silent hung the client 30 s then EndTask (regression:
                            // GServerAccess.cpp(3194) return NULL). This is NOT a success reply.
                            if (!channel100)
                                LogRequestLive("add_item_unrecognized_failure", type, action, length, addItem, DescribeOwnedReference(addItem));
                            if (stop) throw new ProbeFailure("stopped", 0);
                            if (RemainingSessionBudgetMs(overall.ElapsedMilliseconds, firstByteAtMs, deadlineMs) == 0)
                                throw new ProbeFailure("incomplete_frame_timeout", 0);
                            failure = BuildAddItemFailure(AddItemChannel100FailureCode);
                            outgoing.Apply(failure, 0, failure.Length);
                            int failureBudget = (int)Math.Min(2000, deadlineMs - overall.ElapsedMilliseconds);
                            if (failureBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                            stream.WriteTimeout = failureBudget;
                            stream.Write(failure, 0, failure.Length);
                            lock (gate)
                            {
                                MarkReplyLocked(failure.Length);
                                result.AddItemFailureReplies++;
                                if (levelOne) result.LevelUpGrantFailureReplies++;
                                if (!channel100) result.AddItemUnrecognizedFailures++;
                                result.PostLoginReplyBytes += failure.Length;
                                result.Status = channel100 ? "add_item_observed_failure_written" : "add_item_unrecognized_failure_written";
                            }
                        }
                        finally
                        {
                            Array.Clear(addItem, 0, addItem.Length);
                            if (failure != null) Array.Clear(failure, 0, failure.Length);
                        }
                        continue;
                    }
                    if (classification == "grade_up_request")
                    {
                        // 1.16: record the requested channel and KEEP the connection open with
                        // no reply (no captured 31/8C or 31/8D exists to derive one from), so the
                        // client's own timeout behaviour and any later requests are observed.
                        byte[] gradeUp = new byte[1];
                        ReadExact(stream, gradeUp, 0, 1, acceptedAtMs, ref firstByteAtMs, 2);
                        incoming.Apply(gradeUp, 0, 1);
                        gradeUpCount++;
                        lock (gate)
                        {
                            if (result.GradeUpRequestedId < 0) result.GradeUpRequestedId = gradeUp[0];
                            int[] ids = new int[result.GradeUpRequestedIds.Length + 1];
                            Array.Copy(result.GradeUpRequestedIds, ids, result.GradeUpRequestedIds.Length);
                            ids[ids.Length - 1] = gradeUp[0];
                            result.GradeUpRequestedIds = ids;
                            result.Status = "local_grade_up_requested_unanswered";
                        }
                        continue;
                    }
                    if (classification == "gameguard_answer")
                    {
                        // Consume and discard; this local server does not validate GameGuard
                        // answers and, like the official server in every capture, sends nothing.
                        byte[] answer = new byte[length - 6];
                        try
                        {
                            ReadExact(stream, answer, 0, answer.Length, acceptedAtMs, ref firstByteAtMs, 2);
                            incoming.Apply(answer, 0, answer.Length);
                            guardAnswerCount++;
                            lock (gate)
                            {
                                result.GuardAnswerCount = guardAnswerCount;
                                result.GuardAnswerBytes += length;
                                result.Status = "gameguard_answer_received_no_reply";
                            }
                        }
                        finally { Array.Clear(answer, 0, answer.Length); }
                        continue;
                    }
                    if (classification == "empty_buddy_list" || classification == "local_avatar_list" ||
                        classification == "avatar_equipment" || classification == "avatar_update_ack" ||
                        classification == "zero_b4_status")
                    {
                        // Body length was validated exactly by NextPostLoginStep (4..9 bytes).
                        // Consume it so the cipher stays aligned; never log the values.
                        byte[] stepBody = new byte[length - 6];
                        byte[] stepReply = null;
                        try
                        {
                            ReadExact(stream, stepBody, 0, stepBody.Length, acceptedAtMs, ref firstByteAtMs, 2);
                            incoming.Apply(stepBody, 0, stepBody.Length);
                            AccountState stepAccount = SessionAccount;
                            string mismatch = classification == "zero_b4_status" ? CheckB4Body(stepBody, b4Count) :
                                stepAccount != null && classification == "local_avatar_list" ?
                                    (Le32(stepBody, 0) == stepAccount.AccountId ? null : "avatar_owner_mismatch") :
                                stepAccount != null && classification == "avatar_equipment" ?
                                    (stepAccount.FindAvatar(Le32(stepBody, 0)) != null ? null : "equipment_avatar_mismatch") :
                                CheckStepBody(classification, stepBody);
                            if (classification == "empty_buddy_list")
                                lock (gate) { result.BuddyRequestBodyZero = mismatch == null; }
                            else if (mismatch != null)
                            {
                                lock (gate)
                                {
                                    result.PostLoginStopReason = mismatch;
                                    result.Status = "local_" + mismatch;
                                }
                                return;
                            }
                            if (stop) throw new ProbeFailure("stopped", 0);
                            if (RemainingSessionBudgetMs(overall.ElapsedMilliseconds, firstByteAtMs, deadlineMs) == 0)
                                throw new ProbeFailure("incomplete_frame_timeout", 0);
                            stepReply = classification == "empty_buddy_list" ? BuildEmptyBuddyList() :
                                classification == "local_avatar_list" ?
                                    (stepAccount != null ? AccountWire.AvatarList(stepAccount) : BuildLocalAvatarList()) :
                                classification == "avatar_update_ack" ? BuildAvatarUpdateAck(action) :
                                classification == "zero_b4_status" ? BuildZeroB4Status() :
                                stepAccount != null ? AccountWire.Equipment(stepAccount, Le32(stepBody, 0)) :
                                classFixture ? BuildLocalClassEquipment() : BuildEmptyAvatarEquipment();
                            outgoing.Apply(stepReply, 0, stepReply.Length);
                            int stepBudget = (int)Math.Min(2000,
                                deadlineMs - overall.ElapsedMilliseconds);
                            if (stepBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                            stream.WriteTimeout = stepBudget;
                            stream.Write(stepReply, 0, stepReply.Length);
                            lock (gate)
                            {
                                MarkReplyLocked(stepReply.Length);
                                if (classification == "empty_buddy_list")
                                {
                                    buddyWritten = true;
                                    result.BuddyReplyWritten = true;
                                    result.BuddyReplyBytes = stepReply.Length;
                                    result.Status = "empty_buddy_list_written";
                                }
                                else if (classification == "local_avatar_list")
                                {
                                    avatarStage = 1;
                                    result.AvatarListReplyWritten = true;
                                    result.Status = "local_avatar_list_written";
                                }
                                else if (classification == "zero_b4_status")
                                {
                                    b4Count++;
                                    result.B4ReplyCount = b4Count;
                                    result.Status = "zero_b4_status_written";
                                }
                                else if (classification == "avatar_update_ack")
                                {
                                    if (action == 0xa2) result.AvatarA2AckCount++;
                                    else if (action == 0xa4) result.AvatarA4AckCount++;
                                    else
                                    {
                                        result.AvatarA6AckCount++;
                                        result.AvatarA6TrailingByte = stepBody[4];
                                    }
                                    result.Status = "avatar_update_ack_written";
                                }
                                else
                                {
                                    avatarStage = 3;
                                    result.AvatarEquipmentReplyWritten = true;
                                    result.Status = "avatar_equipment_written";
                                }
                                result.PostLoginReplyBytes += stepReply.Length;
                            }
                        }
                        finally
                        {
                            Array.Clear(stepBody, 0, stepBody.Length);
                            if (stepReply != null) Array.Clear(stepReply, 0, stepReply.Length);
                        }
                        continue;
                    }
                    if (classification == "unsupported_header" && avatarStage == 3 &&
                        unsupportedCount < UnsupportedObserveLimit && length - 6 <= UnsupportedBodyLimit)
                    {
                        // 1.17: v1.16 closed the connection on 31/8A, which itself caused the
                        // client's "... NULL" dialog 30 s later. After the avatar chain, an
                        // unsupported request is now consumed (cipher stays aligned), recorded
                        // by header only, NOT answered, and observation continues.
                        byte[] unsupportedBody = new byte[length - 6];
                        try
                        {
                            if (unsupportedBody.Length > 0)
                            {
                                ReadExact(stream, unsupportedBody, 0, unsupportedBody.Length, acceptedAtMs, ref firstByteAtMs, 2);
                                incoming.Apply(unsupportedBody, 0, unsupportedBody.Length);
                            }
                        }
                        finally
                        {
                            LogRequestLive("unanswered_request", type, action, length, unsupportedBody, DescribeOwnedReference(unsupportedBody));
                            Array.Clear(unsupportedBody, 0, unsupportedBody.Length);
                        }
                        unsupportedCount++;
                        lock (gate)
                        {
                            if (result.FirstUnansweredRequest.Length == 0)
                                result.FirstUnansweredRequest = type.ToString("x2") + "/" + action.ToString("x2");
                            result.UnansweredRequestCount = unsupportedCount;
                            result.Status = "unsupported_request_observed_unanswered";
                        }
                        continue;
                    }
                    if (classification != "clock" && classification != "startup_ack" &&
                        classification != "local_cash" && classification != "gift_from" &&
                        classification != "gift_to" && classification != "equipped_avatar" &&
                        classification != "local_grade_list")
                    {
                        lock (gate)
                        {
                            result.PostLoginStopReason = classification;
                            result.Status = avatarStage == 3 ? "local_avatar_postlogin_observed" :
                                avatarStage > 0 ? "local_avatar_partial_postlogin_observed" :
                                buddyWritten ? "local_buddy_postlogin_observed" :
                                giftFromWritten ? "local_gift_postlogin_observed" :
                                propertyReplyCount > 0 ? "local_property_postlogin_observed" :
                                startupAckWritten ? "local_startup_postlogin_observed" :
                                replayWritten ? "captured_gameguard_replay_next_header_observed" :
                                "synthetic_login_postlogin_observed";
                        }
                        return;
                    }
                    if (stop) throw new ProbeFailure("stopped", 0);
                    if (RemainingSessionBudgetMs(overall.ElapsedMilliseconds, firstByteAtMs, deadlineMs) == 0)
                        throw new ProbeFailure("incomplete_frame_timeout", 0);
                    AccountState responseAccount = SessionAccount;
                    byte[] response = classification == "startup_ack" ? BuildStartupAcknowledgement() :
                        classification == "local_cash" ?
                            (responseAccount != null ? AccountWire.Cash(responseAccount) : BuildLocalCashReply()) :
                        classification == "gift_from" ? BuildEmptyGiftCandidate(0x93) :
                        classification == "gift_to" ? BuildEmptyGiftCandidate(0x91) :
                        classification == "equipped_avatar" ?
                            (responseAccount != null ? AccountWire.EquippedAvatar(responseAccount) : BuildLocalEquippedAvatar()) :
                        classification == "local_grade_list" ? BuildLocalGradeList(EffectiveClaimed95()) :
                        BuildClockResponse(DateTime.UtcNow.ToFileTimeUtc());
                    try
                    {
                        outgoing.Apply(response, 0, response.Length);
                        int sendBudget = (int)Math.Min(2000, deadlineMs - overall.ElapsedMilliseconds);
                        if (sendBudget <= 0) throw new ProbeFailure("incomplete_frame_timeout", 0);
                        stream.WriteTimeout = sendBudget;
                        stream.Write(response, 0, response.Length);
                        lock (gate)
                        {
                            MarkReplyLocked(response.Length);
                            if (classification == "startup_ack")
                            {
                                startupAckWritten = true;
                                result.StartupAckWritten = true;
                                result.StartupAckBytes = response.Length;
                                result.Status = "local_startup_ack_written";
                            }
                            else if (classification == "local_cash")
                            {
                                localCashReplyWritten = true;
                                result.CashReplies++;
                                result.LocalCashReplyWritten = true;
                                result.LocalCashReplyBytes = response.Length;
                                result.Status = "local_cash_reply_written";
                            }
                            else if (classification == "gift_from")
                            {
                                giftFromWritten = true;
                                result.GiftFromReplyWritten = true;
                                result.GiftFromReplyBytes = response.Length;
                                result.Status = "gift_from_candidate_written";
                            }
                            else if (classification == "gift_to")
                            {
                                giftToWritten = true;
                                result.GiftToReplyWritten = true;
                                result.GiftToReplyBytes = response.Length;
                                result.Status = "gift_to_candidate_written";
                            }
                            else if (classification == "equipped_avatar")
                            {
                                avatarStage = 2;
                                result.EquippedAvatarReplyWritten = true;
                                result.Status = "local_equipped_avatar_written";
                            }
                            else if (classification == "local_grade_list")
                            {
                                gradeCount++;
                                result.GradeReplyCount = gradeCount;
                                result.Status = "local_grade_list_written";
                            }
                            else result.ClockReplyCount++;
                            result.PostLoginReplyBytes += response.Length;
                        }
                    }
                    finally { Array.Clear(response, 0, response.Length); }
                }
                lock (gate)
                {
                    result.PostLoginStopReason = lobbyEntered ? "session_header_limit" : "header_limit";
                    result.Status = avatarStage > 0 ? "local_avatar_header_limit" :
                        buddyWritten ? "local_buddy_header_limit" :
                        giftFromWritten ? "local_gift_header_limit" :
                        propertyReplyCount > 0 ? "local_property_header_limit" :
                        startupAckWritten ? "local_startup_header_limit" :
                        replayWritten ? "captured_gameguard_replay_header_limit" :
                        "synthetic_login_postlogin_observed";
                }
            }
            finally { Array.Clear(header, 0, header.Length); }
        }

        private static string AsciiZ(byte[] bytes, int offset, int width)
        {
            StringBuilder text = new StringBuilder();
            for (int n = offset; n < offset + width && bytes[n] != 0; n++)
                text.Append(bytes[n] >= 32 && bytes[n] < 127 ? (char)bytes[n] : '?');
            return text.ToString();
        }

        private static bool MatchesSlot(byte[] bytes, int offset, int width, string expected)
        {
            if (expected.Length >= width || offset < 0 || offset + width > bytes.Length) return false;
            for (int n = 0; n < expected.Length; n++)
                if (bytes[offset + n] != (byte)expected[n]) return false;
            // Ignore bounded stale bytes after the immediate terminator.
            return bytes[offset + expected.Length] == 0;
        }

        private const string DummyEmail = "probe@test.invalid";
        private const string DummyPassword = "ProbeOnly123!";

        private static bool MatchesDummyLogin(byte[] frame)
        {
            return frame != null && frame.Length == 91 &&
                MatchesSlot(frame, 6, 64, DummyEmail) &&
                MatchesSlot(frame, 70, 21, DummyPassword);
        }

        // 1.11: the invented password alone admits the local profile. It is what keeps
        // real credentials out of this test; the ID box is pre-filled by the game's
        // saved-login setting (registry SaveID) and repeatedly did not match exactly.
        private static bool AcceptsLocalLogin(byte[] frame)
        {
            return frame != null && frame.Length == 91 && MatchesSlot(frame, 70, 21, DummyPassword);
        }

        // Structural facts about the ID slot only; the value itself is never kept.
        // Returns { empty, has '@', case-insensitive exact match, contains the invented ID }.
        private static bool[] DescribeIdSlot(byte[] frame)
        {
            int end = 6;
            while (end < 70 && frame[end] != 0) end++;
            int length = end - 6;
            bool hasAt = false;
            for (int n = 6; n < end; n++) if (frame[n] == (byte)'@') hasAt = true;
            bool contains = false;
            for (int start = 6; start + DummyEmail.Length <= end && !contains; start++)
            {
                bool same = true;
                for (int n = 0; n < DummyEmail.Length && same; n++)
                    same = char.ToLowerInvariant((char)frame[start + n]) == DummyEmail[n];
                contains = same;
            }
            return new[] { length == 0, hasAt, contains && length == DummyEmail.Length, contains };
        }

        private static void PutAscii(byte[] frame, int offset, int width, string value)
        {
            if (value == null || value.Length == 0 || value.Length >= width ||
                offset < 0 || offset + width > frame.Length)
                throw new InvalidOperationException("synthetic_field_bounds");
            for (int n = 0; n < value.Length; n++)
            {
                if (value[n] < 32 || value[n] > 126)
                    throw new InvalidOperationException("synthetic_field_ascii");
                frame[offset + n] = (byte)value[n];
            }
            frame[offset + value.Length] = 0;
        }

        private static string NewLocalToken()
        {
            byte[] bytes = new byte[15];
            try
            {
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
                return BitConverter.ToString(bytes).Replace("-", "");
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }

        private static byte[] BuildLoginSuccess(string guid, string token)
        {
            Guid parsed;
            if (guid == null || guid.Length != 36 || !Guid.TryParseExact(guid, "D", out parsed) ||
                token == null || token.Length != 30)
                throw new InvalidOperationException("synthetic_identity_shape");
            byte[] frame = new byte[326];
            frame[0] = 0; frame[1] = 0x10;
            frame[2] = 0x01; frame[3] = 0x46;
            frame[4] = 0x85; frame[5] = 0;
            frame[6] = 1; // Local fixture account ID, explicit LE32; other bytes zero.
            PutAscii(frame, 10, 24, "AsterLocal");
            PutAscii(frame, 97, 37, guid);
            PutAscii(frame, 158, 8, "US");
            PutAscii(frame, 166, 32, "NA");
            PutAscii(frame, 198, 64, token);
            PutAscii(frame, 262, 64, "AsterLocal");
            // Exp, carats, medals and unresolved ranges 42..96, 134..149, 154..157 stay zero.
            // This is an experimental local identity, not a populated game account.
            return frame;
        }

        // 1.24: the same reply from account state. Body +0 account ID, +4 name, +24 level,
        // +28 experience: rf-boss-baseline's login body and its 30/81 user info carry the same
        // values at +0/+24/+28 (rf_userinfo_fields.py). The baseline account keeps level 0 and
        // experience 0, so its reply is byte-identical to the v1.23 one apart from GUID/token.
        private static byte[] BuildLoginSuccess(string guid, string token, AccountState s)
        {
            byte[] frame = BuildLoginSuccess(guid, token);
            if (s.AccountId != 1 || s.Name != "AsterLocal")
            {
                Array.Clear(frame, 6, 24);
                PutLe32(frame, 6, s.AccountId);
                PutAscii(frame, 10, 24, s.Name);
                Array.Clear(frame, 262, 64);
                PutAscii(frame, 262, 64, s.Name);
            }
            PutLe32(frame, 30, s.Level);
            PutLe32(frame, 34, (int)(uint)s.Experience);
            PutLe32(frame, 38, s.EffectiveCarats);   // 1.26: Carats, body +32 (capture + Gemnet LoginRes)
            return frame;
        }

        private static byte[] BuildClockResponse(long utcFileTime)
        {
            // Same observed fixed -7-hour FILETIME convention as the Python lab.
            long adjusted = checked(utcFileTime - 7L * 3600 * 10000000);
            byte[] frame = { 0, 0x10, 0, 14, 0x93, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            for (int n = 0; n < 8; n++) frame[6 + n] = (byte)(adjusted >> (8 * n));
            return frame;
        }

        private static byte[] BuildStartupAcknowledgement()
        {
            // The public reference and original capture agree on this fixed
            // startup/status value. Its further semantics are not established.
            return new byte[] { 0, 0x10, 0, 8, 0xd1, 0, 1, 0 };
        }

        private static byte[] BuildLocalCashReply()
        {
            // Three LE32 fields: local account ID1, cash0, medals0.
            // These agree with the invented local login profile, not an official account.
            return new byte[] { 0, 0x31, 0, 18, 0x89, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        }

        private static bool MatchesLocalPropertyOwner(byte[] frame)
        {
            return frame != null && frame.Length == 17 &&
                frame[6] == 1 && frame[7] == 0 && frame[8] == 0 && frame[9] == 0;
        }

        private static byte[] BuildEmptyPropertyResponse()
        {
            // Existing original codec layout: zero count plus eighty zeroed 49-byte
            // records. Empty data is experimental; no usable avatar is asserted.
            byte[] frame = new byte[3928];
            frame[1] = 0x30; frame[2] = 0x0f; frame[3] = 0x58; frame[4] = 0x85;
            return frame;
        }

        private static byte[] BuildEmptyGiftCandidate(int action)
        {
            if (action != 0x93 && action != 0x91)
                throw new InvalidOperationException("gift_candidate_action_invalid");
            // Only the observed total size and action are grounded. The 3501 zero
            // bytes are an experimental empty-list candidate; count width and
            // record semantics are not established. No captured gift data is used.
            byte[] frame = new byte[3507];
            frame[1] = 0x30; frame[2] = 0x0d; frame[3] = 0xb3; frame[4] = (byte)action;
            return frame;
        }

        private static byte[] BuildEmptyBuddyList()
        {
            // Layout from the two official 10/A9 replies (both 3008 bytes): LE16 count,
            // then 100 fixed 30-byte records (LE32 id, 24-byte NUL-padded name, two
            // trailing bytes). rf-empty-buddy shows count 0 with the client continuing.
            // The official tail after count 0 is uninitialized memory; zeros are sent here.
            byte[] frame = new byte[3008];
            frame[1] = 0x10; frame[2] = 0x0b; frame[3] = 0xc0; frame[4] = 0xa9;
            return frame;
        }

        private const int LocalAvatarId = 1;

        // Returns null when the four-byte body is acceptable, else a stop reason.
        private static string CheckStepBody(string classification, byte[] body)
        {
            bool isLocalOne = body[0] == 1 && body[1] == 0 && body[2] == 0 && body[3] == 0;
            if (classification == "empty_buddy_list")
                return body[0] == 0 && body[1] == 0 && body[2] == 0 && body[3] == 0 ? null : "buddy_body_nonzero";
            if (classification == "local_avatar_list")
                return isLocalOne ? null : "avatar_owner_mismatch"; // must be local account 1
            if (classification == "avatar_equipment")
                return isLocalOne ? null : "equipment_avatar_mismatch"; // must be LocalAvatarId
            if (classification == "avatar_update_ack")
                return isLocalOne ? null : "avatar_update_mismatch"; // first LE32 = LocalAvatarId
            throw new InvalidOperationException("step_body_classification_invalid");
        }

        private static byte[] BuildLocalAvatarList()
        {
            // Observed 30/87 layout (3 captures, counts 10/10/20): count byte, then 20
            // LE32 avatar IDs; active IDs non-zero. The single ID 1 is invented locally.
            byte[] frame = new byte[87];
            frame[1] = 0x30; frame[3] = 87; frame[4] = 0x87;
            frame[6] = 1;
            frame[7] = LocalAvatarId;
            return frame;
        }

        private static byte[] BuildLocalEquippedAvatar()
        {
            // Observed 40/A1: one LE32 avatar ID, always one of the listed IDs.
            return new byte[] { 0, 0x40, 0, 10, 0xa1, 0, LocalAvatarId, 0, 0, 0 };
        }

        private static byte[] BuildEmptyAvatarEquipment()
        {
            // Observed 30/89 (360-byte body): 45 LE32 item-instance references, then a
            // 180-byte tail that was zero in every capture. The local inventory is
            // empty, so every reference is zero. Acceptance of an unequipped avatar is
            // NOT established; this is the experiment.
            byte[] frame = new byte[366];
            frame[1] = 0x30; frame[2] = 0x01; frame[3] = 0x6e; frame[4] = 0x89;
            return frame;
        }

        // 1.13 class fixture. Evidence (rf_inventory_check.py, 3 captures): all 40
        // equipment replies have a non-zero slot 0 that resolves to an inventory
        // instance whose catalog item is a class (1000175 x37, 1000176 x3); all avatars
        // of an account share one class instance. The only class-record profile with
        // every opaque byte zero is: catalog 1000176 (Soul Fighter (M), public name),
        // +8 = 20046 (a shared category-like code: 192 of 1157 records), item_end 0,
        // stat 0. The instance ID is local and distinct from account/avatar IDs.
        // Unresolved: meaning of +8, +12..28, +37..48; whether item_end 0 means
        // permanent; acceptance of this record on this client.
        private const int LocalClassInstanceId = 1001;
        private const int ClassCatalogId = 1000176;
        private const int ClassRecordWord8 = 20046;

        private static void PutLe32(byte[] frame, int offset, int value)
        {
            for (int n = 0; n < 4; n++) frame[offset + n] = (byte)(value >> (8 * n));
        }

        // 1.14 rod: every official inventory holds exactly one Fishing Rod (5135224), no
        // official session sent 31/C6, and the v1.13 client (no rod) sent 31/C6 followed by
        // a FUNC_Q_REQ_FISHING_ROD timeout. Profile from the 3 captured rods: +8 85582,
        // item_end 1000, stat 0. Their +23..28 bytes are non-zero and unexplained; zero is
        // used here because 187 records with the same (+8, end, stat) profile are all-zero
        // there. A zero-opaque rod itself was never observed: candidate.
        private const int LocalRodInstanceId = 1002;
        private const int RodCatalogId = 5135224;
        private const int RodRecordWord8 = 85582;
        private const int RodItemEnd = 1000;

        // 1.18 default Exo. Every captured session owns exactly one default Exo for each class
        // in use, never equipped (rf_exo_check.py). The v1.17 client, lacking it, sent 31/8A
        // body 00 00 | LE32 2040035 | LE16 1000 | 00 00, i.e. a grant of Soul Fighter (M)'s
        // default Exo. Record = rf-boss-baseline's 2040035 record exactly (+8 85582, end
        // 1000, stat 0, every opaque byte zero); only the instance ID is local.
        private const int LocalExoInstanceId = 1003;
        private const int ExoCatalogId = 2040035;
        private const int ExoRecordWord8 = 85582;
        private const int ExoItemEnd = 1000;

        // 1.20 claimed-95 consistency: the 95-claim success reply (rf-startup 31/8B) names
        // catalog 3043117, which is owned (never equipped) in BOTH sessions whose channel 95
        // was already claimed and absent from rf-startup's pre-claim inventory. With 95 at the
        // post-claim (1,1,2), the reward is therefore owned too. Its record is rf-boss-
        // baseline's exact 49-byte record from the private fixture; only the instance ID is
        // local. Unresolved: the meaning of its non-zero opaque bytes and item_end 1176.
        private const int LocalRewardInstanceId = 1004;
        private const int RewardCatalogId = 3043117;

        private static byte[] BuildLocalClassPropertyResponse(byte[] rewardRecord)
        {
            byte[] frame = BuildEmptyPropertyResponse();
            frame[6] = 3; // LE16 count = 3; record n starts at frame 8 + 49n
            if (rewardRecord != null)
            {
                if (rewardRecord.Length != 49 || Le32(rewardRecord, 4) != RewardCatalogId)
                    throw new InvalidOperationException("reward_record_invalid");
                frame[6] = 4;
                Array.Copy(rewardRecord, 0, frame, 155, 49);
                PutLe32(frame, 155, LocalRewardInstanceId);
            }
            PutLe32(frame, 106, LocalExoInstanceId);
            PutLe32(frame, 110, ExoCatalogId);
            PutLe32(frame, 114, ExoRecordWord8);
            PutLe32(frame, 106 + 29, ExoItemEnd);
            PutLe32(frame, 8, LocalClassInstanceId);
            PutLe32(frame, 12, ClassCatalogId);
            PutLe32(frame, 16, ClassRecordWord8);
            PutLe32(frame, 57, LocalRodInstanceId);
            PutLe32(frame, 61, RodCatalogId);
            PutLe32(frame, 65, RodRecordWord8);
            PutLe32(frame, 57 + 29, RodItemEnd);
            return frame;
        }

        private static byte[] BuildLocalClassEquipment()
        {
            // Slot 0 (Job/class in the public order) = the local class instance ID,
            // never the catalog ID. Other 44 slots and the 180-byte tail stay zero, as in
            // the 16 captured avatars that populate only slot 0.
            byte[] frame = BuildEmptyAvatarEquipment();
            PutLe32(frame, 6, LocalClassInstanceId);
            return frame;
        }

        // All captures send B4 bodies LE32 1, 2, 3, 4, 5 in order.
        private static string CheckB4Body(byte[] body, int repliesSoFar)
        {
            return body.Length == 4 && Le32(body, 0) == repliesSoFar + 1 ? null : "b4_index_unexpected";
        }

        // 1.15 grade/medal list. Observed 30/A1 bodies: u8 count N, then N x 13-byte records
        // (u8 type ID ascending, three LE32 values). v1.14's empty list made the client log
        // "medal creation request : 1" and send 31/8C (FUNC_Q_GRADE_UP per its error dialog).
        // These are the 25 IDs present in all three captures AND observed with all three
        // values zero; every record below is therefore an observed record value. Common IDs
        // never observed all-zero (35, 95, 108, 121, 122) are deliberately left out.
        //
        // 1.16: the v1.15 client logged "medal creation request : N" for 90, 100, 30-34, 93
        // (each "already exists"), then for 95 (absent) sent 31/8C with body 95, so the
        // client's check is presence-only and 95 is a channel it requires. 95 is added with
        // (0, 0, 2): its exact values in the first rf-startup reply (session start). Fresh-
        // channel initial values are not observable in the captures (95 varies per account:
        // (0,0,2), (10,1,0), (7,1,21)), so this is an observed record, not a proven default.
        private static readonly byte[] LocalGradeIds = {
            1, 2, 3, 5, 10, 11, 12, 30, 31, 32, 33, 34, 50, 55, 56, 80, 81, 90, 93, 94, 95, 96, 99, 100, 109, 123 };

        // 1.20 (controlled experiment, user-approved): claimed95 = true sets 95 to (1,1,2),
        // rf-startup's value right AFTER its official 95 claim (reply 3 of 30/A1); the v1.19
        // value (0,0,2) made the client claim 95, a request with no derivable reply.
        private static byte[] BuildLocalGradeList(bool claimed95)
        {
            int total = 6 + 1 + 13 * LocalGradeIds.Length;
            byte[] frame = new byte[total];
            frame[1] = 0x30; frame[2] = (byte)(total >> 8); frame[3] = (byte)total; frame[4] = 0xa1;
            frame[6] = (byte)LocalGradeIds.Length;
            for (int n = 0; n < LocalGradeIds.Length; n++)
            {
                frame[7 + 13 * n] = LocalGradeIds[n];
                if (LocalGradeIds[n] != 95) continue;
                if (claimed95) { PutLe32(frame, 7 + 13 * n + 1, 1); PutLe32(frame, 7 + 13 * n + 5, 1); }
                PutLe32(frame, 7 + 13 * n + 9, 2);
            }
            return frame;
        }

        // ADD_ITEM 31/8A body 02 64 00 00 00 00 00 00 00 00 (medal channel 100 claim) is the
        // first ADD_ITEM in all three captures, with channel 100 at (0,0,0) as in our grade
        // list; the official server answered 31/18B code 10001 "FAIL(unknown)" every time and
        // the client continued.
        private const int AddItemChannel100FailureCode = 10001;

        // 1.21: GetLevelUpItem. Three v1.20 real-client runs (fresh account, experience 0,
        // the client shows "You are now Level 1 ... Level 1 Rewards") each sent exactly
        // 31/8A 01 00 | LE32 5023329 | LE16 1000 | 00 00 right after LoginCheck. Unanswered,
        // it timed out (FUNC_Q_ADD_ITEM NULL) and the client ended after LoginCheck. No
        // capture holds a kind-1 grant success; the only success sample (kind 2) has
        // unidentified fields, so no grant is derivable. The observed failure frame is sent
        // (the client logged "item grant error 10001 / item Add failed" for it and continued
        // to "LoginCheck All Green"). UNVERIFIED: that 10001 is the code a real server uses
        // for this kind. Nothing is granted, so repeats or reconnects cannot duplicate items.
        private static readonly byte[] LevelOneRewardGrant = { 1, 0, 0x61, 0xa6, 0x4c, 0, 0xe8, 0x03, 0, 0 };

        private static bool IsLevelOneRewardGrant(byte[] body)
        {
            if (body == null || body.Length != LevelOneRewardGrant.Length) return false;
            for (int n = 0; n < body.Length; n++) if (body[n] != LevelOneRewardGrant[n]) return false;
            return true;
        }

        private static bool IsChannel100Claim(byte[] body)
        {
            if (body == null || body.Length != 10 || body[0] != 2 || body[1] != 100) return false;
            for (int n = 2; n < 10; n++) if (body[n] != 0) return false;
            return true;
        }

        private static byte[] BuildAddItemFailure(int code)
        {
            // Observed 31/18B (5 captures): type 0x0031, total 520, action 0x018B; body LE16
            // code, "FAIL(unknown)", NUL. The official remainder is uninitialized memory
            // (zero through body offset 32 in every capture); zeros are sent here.
            byte[] frame = new byte[520];
            frame[1] = 0x31; frame[2] = 0x02; frame[3] = 0x08; frame[4] = 0x8b; frame[5] = 0x01;
            frame[6] = (byte)code; frame[7] = (byte)(code >> 8);
            byte[] text = Encoding.ASCII.GetBytes("FAIL(unknown)");
            text.CopyTo(frame, 8);
            return frame;
        }

        private static byte[] BuildQuestUpdateAck(byte[] requestBody)
        {
            // Observed 2/2: 30/CF, total 18, body = the request body. Small sample; quest state
            // is not persisted by this probe (the quest lists are a fixed one-session replay).
            if (requestBody == null || requestBody.Length != 12) throw new InvalidOperationException("quest_body_invalid");
            byte[] frame = new byte[18];
            frame[1] = 0x30; frame[3] = 18; frame[4] = 0xcf;
            Array.Copy(requestBody, 0, frame, 6, 12);
            return frame;
        }

        private static bool IsB6Body(byte[] body)
        {
            return body != null && body.Length == 1 && body[0] == 1;
        }

        private static readonly byte[] RoomPollBody = { 0x0a, 0, 0, 0, 0, 0, 0, 0x46 };

        private static bool IsRoomPollBody(byte[] body)
        {
            if (body == null || body.Length != RoomPollBody.Length) return false;
            for (int n = 0; n < body.Length; n++) if (body[n] != RoomPollBody[n]) return false;
            return true;
        }

        private static byte[] BuildB6Reply()
        {
            // Observed 11/11: header type 0x0210 (0x10 with 0x200 set), total 7, action 0xB7,
            // body 01. The meaning of the 0x200 type bit and of the byte is not established.
            return new byte[] { 0x02, 0x10, 0, 7, 0xb7, 0, 1 };
        }

        private static byte[] BuildEmptyRoomList()
        {
            // Observed 40/85 bodies (12 distinct, N = 1..4 rooms) are exactly 10 + 223*N:
            // u16 0 | u16 first room number | u16 0 | u16 0x8000|last room number | u16 N,
            // then N x 223-byte room records (they contain other players' room names and are
            // never replayed). UNVERIFIED: N = 0 was never observed; the first/last fields
            // are set to 0 because there is no room to reference.
            return new byte[] { 0, 0x40, 0, 16, 0x85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        }

        private static byte[] BuildZeroB4Status()
        {
            // Observed 30/B5: 19-byte body; the official server sent all-zero bodies for
            // some indices in every capture. Index meanings are unknown.
            byte[] frame = new byte[25];
            frame[1] = 0x30; frame[3] = 25; frame[4] = 0xb5;
            return frame;
        }

        private static byte[] BuildAvatarUpdateAck(int requestAction)
        {
            // Observed A3/A5/A7: header only (6 bytes), action = request action + 1.
            if (requestAction != 0xa2 && requestAction != 0xa4 && requestAction != 0xa6)
                throw new InvalidOperationException("avatar_ack_action_invalid");
            return new byte[] { 0, 0x40, 0, 6, (byte)(requestAction + 1), 0 };
        }

        private static byte[] BuildLoginFailure()
        {
            // Original serialization of the public reference's fixed failure layout.
            // Header: type BE16, total length BE16, action LE16; code LE16.
            byte[] frame = new byte[520];
            frame[0] = 0x02; frame[1] = 0x10;
            frame[2] = 0x02; frame[3] = 0x08;
            frame[4] = 0x85; frame[5] = 0x02;
            frame[6] = 0xbe; frame[7] = 0x72; // 29374
            byte[] message = Encoding.ASCII.GetBytes(
                "ASTER LOCAL SERVER: login message received. Gameplay is not enabled yet.");
            if (message.Length > 511) throw new InvalidOperationException("fixed_banner_too_long");
            message.CopyTo(frame, 8); // Remaining bytes include the NUL terminator.
            return frame;
        }

        private static string Sha256(byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }

        public void Stop() { Stop("stop_requested"); }

        // Deliberate shutdown: stop accepting, close the active socket, log once. The account
        // state is the fixed local fixture (nothing mutable to persist); the session log
        // already holds every ended client session.
        public void Stop(string reason)
        {
            lock (gate)
            {
                stop = true;
                if (string.IsNullOrEmpty(serverEndReason)) serverEndReason = reason ?? "stop_requested";
                ClearCapturedInitializationLocked();
                authorization.Set();
                if (active != null) active.Close();
            }
            if (listener != null) listener.Stop();
            if (worker != null && worker != Thread.CurrentThread) worker.Join(3000);
            ready = false;
            lock (gate)
            {
                if (!shutdownLogged)
                {
                    shutdownLogged = true;
                    AppendLogLocked("{\"event\":\"server_shutdown\",\"utc\":" + Json(DateTime.UtcNow.ToString("o")) +
                        ",\"reason\":" + Json(serverEndReason) + ",\"client_sessions\":" + endedSessions + "}");
                }
            }
        }

        public string ServerEndReason { get { lock (gate) { return serverEndReason; } } }

        public static void SelfTest()
        {
            // Pure tests: no listener, client, imported binary or timer sleeps.
            if (RemainingReadBudgetMs(32000, -1) != 208000 ||
                RemainingReadBudgetMs(32000, 32000) != 5000 ||
                RemainingReadBudgetMs(36999, 32000) != 1 ||
                RemainingReadBudgetMs(37000, 32000) != 0 ||
                RemainingReadBudgetMs(239000, 238000) != 1000 ||
                RemainingReadBudgetMs(240000, -1) != 0 ||
                RemainingReadBudgetMs(240000, 239000) != 0)
                throw new InvalidOperationException("deadline_selftest_failed");
            // Independently generated goldens use only invented local test data.
            byte[] failure = BuildLoginFailure();
            if (failure.Length != 520 || failure[519] != 0 ||
                Sha256(failure) != "866915444996422097f1c09c251174d713706ef2dda6412ad41689343054f4dd")
                throw new InvalidOperationException("login_failure_layout_selftest_failed");
            byte[] responses = new byte[526];
            byte[] versionAck = { 0, 0x10, 0, 6, 0x91, 0 };
            versionAck.CopyTo(responses, 0); failure.CopyTo(responses, 6);
            Cipher serverCipher = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            serverCipher.Apply(responses, 0, 6);
            serverCipher.Apply(responses, 6, 520);
            if (Sha256(responses) != "4f63e44c4093452dbea89605e6eae7ae7ce6556bf35ab23e7620a8a76a0561e1")
                throw new InvalidOperationException("continuous_response_selftest_failed");
            byte[] syntheticClient = new byte[117];
            byte[] versionHeader = { 0, 0x10, 0, 26, 0x90, 0 };
            byte[] loginHeader = { 0, 0x10, 0, 91, 0x84, 0 };
            versionHeader.CopyTo(syntheticClient, 0); loginHeader.CopyTo(syntheticClient, 26);
            Encoding.ASCII.GetBytes("probe@test.invalid").CopyTo(syntheticClient, 32);
            Encoding.ASCII.GetBytes("ProbeOnly123!").CopyTo(syntheticClient, 96);
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(syntheticClient, 0, 117);
            if (Sha256(syntheticClient) != "644a553a590047fbff99f1b8d4d16cd4b5547b567be454e729b5084b2d0769c7")
                throw new InvalidOperationException("continuous_request_selftest_failed");
            Cipher clientCipher = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            clientCipher.Apply(syntheticClient, 0, 6);
            clientCipher.Apply(syntheticClient, 6, 20);
            clientCipher.Apply(syntheticClient, 26, 6);
            for (int n = 0; n < 6; n++)
                if (syntheticClient[26 + n] != loginHeader[n])
                    throw new InvalidOperationException("continuous_login_header_selftest_failed");
            Array.Clear(syntheticClient, 0, syntheticClient.Length);
            byte[] success = BuildLoginSuccess("00000000-0000-4000-8000-000000000001",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234");
            if (Sha256(success) != "787c8001445d3b14ab6fd7d137b20433bd5c1fa600c6c975346d846f12665cf8")
                throw new InvalidOperationException("synthetic_success_layout_selftest_failed");
            byte[] clockFixture = BuildClockResponse(
                new DateTime(2026, 10, 16, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
            if (Sha256(clockFixture) != "d7be572c67d192219957f03c2c4088a4fb4e9fd0846343a37fea42a0c193f29e")
                throw new InvalidOperationException("clock_layout_selftest_failed");
            byte[] successStream = new byte[346];
            versionAck.CopyTo(successStream, 0); success.CopyTo(successStream, 6);
            clockFixture.CopyTo(successStream, 332);
            Cipher successCipher = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            successCipher.Apply(successStream, 0, 6); successCipher.Apply(successStream, 6, 326);
            successCipher.Apply(successStream, 332, 14);
            if (Sha256(successStream) != "ee62645dd411897a56d4f9a16be1ce80dea966ae2d2b6f288ada146bed924fe9")
                throw new InvalidOperationException("continuous_success_clock_selftest_failed");
            byte[] fixture = new byte[91];
            loginHeader.CopyTo(fixture, 0);
            Encoding.ASCII.GetBytes("probe@test.invalid").CopyTo(fixture, 6);
            Encoding.ASCII.GetBytes("ProbeOnly123!").CopyTo(fixture, 70);
            if (!MatchesDummyLogin(fixture) || MatchesDummyLogin(new byte[90]))
                throw new InvalidOperationException("fixture_shape_selftest_failed");
            fixture[6] ^= 1;
            if (MatchesDummyLogin(fixture)) throw new InvalidOperationException("fixture_email_selftest_failed");
            fixture[6] ^= 1;
            fixture[70] ^= 1;
            if (MatchesDummyLogin(fixture)) throw new InvalidOperationException("fixture_password_selftest_failed");
            fixture[70] ^= 1;
            int emailEnd = 6 + "probe@test.invalid".Length;
            int passwordEnd = 70 + "ProbeOnly123!".Length;
            fixture[emailEnd] = 1;
            if (MatchesDummyLogin(fixture)) throw new InvalidOperationException("fixture_email_nul_selftest_failed");
            fixture[emailEnd] = 0; fixture[passwordEnd] = 1;
            if (MatchesDummyLogin(fixture)) throw new InvalidOperationException("fixture_password_nul_selftest_failed");
            fixture[passwordEnd] = 0;
            byte[] laterRequests = new byte[129];
            versionHeader.CopyTo(laterRequests, 0); fixture.CopyTo(laterRequests, 26);
            byte[] clockHeader = { 0, 0x10, 0, 6, 0x92, 0 };
            byte[] guardHeader = { 0, 0x48, 0, 6, 0x80, 0 };
            clockHeader.CopyTo(laterRequests, 117); guardHeader.CopyTo(laterRequests, 123);
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(laterRequests, 0, laterRequests.Length);
            if (Sha256(laterRequests) != "318b690ee2c93ce4a8f7ced1df5ab4b66685aa16ed02bef7d35dd0b285863f2a")
                throw new InvalidOperationException("continuous_postlogin_request_selftest_failed");
            Cipher laterIncoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            laterIncoming.Apply(laterRequests, 0, 26);
            laterIncoming.Apply(laterRequests, 26, 6); laterIncoming.Apply(laterRequests, 32, 85);
            laterIncoming.Apply(laterRequests, 117, 6); laterIncoming.Apply(laterRequests, 123, 6);
            for (int n = 0; n < 6; n++)
                if (laterRequests[117 + n] != clockHeader[n] || laterRequests[123 + n] != guardHeader[n])
                    throw new InvalidOperationException("continuous_postlogin_headers_selftest_failed");
            fixture[emailEnd + 1] = 0xff; fixture[passwordEnd + 1] = 0xff;
            if (!MatchesDummyLogin(fixture)) throw new InvalidOperationException("fixture_padding_selftest_failed");
            // 1.11 acceptance: password decides; ID facts are booleans only.
            bool[] facts = DescribeIdSlot(fixture);
            if (!AcceptsLocalLogin(fixture) || facts[0] || !facts[1] || !facts[2] || !facts[3])
                throw new InvalidOperationException("login_accept_exact_selftest_failed");
            byte[] otherId = (byte[])fixture.Clone();
            Array.Clear(otherId, 6, 64);
            Encoding.ASCII.GetBytes("someone@example.invalid").CopyTo(otherId, 6);
            facts = DescribeIdSlot(otherId);
            if (!AcceptsLocalLogin(otherId) || facts[0] || !facts[1] || facts[2] || facts[3])
                throw new InvalidOperationException("login_accept_other_id_selftest_failed");
            Array.Clear(otherId, 6, 64);
            Encoding.ASCII.GetBytes("xProbe@Test.invalid").CopyTo(otherId, 6);
            facts = DescribeIdSlot(otherId);
            if (facts[2] || !facts[3]) throw new InvalidOperationException("login_id_contains_selftest_failed");
            Array.Clear(otherId, 6, 64);
            Encoding.ASCII.GetBytes("PROBE@TEST.INVALID").CopyTo(otherId, 6);
            facts = DescribeIdSlot(otherId);
            if (!facts[2] || !facts[3]) throw new InvalidOperationException("login_id_case_selftest_failed");
            Array.Clear(otherId, 6, 64);
            facts = DescribeIdSlot(otherId);
            if (!facts[0] || facts[1] || facts[3] || !AcceptsLocalLogin(otherId))
                throw new InvalidOperationException("login_id_empty_selftest_failed");
            otherId[70] ^= 1;
            if (AcceptsLocalLogin(otherId)) throw new InvalidOperationException("login_password_gate_selftest_failed");
            Array.Clear(otherId, 0, otherId.Length);
            Array.Clear(fixture, 0, fixture.Length); Array.Clear(laterRequests, 0, laterRequests.Length);
            if (ClassifyPostLoginHeader(0x10, 0x92, 6) != "clock" ||
                ClassifyPostLoginHeader(0x10, 0x92, 7) != "invalid_header" ||
                ClassifyPostLoginHeader(0x48, 0x80, 6) != "gameguard_header" ||
                ClassifyPostLoginHeader(0x30, 0x84, 17) != "unsupported_header" ||
                ClassifyPostLoginHeader(0x10, 0x92, 5) != "invalid_header")
                throw new InvalidOperationException("postlogin_classification_selftest_failed");
            // Invented bytes 0..59 are a shape/cipher test, never an initialization
            // generated for the client and never a fallback for the real capture.
            byte[] syntheticGuard = new byte[68];
            syntheticGuard[1] = 0x48; syntheticGuard[3] = 68;
            syntheticGuard[4] = 0x81; syntheticGuard[6] = 60;
            for (int n = 0; n < 60; n++) syntheticGuard[8 + n] = (byte)n;
            if (!IsInitializationShape(syntheticGuard) || IsInitializationShape(null) ||
                IsInitializationShape(new byte[67]) || IsInitializationShape(new byte[69]) ||
                Sha256(syntheticGuard) != "404fb4a8c5888bfdb0334942bf2ad02b28cde6e803d98b3d99252b016d7d2753")
                throw new InvalidOperationException("capture_shape_selftest_failed");
            for (int n = 0; n < 8; n++)
            {
                syntheticGuard[n] ^= 1;
                if (IsInitializationShape(syntheticGuard))
                    throw new InvalidOperationException("capture_shape_mutation_selftest_failed");
                syntheticGuard[n] ^= 1;
            }
            byte[] syntheticSource = new byte[940];
            byte[] syntheticSelected = new byte[68];
            byte[] syntheticSkip = new byte[872];
            byte[] syntheticReplies = new byte[414];
            byte[] startupFixture = BuildStartupAcknowledgement();
            byte[] cashFixture = BuildLocalCashReply();
            byte[] bootstrapReplies = new byte[454];
            byte[] bootstrapRequests = new byte[153];
            byte[] emptyProperty = BuildEmptyPropertyResponse();
            byte[] propertyReplies = new byte[12238];
            byte[] propertyRequests = new byte[204];
            try
            {
                syntheticGuard.CopyTo(syntheticSource, 872);
                new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(syntheticSource, 0, syntheticSource.Length);
                if (Sha256(syntheticSource) != "4c486dae121eadc9dc43c1ac709ab3e471919968297e5fa375c511c9593bcbe2")
                    throw new InvalidOperationException("capture_skip_stream_selftest_failed");
                Array.Copy(syntheticSource, 872, syntheticSelected, 0, 68);
                if (Sha256(syntheticSelected) != "d20e29e1decf3d3eb92b162fed5c31a9e4b27f72a85c51c9702c27ae9d4fde91")
                    throw new InvalidOperationException("capture_slice_selftest_failed");
                Cipher syntheticSourceCipher = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                syntheticSourceCipher.Apply(syntheticSkip, 0, syntheticSkip.Length);
                syntheticSourceCipher.Apply(syntheticSelected, 0, syntheticSelected.Length);
                if (!IsInitializationShape(syntheticSelected) ||
                    Sha256(syntheticSelected) != Sha256(syntheticGuard))
                    throw new InvalidOperationException("capture_skip_decode_selftest_failed");
                versionAck.CopyTo(syntheticReplies, 0); success.CopyTo(syntheticReplies, 6);
                clockFixture.CopyTo(syntheticReplies, 332); syntheticGuard.CopyTo(syntheticReplies, 346);
                Cipher replayCipher = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                replayCipher.Apply(syntheticReplies, 0, 6); replayCipher.Apply(syntheticReplies, 6, 326);
                replayCipher.Apply(syntheticReplies, 332, 14); replayCipher.Apply(syntheticReplies, 346, 68);
                if (Sha256(syntheticReplies) != "10f064f3833e33e5a49572b399f9645f301a474ff42e6933893dd4e7c9cd06d0")
                    throw new InvalidOperationException("capture_continuous_reply_selftest_failed");
                if (Sha256(startupFixture) != "9d8f1ec8473e906e3afee634e0a8d1738d5b70040dfbc93de2cd6954cbe78c7b" ||
                    Sha256(cashFixture) != "de7f4259af2973a3ef3c9ed8eb907f3971157ae57556fa2be16255d757db3d7d")
                    throw new InvalidOperationException("startup_reply_layout_selftest_failed");
                versionAck.CopyTo(bootstrapReplies, 0); success.CopyTo(bootstrapReplies, 6);
                clockFixture.CopyTo(bootstrapReplies, 332); syntheticGuard.CopyTo(bootstrapReplies, 346);
                startupFixture.CopyTo(bootstrapReplies, 414); cashFixture.CopyTo(bootstrapReplies, 422);
                clockFixture.CopyTo(bootstrapReplies, 440);
                Cipher bootstrapOutgoing = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                bootstrapOutgoing.Apply(bootstrapReplies, 0, 6);
                bootstrapOutgoing.Apply(bootstrapReplies, 6, 326);
                bootstrapOutgoing.Apply(bootstrapReplies, 332, 14);
                bootstrapOutgoing.Apply(bootstrapReplies, 346, 68);
                bootstrapOutgoing.Apply(bootstrapReplies, 414, 8);
                bootstrapOutgoing.Apply(bootstrapReplies, 422, 18);
                bootstrapOutgoing.Apply(bootstrapReplies, 440, 14);
                if (Sha256(bootstrapReplies) != "8bbd1b68b04f40467577b803841d7aaf3aa8c206807d69661cd38df2f54c2953")
                    throw new InvalidOperationException("startup_continuous_reply_selftest_failed");
                versionHeader.CopyTo(bootstrapRequests, 0); loginHeader.CopyTo(bootstrapRequests, 26);
                Encoding.ASCII.GetBytes("probe@test.invalid").CopyTo(bootstrapRequests, 32);
                Encoding.ASCII.GetBytes("ProbeOnly123!").CopyTo(bootstrapRequests, 96);
                clockHeader.CopyTo(bootstrapRequests, 117); guardHeader.CopyTo(bootstrapRequests, 123);
                new byte[] { 0, 0x10, 0, 6, 0xd0, 0 }.CopyTo(bootstrapRequests, 129);
                new byte[] { 0, 0x31, 0, 6, 0x88, 0 }.CopyTo(bootstrapRequests, 135);
                clockHeader.CopyTo(bootstrapRequests, 141);
                // This older prefix vector ends at the first property header.
                // Full property bodies are covered by the vectors below.
                new byte[] { 0, 0x30, 0, 17, 0x84, 0 }.CopyTo(bootstrapRequests, 147);
                new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(bootstrapRequests, 0, bootstrapRequests.Length);
                if (Sha256(bootstrapRequests) != "a64106af8fc7cd9397389640175097cc8b261c67684068b8531b99462da88cb5")
                    throw new InvalidOperationException("startup_request_stream_selftest_failed");
                Cipher bootstrapIncoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                bootstrapIncoming.Apply(bootstrapRequests, 0, 26);
                bootstrapIncoming.Apply(bootstrapRequests, 26, 6);
                bootstrapIncoming.Apply(bootstrapRequests, 32, 85);
                string[] expectedSteps = { "clock", "gameguard_replay", "startup_ack", "local_cash", "clock", "empty_property" };
                bool testGg = false, testAck = false, testCash = false;
                for (int n = 0; n < expectedSteps.Length; n++)
                {
                    int at = 117 + n * 6;
                    bootstrapIncoming.Apply(bootstrapRequests, at, 6);
                    string step = NextPostLoginStep(
                        (bootstrapRequests[at] << 8) | bootstrapRequests[at + 1],
                        bootstrapRequests[at + 4] | (bootstrapRequests[at + 5] << 8),
                        (bootstrapRequests[at + 2] << 8) | bootstrapRequests[at + 3],
                        testGg, testAck, testCash, 0);
                    if (step != expectedSteps[n]) throw new InvalidOperationException("startup_header_sequence_selftest_failed");
                    if (step == "gameguard_replay") testGg = true;
                    if (step == "startup_ack") testAck = true;
                    if (step == "local_cash") testCash = true;
                }
                Probe ownership = new Probe();
                try
                {
                    ownership.SetCapturedInitialization(syntheticGuard);
                    byte[] ownedFirst = ownership.capturedInitialization;
                    syntheticGuard[8] = 0xff;
                    if (ownedFirst[8] != 0 || !ownership.Result.CaptureFixtureLoaded)
                        throw new InvalidOperationException("capture_clone_selftest_failed");
                    syntheticGuard[8] = 0;
                    ownership.SetCapturedInitialization(syntheticGuard);
                    for (int n = 0; n < ownedFirst.Length; n++)
                        if (ownedFirst[n] != 0) throw new InvalidOperationException("capture_replace_clear_selftest_failed");
                    byte[] ownedSecond = ownership.capturedInitialization;
                    ownership.Stop();
                    for (int n = 0; n < ownedSecond.Length; n++)
                        if (ownedSecond[n] != 0) throw new InvalidOperationException("capture_stop_clear_selftest_failed");
                    bool rejected = false;
                    try { ownership.SetCapturedInitialization(syntheticGuard); }
                    catch (InvalidOperationException ex) { rejected = ex.Message == "capture_fixture_already_started"; }
                    if (!rejected) throw new InvalidOperationException("capture_late_set_selftest_failed");
                }
                finally { ownership.Stop(); ownership.authorization.Dispose(); }
                // Exercise all three state flags, including unreachable combinations:
                // each one-shot response has exactly one valid preceding state.
                for (int state = 0; state < 8; state++)
                {
                    bool gg = (state & 1) != 0;
                    bool ack = (state & 2) != 0;
                    bool cash = (state & 4) != 0;
                    if (NextPostLoginStep(0x48, 0x80, 6, gg, ack, cash, 0) !=
                            (state == 0 ? "gameguard_replay" : "startup_out_of_order") ||
                        NextPostLoginStep(0x10, 0xd0, 6, gg, ack, cash, 0) !=
                            (state == 1 ? "startup_ack" : "startup_out_of_order") ||
                        NextPostLoginStep(0x31, 0x88, 6, gg, ack, cash, 0) !=
                            ((state & 3) == 3 ? "local_cash" : "startup_out_of_order") ||   // 1.23: repeats allowed
                        NextPostLoginStep(0x10, 0x92, 6, gg, ack, cash, 0) != "clock" ||
                        NextPostLoginStep(0x30, 0x84, 17, gg, ack, cash, 0) !=
                            (state == 7 ? "empty_property" : "startup_out_of_order") ||
                        NextPostLoginStep(0x30, 0x92, 6, gg, ack, cash, 0) != "gift_out_of_order")
                        throw new InvalidOperationException("startup_order_selftest_failed");
                }
                if (NextPostLoginStep(0x48, 0x80, 7, false, false, false, 0) != "gameguard_header" ||
                    NextPostLoginStep(0x48, 0x42, 116, true, true, true, 0) != "gameguard_answer" ||
                    NextPostLoginStep(0x48, 0x44, 116, true, true, true, 0) != "gameguard_header" ||
                    NextPostLoginStep(0x10, 0xd0, 7, true, false, false, 0) != "invalid_header" ||
                    NextPostLoginStep(0x31, 0x88, 7, true, true, false, 0) != "invalid_header" ||
                    NextPostLoginStep(0x10, 0x92, 5, true, true, true, 0) != "invalid_header" ||
                    NextPostLoginStep(0x30, 0x84, 6, true, true, true, 0) != "invalid_header" ||
                    NextPostLoginStep(0x30, 0x84, 18, true, true, true, 0) != "invalid_header")
                    throw new InvalidOperationException("startup_length_selftest_failed");
                if (emptyProperty.Length != 3928 ||
                    Sha256(emptyProperty) != "d3bef5606f949b3e8fe004554f242e85b80685f137d49f96bc2b1d273aed24e0")
                    throw new InvalidOperationException("empty_property_layout_selftest_failed");
                Array.Copy(bootstrapReplies, propertyReplies, bootstrapReplies.Length);
                for (int n = 0; n < 3; n++)
                {
                    byte[] encrypted = (byte[])emptyProperty.Clone();
                    try
                    {
                        // Continue after the preceding454 encrypted response bytes.
                        bootstrapOutgoing.Apply(encrypted, 0, encrypted.Length);
                        Array.Copy(encrypted, 0, propertyReplies, 454 + n * 3928, encrypted.Length);
                    }
                    finally { Array.Clear(encrypted, 0, encrypted.Length); }
                }
                if (Sha256(propertyReplies) != "081e0c598a88b8cba121a0cecf7914d38f0fd91e0f5701588e248db8948f79b2")
                    throw new InvalidOperationException("property_continuous_reply_selftest_failed");
                // bootstrapRequests is now plaintext. Exclude its final header,
                // then append three complete requests with distinct invented tails.
                Array.Copy(bootstrapRequests, propertyRequests, 147);
                for (int n = 0; n < 3; n++)
                {
                    int at = 147 + n * 17;
                    propertyRequests[at + 1] = 0x30; propertyRequests[at + 3] = 17;
                    propertyRequests[at + 4] = 0x84; propertyRequests[at + 6] = 1;
                    for (int tail = 0; tail < 7; tail++)
                        propertyRequests[at + 10 + tail] = n == 0 ? (byte)0 :
                            n == 1 ? (byte)tail : (byte)0xff;
                }
                new byte[] { 0, 0x30, 0, 6, 0x92, 0 }.CopyTo(propertyRequests, 198);
                new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(propertyRequests, 0, propertyRequests.Length);
                if (Sha256(propertyRequests) != "dcb0a18670e4384527858a32263f407b3c1eae046fc48847b5364e53239dae83")
                    throw new InvalidOperationException("property_request_stream_selftest_failed");
                Cipher propertyIncoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                propertyIncoming.Apply(propertyRequests, 0, 147);
                for (int n = 0; n < 3; n++)
                {
                    byte[] fragmentedProperty = new byte[17];
                    try
                    {
                        Array.Copy(propertyRequests, 147 + n * 17, fragmentedProperty, 0, 17);
                        propertyIncoming.Apply(fragmentedProperty, 0, 2);
                        propertyIncoming.Apply(fragmentedProperty, 2, 4);
                        if (NextPostLoginStep(
                            (fragmentedProperty[0] << 8) | fragmentedProperty[1],
                            fragmentedProperty[4] | (fragmentedProperty[5] << 8),
                            (fragmentedProperty[2] << 8) | fragmentedProperty[3],
                            true, true, true, n) != "empty_property")
                            throw new InvalidOperationException("property_fragment_header_selftest_failed");
                        propertyIncoming.Apply(fragmentedProperty, 6, 1);
                        propertyIncoming.Apply(fragmentedProperty, 7, 3);
                        propertyIncoming.Apply(fragmentedProperty, 10, 7);
                        if (!MatchesLocalPropertyOwner(fragmentedProperty))
                            throw new InvalidOperationException("property_fragment_body_selftest_failed");
                        for (int ownerByte = 6; ownerByte < 10; ownerByte++)
                        {
                            fragmentedProperty[ownerByte] ^= 1;
                            if (MatchesLocalPropertyOwner(fragmentedProperty))
                                throw new InvalidOperationException("property_owner_selftest_failed");
                            fragmentedProperty[ownerByte] ^= 1;
                        }
                    }
                    finally { Array.Clear(fragmentedProperty, 0, fragmentedProperty.Length); }
                }
                propertyIncoming.Apply(propertyRequests, 198, 1);
                propertyIncoming.Apply(propertyRequests, 199, 5);
                if (propertyRequests[198] != 0 || propertyRequests[199] != 0x30 ||
                    propertyRequests[200] != 0 || propertyRequests[201] != 6 ||
                    propertyRequests[202] != 0x92 || propertyRequests[203] != 0 ||
                    NextPostLoginStep(0x30, 0x92, 6, true, true, true, 3, 3) != "gift_from" ||
                    NextPostLoginStep(0x30, 0x84, 17, true, true, true, 3) != "empty_property" ||        // 1.23: no page cap
                    NextPostLoginStep(0x30, 0x84, 17, true, true, true, 100000) != "empty_property" ||
                    MatchesLocalPropertyOwner(null) || MatchesLocalPropertyOwner(new byte[16]) ||
                    MatchesLocalPropertyOwner(new byte[18]))
                    throw new InvalidOperationException("property_cap_or_truncation_selftest_failed");
                SelfTestGiftCandidates(bootstrapRequests, bootstrapReplies, emptyProperty);
                SelfTestBuddyList();
                SelfTestAvatarSteps();
                SelfTestClassFixture();
                SelfTestLobbyQueries();
                SelfTestAddItem();
                SelfTestMainMenu();
                SelfTestLobbySession();
            }
            finally
            {
                Array.Clear(syntheticGuard, 0, syntheticGuard.Length);
                Array.Clear(syntheticSource, 0, syntheticSource.Length);
                Array.Clear(syntheticSelected, 0, syntheticSelected.Length);
                Array.Clear(syntheticSkip, 0, syntheticSkip.Length);
                Array.Clear(syntheticReplies, 0, syntheticReplies.Length);
                Array.Clear(startupFixture, 0, startupFixture.Length);
                Array.Clear(cashFixture, 0, cashFixture.Length);
                Array.Clear(bootstrapReplies, 0, bootstrapReplies.Length);
                Array.Clear(bootstrapRequests, 0, bootstrapRequests.Length);
                Array.Clear(emptyProperty, 0, emptyProperty.Length);
                Array.Clear(propertyReplies, 0, propertyReplies.Length);
                Array.Clear(propertyRequests, 0, propertyRequests.Length);
            }
            byte[] vector = Encoding.ASCII.GetBytes("Plaintext");
            new Cipher(Encoding.ASCII.GetBytes("Key")).Apply(vector, 0, vector.Length);
            if (BitConverter.ToString(vector) != "BB-F3-16-E8-D9-40-AF-0A-D3")
                throw new InvalidOperationException("rc4_selftest_failed");
            byte[] reply = { 0, 0x10, 0, 6, 0x91, 0 };
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(reply, 0, 6);
            if (BitConverter.ToString(reply) != "4A-EA-41-28-20-C9")
                throw new InvalidOperationException("reply_selftest_failed");
            byte[] request = { 0x4a, 0xea, 0x41, 0x34, 0x21, 0xc9 };
            Cipher fragmented = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            fragmented.Apply(request, 0, 2); fragmented.Apply(request, 2, 4);
            if (BitConverter.ToString(request) != "00-10-00-1A-90-00")
                throw new InvalidOperationException("request_selftest_failed");
        }

        private static void SelfTestGiftCandidates(byte[] plaintextStartup, byte[] encryptedStartup,
                                                   byte[] emptyProperty)
        {
            // All data here is synthetic; no capture file is opened by SelfTest.
            byte[] from = BuildEmptyGiftCandidate(0x93);
            byte[] to = BuildEmptyGiftCandidate(0x91);
            try
            {
                if (Sha256(from) != "4a41843a6fddb38348a8ffabafaa2645b5841d16a7dc6c32aabf36d736cda54a" ||
                    Sha256(to) != "eaf0ecf3865d886cdea90ced30594434e46a54aebfda2896837164c4cb024f0f")
                    throw new InvalidOperationException("gift_candidate_layout_selftest_failed");
                bool rejectedAction = false;
                try { BuildEmptyGiftCandidate(0x92); }
                catch (InvalidOperationException ex) { rejectedAction = ex.Message == "gift_candidate_action_invalid"; }
                if (!rejectedAction) throw new InvalidOperationException("gift_candidate_action_selftest_failed");
                for (int state = 0; state < 8; state++)
                {
                    bool gg = (state & 1) != 0, ack = (state & 2) != 0, cash = (state & 4) != 0;
                    for (int gifts = 0; gifts < 4; gifts++)
                    {
                        bool sentFrom = (gifts & 1) != 0, sentTo = (gifts & 2) != 0;
                        if (NextPostLoginStep(0x30, 0x92, 6, gg, ack, cash, 1, 1, sentFrom, sentTo) !=
                                (state == 7 && gifts == 0 ? "gift_from" : "gift_out_of_order") ||
                            NextPostLoginStep(0x30, 0x90, 6, gg, ack, cash, 1, 1, sentFrom, sentTo) !=
                                (state == 7 && gifts == 1 ? "gift_to" : "gift_out_of_order") ||
                            NextPostLoginStep(0x10, 0x92, 6, gg, ack, cash, 1, 1, sentFrom, sentTo) != "clock")
                            throw new InvalidOperationException("gift_order_selftest_failed");
                    }
                }
                for (int replies = 0; replies <= 3; replies++)
                {
                    if (NextPostLoginStep(0x30, 0x92, 6, true, true, true, replies, replies) !=
                        (replies == 0 ? "gift_out_of_order" : "gift_from"))
                        throw new InvalidOperationException("gift_property_count_selftest_failed");
                }
                if (NextPostLoginStep(0x30, 0x92, 7, true, true, true, 1, 1) != "invalid_header" ||
                    NextPostLoginStep(0x30, 0x90, 5, true, true, true, 1, 1, true) != "invalid_header" ||
                    NextPostLoginStep(0x30, 0x84, 17, true, true, true, 1, 1, true) != "property_phase_closed" ||
                    NextPostLoginStep(0x30, 0x84, 17, true, true, true, 1, 1, true, true) != "property_phase_closed" ||
                    NextPostLoginStep(0x10, 0xa8, 10, true, true, true, 1, 1, true, true) != "empty_buddy_list")
                    throw new InvalidOperationException("gift_phase_or_length_selftest_failed");
                for (int properties = 1; properties <= 3; properties += 2)
                {
                    byte[] replies = new byte[454 + properties * 3928 + 2 * 3507];
                    byte[] requests = new byte[147 + properties * 17 + 18];
                    byte[] skip = new byte[454];
                    try
                    {
                        Array.Copy(encryptedStartup, replies, 454);
                        Cipher outgoing = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                        outgoing.Apply(skip, 0, skip.Length);
                        int responseAt = 454;
                        for (int n = 0; n < properties; n++)
                        {
                            Array.Copy(emptyProperty, 0, replies, responseAt, emptyProperty.Length);
                            outgoing.Apply(replies, responseAt, emptyProperty.Length);
                            responseAt += emptyProperty.Length;
                        }
                        Array.Copy(from, 0, replies, responseAt, from.Length);
                        outgoing.Apply(replies, responseAt, from.Length); responseAt += from.Length;
                        Array.Copy(to, 0, replies, responseAt, to.Length);
                        outgoing.Apply(replies, responseAt, to.Length);
                        string expectedReply = properties == 1 ?
                            "b5c4f46105d97adb8e38d54c480df179092073f5eb62afa777e15dabd9ec03a5" :
                            "372b0a77f95c046f66096bfe075845e0752648331c6dee157e98e7351d6a7a53";
                        if (Sha256(replies) != expectedReply)
                            throw new InvalidOperationException("gift_continuous_reply_selftest_failed");
                        Array.Copy(plaintextStartup, requests, 147);
                        for (int n = 0; n < properties; n++)
                        {
                            int at = 147 + n * 17;
                            requests[at + 1] = 0x30; requests[at + 3] = 17;
                            requests[at + 4] = 0x84; requests[at + 6] = 1;
                            for (int tail = 0; tail < 7; tail++)
                                requests[at + 10 + tail] = n == 0 ? (byte)0 : n == 1 ? (byte)tail : (byte)0xff;
                        }
                        int giftAt = 147 + properties * 17;
                        new byte[] { 0, 0x30, 0, 6, 0x92, 0 }.CopyTo(requests, giftAt);
                        new byte[] { 0, 0x30, 0, 6, 0x90, 0 }.CopyTo(requests, giftAt + 6);
                        // The last request declares ten bytes, but its four-byte
                        // buddy body is deliberately absent and must not be read.
                        new byte[] { 0, 0x10, 0, 10, 0xa8, 0 }.CopyTo(requests, giftAt + 12);
                        new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(requests, 0, requests.Length);
                        string expectedRequest = properties == 1 ?
                            "20507261247c399ebe73b49aec8592c049db45e9d37a864baffec2cf0083b4b8" :
                            "b4abdc2f65ff3c90be81121247aa0b60c8fb2328e48805a674f29de334d22f8c";
                        if (Sha256(requests) != expectedRequest)
                            throw new InvalidOperationException("gift_request_stream_selftest_failed");
                        Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
                        incoming.Apply(requests, 0, 147);
                        for (int n = 0; n < properties; n++)
                        {
                            int at = 147 + n * 17;
                            incoming.Apply(requests, at, 6);
                            incoming.Apply(requests, at + 6, 11);
                        }
                        bool observedFrom = false, observedTo = false;
                        string[] expectedSteps = { "gift_from", "gift_to", "empty_buddy_list" };
                        for (int n = 0; n < 3; n++)
                        {
                            int at = giftAt + n * 6;
                            incoming.Apply(requests, at, 3); incoming.Apply(requests, at + 3, 3);
                            string step = NextPostLoginStep((requests[at] << 8) | requests[at + 1],
                                requests[at + 4] | (requests[at + 5] << 8),
                                (requests[at + 2] << 8) | requests[at + 3],
                                true, true, true, properties, properties, observedFrom, observedTo);
                            if (step != expectedSteps[n])
                                throw new InvalidOperationException("gift_header_sequence_selftest_failed");
                            if (step == "gift_from") observedFrom = true;
                            if (step == "gift_to") observedTo = true;
                        }
                    }
                    finally
                    {
                        Array.Clear(replies, 0, replies.Length);
                        Array.Clear(requests, 0, requests.Length);
                        Array.Clear(skip, 0, skip.Length);
                    }
                }
            }
            finally { Array.Clear(from, 0, from.Length); Array.Clear(to, 0, to.Length); }
        }

        private static void SelfTestBuddyList()
        {
            // All data here is synthetic; no capture file is opened by SelfTest.
            byte[] reply = BuildEmptyBuddyList();
            if (reply.Length != 3008 || reply[0] != 0 || reply[1] != 0x10 ||
                ((reply[2] << 8) | reply[3]) != reply.Length || reply[4] != 0xa9 || reply[5] != 0 ||
                (reply.Length - 8) % 30 != 0 || (reply.Length - 8) / 30 != 100)
                throw new InvalidOperationException("buddy_layout_selftest_failed");
            for (int n = 6; n < reply.Length; n++)
                if (reply[n] != 0) throw new InvalidOperationException("buddy_empty_body_selftest_failed");
            for (int state = 0; state < 8; state++)
            {
                bool gg = (state & 1) != 0, ack = (state & 2) != 0, cash = (state & 4) != 0;
                for (int gifts = 0; gifts < 4; gifts++)
                {
                    bool sentFrom = (gifts & 1) != 0, sentTo = (gifts & 2) != 0;
                    for (int buddy = 0; buddy < 2; buddy++)
                    {
                        string expected = state == 7 && gifts == 3 && buddy == 0 ?
                            "empty_buddy_list" : "buddy_out_of_order";
                        if (NextPostLoginStep(0x10, 0xa8, 10, gg, ack, cash, 1, 1,
                                sentFrom, sentTo, buddy == 1) != expected)
                            throw new InvalidOperationException("buddy_order_selftest_failed");
                    }
                }
            }
            if (NextPostLoginStep(0x10, 0xa8, 9, true, true, true, 1, 1, true, true) != "invalid_header" ||
                NextPostLoginStep(0x10, 0xa8, 11, true, true, true, 1, 1, true, true) != "invalid_header" ||
                NextPostLoginStep(0x30, 0x92, 6, true, true, true, 1, 1, true, true, true) != "gift_out_of_order" ||
                NextPostLoginStep(0x30, 0x86, 10, true, true, true, 1, 1, true, true, true) != "local_avatar_list")
                throw new InvalidOperationException("buddy_phase_selftest_failed");
            // Cipher alignment: buddy header, its four-byte body, then the next header.
            // Decrypting piecewise as ObservePostLogin does must recover the next
            // header; skipping the body must not (the v1.8 behaviour stopped there).
            byte[] plain = { 0, 0x10, 0, 10, 0xa8, 0, 0, 0, 0, 0, 0, 0x30, 0, 10, 0x86, 0 };
            byte[] wire = (byte[])plain.Clone();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);
            byte[] aligned = (byte[])wire.Clone();
            Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            incoming.Apply(aligned, 0, 6); incoming.Apply(aligned, 6, 4); incoming.Apply(aligned, 10, 6);
            int nextType = (aligned[10] << 8) | aligned[11];
            int nextLength = (aligned[12] << 8) | aligned[13];
            int nextAction = aligned[14] | (aligned[15] << 8);
            byte[] skipped = (byte[])wire.Clone();
            Cipher unaligned = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            unaligned.Apply(skipped, 0, 6); unaligned.Apply(skipped, 10, 6);
            if (nextType != 0x30 || nextLength != 10 || nextAction != 0x86 ||
                NextPostLoginStep(nextType, nextAction, nextLength, true, true, true, 1, 1,
                    true, true, true) != "local_avatar_list" ||
                (skipped[11] == 0x30 && skipped[14] == 0x86))
                throw new InvalidOperationException("buddy_cipher_alignment_selftest_failed");
        }

        private static void SelfTestAvatarSteps()
        {
            // All data here is synthetic; no capture file is opened by SelfTest.
            byte[] list = BuildLocalAvatarList();
            byte[] equipped = BuildLocalEquippedAvatar();
            byte[] equipment = BuildEmptyAvatarEquipment();
            if (list.Length != 87 || ((list[2] << 8) | list[3]) != 87 || list[1] != 0x30 || list[4] != 0x87 ||
                list[6] != 1 || list[7] != 1 || list[8] != 0 || list[9] != 0 || list[10] != 0)
                throw new InvalidOperationException("avatar_list_layout_selftest_failed");
            for (int n = 11; n < list.Length; n++)
                if (list[n] != 0) throw new InvalidOperationException("avatar_list_unused_selftest_failed");
            if (equipped.Length != 10 || equipped[1] != 0x40 || equipped[3] != 10 || equipped[4] != 0xa1 ||
                equipped[6] != list[7] || equipped[7] != 0 || equipped[8] != 0 || equipped[9] != 0)
                throw new InvalidOperationException("equipped_avatar_layout_selftest_failed");
            if (equipment.Length != 366 || ((equipment[2] << 8) | equipment[3]) != 366 ||
                equipment[1] != 0x30 || equipment[4] != 0x89 || (equipment.Length - 6) != 45 * 4 + 180)
                throw new InvalidOperationException("equipment_layout_selftest_failed");
            for (int n = 6; n < equipment.Length; n++)
                if (equipment[n] != 0) throw new InvalidOperationException("equipment_empty_selftest_failed");
            // Order: each step only once, only in sequence, only after the buddy list.
            int[][] steps = { new[] { 0x30, 0x86, 10 }, new[] { 0x40, 0xa0, 6 }, new[] { 0x30, 0x88, 10 } };
            string[] names = { "local_avatar_list", "equipped_avatar", "avatar_equipment" };
            for (int stage = 0; stage <= 3; stage++)
                for (int s = 0; s < 3; s++)
                    for (int buddy = 0; buddy < 2; buddy++)
                    {
                        string expected = buddy == 1 && stage == s ? names[s] : "avatar_out_of_order";
                        if (NextPostLoginStep(steps[s][0], steps[s][1], steps[s][2], true, true, true, 1, 1,
                                true, true, buddy == 1, stage) != expected)
                            throw new InvalidOperationException("avatar_order_selftest_failed");
                        if (NextPostLoginStep(steps[s][0], steps[s][1], steps[s][2] + 1, true, true, true, 1, 1,
                                true, true, buddy == 1, stage) != "invalid_header")
                            throw new InvalidOperationException("avatar_length_selftest_failed");
                    }
            // Avatar update acks: only after the full chain, exact lengths, header-only replies.
            int[][] acks = { new[] { 0xa2, 10 }, new[] { 0xa4, 15 }, new[] { 0xa6, 11 } };
            foreach (int[] ack in acks)
            {
                for (int stage = 0; stage <= 3; stage++)
                    if (NextPostLoginStep(0x40, ack[0], ack[1], true, true, true, 1, 1, true, true, true, stage) !=
                        (stage == 3 ? "avatar_update_ack" : "avatar_out_of_order"))
                        throw new InvalidOperationException("avatar_ack_order_selftest_failed");
                if (NextPostLoginStep(0x40, ack[0], ack[1] - 1, true, true, true, 1, 1, true, true, true, 3) != "invalid_header" ||
                    NextPostLoginStep(0x40, ack[0], ack[1] + 1, true, true, true, 1, 1, true, true, true, 3) != "invalid_header")
                    throw new InvalidOperationException("avatar_ack_length_selftest_failed");
                byte[] reply = BuildAvatarUpdateAck(ack[0]);
                if (reply.Length != 6 || reply[1] != 0x40 || reply[3] != 6 || reply[4] != ack[0] + 1 || reply[5] != 0)
                    throw new InvalidOperationException("avatar_ack_layout_selftest_failed");
            }
            bool ackRejected = false;
            try { BuildAvatarUpdateAck(0xa0); }
            catch (InvalidOperationException ex) { ackRejected = ex.Message == "avatar_ack_action_invalid"; }
            if (!ackRejected ||
                CheckStepBody("avatar_update_ack", new byte[] { 1, 0, 0, 0, 0x0a }) != null ||
                CheckStepBody("avatar_update_ack", new byte[] { 2, 0, 0, 0, 0x0a }) != "avatar_update_mismatch")
                throw new InvalidOperationException("avatar_ack_body_selftest_failed");
            if (NextPostLoginStep(0x30, 0xa0, 6, true, true, true, 1, 1, true, true, true, 3) != "local_grade_list" ||
                NextPostLoginStep(0x10, 0xa8, 10, true, true, true, 1, 1, true, true, true, 1) != "buddy_out_of_order")
                throw new InvalidOperationException("avatar_phase_selftest_failed");
            // Body checks: owner/avatar must be exactly LE32 1; buddy body must be zero.
            if (CheckStepBody("local_avatar_list", new byte[] { 1, 0, 0, 0 }) != null ||
                CheckStepBody("local_avatar_list", new byte[] { 2, 0, 0, 0 }) != "avatar_owner_mismatch" ||
                CheckStepBody("local_avatar_list", new byte[] { 1, 0, 0, 1 }) != "avatar_owner_mismatch" ||
                CheckStepBody("avatar_equipment", new byte[] { 1, 0, 0, 0 }) != null ||
                CheckStepBody("avatar_equipment", new byte[] { 0, 0, 0, 0 }) != "equipment_avatar_mismatch" ||
                CheckStepBody("empty_buddy_list", new byte[4]) != null ||
                CheckStepBody("empty_buddy_list", new byte[] { 0, 0, 1, 0 }) != "buddy_body_nonzero")
                throw new InvalidOperationException("step_body_selftest_failed");
            // Cipher alignment through the whole chain to the next unsupported header.
            byte[] plain = {
                0, 0x10, 0, 10, 0xa8, 0, 0, 0, 0, 0,
                0, 0x30, 0, 10, 0x86, 0, 1, 0, 0, 0,
                0, 0x40, 0, 6, 0xa0, 0,
                0, 0x30, 0, 10, 0x88, 0, 1, 0, 0, 0,
                0, 0x40, 0, 11, 0xa6, 0, 1, 0, 0, 0, 0x0a,
                0, 0x40, 0, 15, 0xa4, 0, 1, 0, 0, 0, 9, 8, 7, 6, 5,
                0, 0x40, 0, 10, 0xa2, 0, 1, 0, 0, 0,
                0, 0x30, 0, 6, 0xa0, 0 };
            byte[] wire = (byte[])plain.Clone();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);
            Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            bool buddyDone = false; int stageNow = 0; int at = 0;
            string[] expectedChain = { "empty_buddy_list", "local_avatar_list", "equipped_avatar",
                "avatar_equipment", "avatar_update_ack", "avatar_update_ack", "avatar_update_ack",
                "local_grade_list" };
            foreach (string expectedStep in expectedChain)
            {
                incoming.Apply(wire, at, 6);
                int type = (wire[at] << 8) | wire[at + 1];
                int length = (wire[at + 2] << 8) | wire[at + 3];
                int action = wire[at + 4] | (wire[at + 5] << 8);
                string step = NextPostLoginStep(type, action, length, true, true, true, 1, 1,
                    true, true, buddyDone, stageNow);
                if (step != expectedStep) throw new InvalidOperationException("avatar_chain_selftest_failed");
                at += 6;
                if (length > 6 && step != "unsupported_header")
                {
                    byte[] body = new byte[length - 6];
                    Array.Copy(wire, at, body, 0, body.Length);
                    incoming.Apply(body, 0, body.Length);
                    if (CheckStepBody(step, body) != null)
                        throw new InvalidOperationException("avatar_chain_body_selftest_failed");
                    if (action == 0xa6 && body[4] != 0x0a)
                        throw new InvalidOperationException("avatar_chain_a6_byte_selftest_failed");
                    at += body.Length;
                }
                if (step == "empty_buddy_list") buddyDone = true;
                else if (step == "local_avatar_list") stageNow = 1;
                else if (step == "equipped_avatar") stageNow = 2;
                else if (step == "avatar_equipment") stageNow = 3;
            }
            if (at != wire.Length) throw new InvalidOperationException("avatar_chain_length_selftest_failed");
        }

        private static int Le32(byte[] b, int offset)
        {
            return b[offset] | (b[offset + 1] << 8) | (b[offset + 2] << 16) | (b[offset + 3] << 24);
        }

        private static void SelfTestClassFixture()
        {
            byte[] property = BuildLocalClassPropertyResponse(null);
            byte[] equipment = BuildLocalClassEquipment();
            byte[] emptyProperty = BuildEmptyPropertyResponse();
            byte[] emptyEquipment = BuildEmptyAvatarEquipment();
            if (property.Length != 3928 || property[1] != 0x30 || property[4] != 0x85 ||
                (property[6] | (property[7] << 8)) != 3)
                throw new InvalidOperationException("class_property_layout_selftest_failed");
            int count = property[6] | (property[7] << 8);
            int slot0 = Le32(equipment, 6);
            bool resolves = false;
            for (int n = 0; n < count; n++)
            {
                int record = 8 + 49 * n;
                if (Le32(property, record) == slot0) resolves = true;
            }
            // Consistency rule from all 40 captured replies: slot 0 is a non-zero
            // inventory INSTANCE (not catalog) ID present in the inventory page.
            if (slot0 == 0 || !resolves || slot0 == Le32(property, 12) ||
                Le32(property, 12) != ClassCatalogId || Le32(property, 16) != ClassRecordWord8 ||
                Le32(property, 8 + 29) != 0 || Le32(property, 8 + 33) != 0)
                throw new InvalidOperationException("class_reference_selftest_failed");
            // Exact expected page: two records, every unlisted byte zero.
            byte[] expectedPage = BuildEmptyPropertyResponse();
            expectedPage[6] = 3;
            PutLe32(expectedPage, 106, 1003); PutLe32(expectedPage, 110, 2040035); PutLe32(expectedPage, 114, 85582);
            PutLe32(expectedPage, 135, 1000);
            PutLe32(expectedPage, 8, 1001); PutLe32(expectedPage, 12, 1000176); PutLe32(expectedPage, 16, 20046);
            PutLe32(expectedPage, 57, 1002); PutLe32(expectedPage, 61, 5135224); PutLe32(expectedPage, 65, 85582);
            PutLe32(expectedPage, 86, 1000);
            for (int n = 0; n < property.Length; n++)
                if (property[n] != expectedPage[n]) throw new InvalidOperationException("class_property_zero_selftest_failed");
            // The rod is owned but never equipped (no captured slot references a rod).
            for (int n = 0; n < 45; n++)
                if (Le32(equipment, 6 + 4 * n) == LocalRodInstanceId || Le32(equipment, 6 + 4 * n) == LocalExoInstanceId)
                    throw new InvalidOperationException("rod_equipped_selftest_failed");
            for (int n = 10; n < equipment.Length; n++)
                if (equipment[n] != 0) throw new InvalidOperationException("class_equipment_zero_selftest_failed");
            if (slot0 == LocalAvatarId || slot0 == 1)
                throw new InvalidOperationException("class_instance_distinct_selftest_failed");
            // The comparison fixture is exactly v1.12: zero count, zero equipment.
            for (int n = 6; n < emptyProperty.Length; n++)
                if (emptyProperty[n] != 0) throw new InvalidOperationException("empty_fixture_selftest_failed");
            for (int n = 6; n < emptyEquipment.Length; n++)
                if (emptyEquipment[n] != 0) throw new InvalidOperationException("empty_fixture_selftest_failed");
            for (int n = 0; n < 6; n++)
                if (property[n] != emptyProperty[n] || equipment[n] != emptyEquipment[n])
                    throw new InvalidOperationException("fixture_header_selftest_failed");
        }

        private static void SelfTestLobbyQueries()
        {
            byte[] grade = BuildLocalGradeList(false);
            byte[] b4 = BuildZeroB4Status();
            if (grade.Length != 345 || grade[1] != 0x30 || ((grade[2] << 8) | grade[3]) != grade.Length ||
                grade[4] != 0xa1 || grade[6] != 26 || (grade.Length - 7) != 13 * grade[6])
                throw new InvalidOperationException("grade_layout_selftest_failed");
            // IDs ascending, include 1, 2 and 95; only 95 carries values, exactly (0, 0, 2).
            // The other omitted common IDs (35, 108, 121, 122) stay out: one change per run.
            int previous = 0;
            bool has95 = false;
            for (int n = 0; n < grade[6]; n++)
            {
                int rec = 7 + 13 * n;
                int id = grade[rec];
                if (id <= previous || id == 35 || id == 108 || id == 121 || id == 122)
                    throw new InvalidOperationException("grade_ids_selftest_failed");
                previous = id;
                int a = Le32(grade, rec + 1), b = Le32(grade, rec + 5), c = Le32(grade, rec + 9);
                if (id == 95) { has95 = true; if (a != 0 || b != 0 || c != 2) throw new InvalidOperationException("grade_values_selftest_failed"); }
                else if (a != 0 || b != 0 || c != 0) throw new InvalidOperationException("grade_values_selftest_failed");
            }
            if (!has95) throw new InvalidOperationException("grade_ids_selftest_failed");
            if (grade[7] != 1 || grade[20] != 2) throw new InvalidOperationException("grade_ids_selftest_failed");
            if (NextPostLoginStep(0x31, 0x8c, 7, true, true, true, 1, 1, true, true, true, 3, 1) != "grade_up_request" ||
                NextPostLoginStep(0x31, 0x8c, 7, true, true, true, 1, 1, true, true, true, 3, 0) != "grade_out_of_order" ||
                NextPostLoginStep(0x31, 0x8c, 6, true, true, true, 1, 1, true, true, true, 3, 1) != "invalid_header" ||
                NextPostLoginStep(0x31, 0x8c, 7, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, GradeUpLimit - 1) != "grade_up_request" ||
                NextPostLoginStep(0x31, 0x8c, 7, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, GradeUpLimit) != "grade_out_of_order")
                throw new InvalidOperationException("grade_up_selftest_failed");
            if (b4.Length != 25 || b4[1] != 0x30 || b4[3] != 25 || b4[4] != 0xb5)
                throw new InvalidOperationException("b4_layout_selftest_failed");
            for (int n = 6; n < b4.Length; n++)
                if (b4[n] != 0) throw new InvalidOperationException("b4_zero_selftest_failed");
            // Grade only after the avatar chain, bounded repeats; B4 only after a grade reply.
            for (int stage = 0; stage <= 3; stage++)
                if (NextPostLoginStep(0x30, 0xa0, 6, true, true, true, 1, 1, true, true, true, stage) !=
                    (stage == 3 ? "local_grade_list" : "grade_out_of_order"))
                    throw new InvalidOperationException("grade_order_selftest_failed");
            if (NextPostLoginStep(0x30, 0xa0, 6, true, true, true, 1, 1, true, true, true, 3, GradeRequestLimit) != "grade_out_of_order" ||
                NextPostLoginStep(0x30, 0xa0, 7, true, true, true, 1, 1, true, true, true, 3) != "invalid_header" ||
                NextPostLoginStep(0x30, 0xb4, 10, true, true, true, 1, 1, true, true, true, 3, 0) != "b4_out_of_order" ||
                NextPostLoginStep(0x30, 0xb4, 10, true, true, true, 1, 1, true, true, true, 3, 1, 4) != "zero_b4_status" ||
                NextPostLoginStep(0x30, 0xb4, 10, true, true, true, 1, 1, true, true, true, 3, 1, 5) != "b4_out_of_order" ||
                NextPostLoginStep(0x30, 0xb4, 11, true, true, true, 1, 1, true, true, true, 3, 1, 0) != "invalid_header")
                throw new InvalidOperationException("b4_order_selftest_failed");
            // GameGuard answer: accepted (no reply) only after the init replay; bounded size/count.
            if (NextPostLoginStep(0x48, 0x42, 124, true, true, true, 1) != "gameguard_answer" ||
                NextPostLoginStep(0x48, 0x42, 116, false, false, false, 0) != "gameguard_answer_unexpected" ||
                NextPostLoginStep(0x48, 0x42, 124, true, true, true, 1, 0, false, false, false, 0, 0, 0, GuardAnswerLimit) != "gameguard_answer_unexpected" ||
                NextPostLoginStep(0x48, 0x42, 6, true, true, true, 1) != "invalid_header" ||
                NextPostLoginStep(0x48, 0x42, 513, true, true, true, 1) != "invalid_header" ||
                NextPostLoginStep(0x48, 0x80, 6, true, true, true, 1) != "startup_out_of_order")
                throw new InvalidOperationException("guard_answer_selftest_failed");
            // Cipher alignment: grade, B4 x2, a 124-byte GG answer, B4 x3, then 30/B2.
            byte[] plain = new byte[6 + 10 * 2 + 124 + 10 * 3 + 6];
            int at = 0;
            new byte[] { 0, 0x30, 0, 6, 0xa0, 0 }.CopyTo(plain, at); at += 6;
            for (int n = 1; n <= 2; n++) { new byte[] { 0, 0x30, 0, 10, 0xb4, 0, (byte)n, 0, 0, 0 }.CopyTo(plain, at); at += 10; }
            new byte[] { 0, 0x48, 0, 124, 0x42, 0 }.CopyTo(plain, at);
            for (int n = 6; n < 124; n++) plain[at + n] = (byte)(n * 7);
            at += 124;
            for (int n = 3; n <= 5; n++) { new byte[] { 0, 0x30, 0, 10, 0xb4, 0, (byte)n, 0, 0, 0 }.CopyTo(plain, at); at += 10; }
            new byte[] { 0, 0x30, 0, 6, 0xb2, 0 }.CopyTo(plain, at);
            byte[] wire = (byte[])plain.Clone();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);
            Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            int grades = 0, b4s = 0, answers = 0;
            string[] expected = { "local_grade_list", "zero_b4_status", "zero_b4_status", "gameguard_answer",
                "zero_b4_status", "zero_b4_status", "zero_b4_status", "login_check" };
            at = 0;
            foreach (string want in expected)
            {
                incoming.Apply(wire, at, 6);
                int type = (wire[at] << 8) | wire[at + 1];
                int length = (wire[at + 2] << 8) | wire[at + 3];
                int action = wire[at + 4] | (wire[at + 5] << 8);
                string step = NextPostLoginStep(type, action, length, true, true, true, 1, 1, true, true, true, 3,
                    grades, b4s, answers);
                if (step != want) throw new InvalidOperationException("lobby_query_chain_selftest_failed");
                at += 6;
                if (step == "unsupported_header") break;
                if (length > 6)
                {
                    incoming.Apply(wire, at, length - 6);
                    byte[] body = new byte[length - 6];
                    Array.Copy(wire, at, body, 0, body.Length);
                    if (step == "zero_b4_status" && CheckB4Body(body, b4s) != null)
                        throw new InvalidOperationException("b4_index_chain_selftest_failed");
                    at += length - 6;
                }
                if (step == "local_grade_list") grades++;
                else if (step == "zero_b4_status") b4s++;
                else if (step == "gameguard_answer") answers++;
            }
            if (at != wire.Length || b4s != 5 || answers != 1)
                throw new InvalidOperationException("lobby_query_chain_length_selftest_failed");
            byte[] qb = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            byte[] qa = BuildQuestUpdateAck(qb);
            if (qa.Length != 18 || qa[1] != 0x30 || qa[3] != 18 || qa[4] != 0xcf || qa[5] != 0 || qa[6] != 1 || qa[17] != 12 ||
                NextPostLoginStep(0x30, 0xce, 18, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 0) != "menu_out_of_order" ||
                NextPostLoginStep(0x30, 0xce, 18, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 1) != "quest_update" ||
                NextPostLoginStep(0x30, 0xce, 17, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 1) != "invalid_header")
                throw new InvalidOperationException("quest_update_selftest_failed");
            if (CheckB4Body(new byte[] { 2, 0, 0, 0 }, 0) != "b4_index_unexpected" ||
                CheckB4Body(new byte[] { 1, 0, 0, 0 }, 1) != "b4_index_unexpected" ||
                CheckB4Body(new byte[] { 5, 0, 0, 0 }, 4) != null)
                throw new InvalidOperationException("b4_index_selftest_failed");
        }

        private static void SelfTestAddItem()
        {
            byte[] failure = BuildAddItemFailure(AddItemChannel100FailureCode);
            byte[] expectedHead = { 0, 0x31, 0x02, 0x08, 0x8b, 0x01, 0x11, 0x27,
                (byte)'F', (byte)'A', (byte)'I', (byte)'L', (byte)'(', (byte)'u', (byte)'n', (byte)'k',
                (byte)'n', (byte)'o', (byte)'w', (byte)'n', (byte)')', 0 };
            if (failure.Length != 520 || ((failure[2] << 8) | failure[3]) != 520)
                throw new InvalidOperationException("add_item_failure_layout_selftest_failed");
            for (int n = 0; n < failure.Length; n++)
                if (failure[n] != (n < expectedHead.Length ? expectedHead[n] : (byte)0))
                    throw new InvalidOperationException("add_item_failure_bytes_selftest_failed");
            byte[] claim100 = { 2, 100, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] claim95 = { 2, 95, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] claim100Tail = { 2, 100, 0, 0, 0, 0, 0, 0, 0, 1 };
            byte[] level1 = { 1, 0, 0x61, 0xa6, 0x4c, 0, 0xe8, 0x03, 0, 0 };
            byte[] otherItem = { 1, 0, 0x62, 0xa6, 0x4c, 0, 0xe8, 0x03, 0, 0 };
            byte[] exoGrant = { 0, 0, 0xe3, 0x20, 0x1f, 0, 0xe8, 0x03, 0, 0 };
            if (!IsLevelOneRewardGrant(level1) || IsLevelOneRewardGrant(otherItem) || IsLevelOneRewardGrant(exoGrant) ||
                IsLevelOneRewardGrant(claim100) || IsChannel100Claim(level1) || IsLevelOneRewardGrant(new byte[9]))
                throw new InvalidOperationException("level_grant_match_selftest_failed");
            if (!IsChannel100Claim(claim100) || IsChannel100Claim(claim95) || IsChannel100Claim(claim100Tail) ||
                IsChannel100Claim(new byte[9]) || IsChannel100Claim(new byte[] { 1, 100, 0, 0, 0, 0, 0, 0, 0, 0 }))
                throw new InvalidOperationException("add_item_match_selftest_failed");
            if (NextPostLoginStep(0x31, 0x8a, 16, true, true, true, 1, 1, true, true, true, 3, 1) != "add_item" ||
                NextPostLoginStep(0x31, 0x8a, 16, true, true, true, 1, 1, true, true, true, 3, 0) != "add_item_out_of_order" ||
                NextPostLoginStep(0x31, 0x8a, 15, true, true, true, 1, 1, true, true, true, 3, 1) != "invalid_header" ||
                NextPostLoginStep(0x31, 0x18b, 520, true, true, true, 1, 1, true, true, true, 3, 1) != "unsupported_header")
                throw new InvalidOperationException("add_item_order_selftest_failed");
            // Cipher continuity: grade, ADD_ITEM(100), unsupported 30/BC with an 8-byte body,
            // ADD_ITEM(95), then a final header that must still decode.
            byte[] plain = new byte[6 + 16 + 14 + 16 + 6];
            int pos = 0;
            new byte[] { 0, 0x30, 0, 6, 0xa0, 0 }.CopyTo(plain, pos); pos += 6;
            new byte[] { 0, 0x31, 0, 16, 0x8a, 0 }.CopyTo(plain, pos); claim100.CopyTo(plain, pos + 6); pos += 16;
            new byte[] { 0, 0x31, 0, 14, 0xd6, 0, 9, 8, 7, 6, 5, 4, 3, 2 }.CopyTo(plain, pos); pos += 14;
            new byte[] { 0, 0x31, 0, 16, 0x8a, 0 }.CopyTo(plain, pos); claim95.CopyTo(plain, pos + 6); pos += 16;
            new byte[] { 0, 0x31, 0, 6, 0xc8, 0 }.CopyTo(plain, pos);
            byte[] wire = (byte[])plain.Clone();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);
            Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            string[] want = { "local_grade_list", "add_item", "unsupported_header", "add_item", "unsupported_header" };
            int grades = 0; pos = 0;
            bool[] matched = new bool[2]; int adds = 0;
            foreach (string expected in want)
            {
                incoming.Apply(wire, pos, 6);
                int type = (wire[pos] << 8) | wire[pos + 1];
                int length = (wire[pos + 2] << 8) | wire[pos + 3];
                int action = wire[pos + 4] | (wire[pos + 5] << 8);
                string step = NextPostLoginStep(type, action, length, true, true, true, 1, 1, true, true, true, 3, grades);
                if (step != expected) throw new InvalidOperationException("add_item_chain_selftest_failed");
                pos += 6;
                if (pos == wire.Length) break;
                byte[] body = new byte[length - 6];
                Array.Copy(wire, pos, body, 0, body.Length);
                incoming.Apply(body, 0, body.Length);
                pos += body.Length;
                if (step == "local_grade_list") grades++;
                if (step == "add_item") matched[adds++] = IsChannel100Claim(body);
            }
            if (pos != wire.Length || !matched[0] || matched[1])
                throw new InvalidOperationException("add_item_chain_alignment_selftest_failed");
        }

        private static byte[] SyntheticLobbyFixture(bool dropBd, bool duplicatePage, bool badMagic, int bdTotal = 47,
                                                    bool dropReward = false, int rewardCatalog = 3043117)
        {
            List<byte> data = new List<byte>(new byte[] { (byte)'R', (byte)'F', (byte)'L', (byte)'F', (byte)(badMagic ? '2' : '1'), 0 });
            List<byte[]> entries = new List<byte[]>();
            Func<int, int, int, byte[], byte[]> entry = (kind, action, total, request) =>
            {
                List<byte> e = new List<byte> { (byte)kind, (byte)request.Length };
                e.AddRange(request);
                e.Add((byte)total); e.Add((byte)(total >> 8));
                byte[] frame = new byte[total];
                frame[1] = 0x30; frame[2] = (byte)(total >> 8); frame[3] = (byte)total; frame[4] = (byte)action;
                frame[total - 1] = (byte)kind;  // marker so replies are distinguishable
                e.AddRange(frame);
                return e.ToArray();
            };
            entries.Add(entry(1, 0xb3, 46, new byte[0]));
            entries.Add(entry(2, 0xbb, 14, new byte[0]));
            if (!dropBd) entries.Add(entry(3, 0xbd, bdTotal, new byte[0]));
            for (int n = 0; n < 5; n++)
                entries.Add(entry(4, 0xcd, 1810, new byte[] { (byte)(duplicatePage && n == 4 ? 1 : n + 1), 0, 0, 0, 0, 0, 0, 0 }));
            if (!dropReward)
            {
                byte[] record = new byte[49];
                PutLe32(record, 0, 777); PutLe32(record, 4, rewardCatalog); PutLe32(record, 8, 87118);
                PutLe32(record, 29, 1176); record[25] = 0x5a;  // synthetic opaque byte
                List<byte> e = new List<byte> { 5, 0, 49, 0 };
                e.AddRange(record);
                entries.Add(e.ToArray());
            }
            data.Add((byte)entries.Count); data.Add(0);
            foreach (byte[] e in entries) data.AddRange(e);
            return data.ToArray();
        }

        private static void SelfTestMainMenu()
        {
            LobbyFixture fixture = ParseLobbyFixture(SyntheticLobbyFixture(false, false, false));
            if (fixture.B3.Length != 46 || fixture.BB.Length != 14 || fixture.BD.Length != 47 || fixture.Pages.Count != 5 ||
                !fixture.Pages.ContainsKey("0300000000000000"))
                throw new InvalidOperationException("menu_fixture_parse_selftest_failed");
            foreach (bool[] bad in new[] { new[] { true, false, false }, new[] { false, true, false }, new[] { false, false, true } })
            {
                bool rejected = false;
                try { ParseLobbyFixture(SyntheticLobbyFixture(bad[0], bad[1], bad[2])); }
                catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("menu_fixture_reject_selftest_failed");
            }
            bool wrongLengthRejected = false;
            try { ParseLobbyFixture(SyntheticLobbyFixture(false, false, false, 46)); }
            catch (InvalidOperationException) { wrongLengthRejected = true; }
            if (!wrongLengthRejected) throw new InvalidOperationException("menu_fixture_length_selftest_failed");
            byte[] truncated = SyntheticLobbyFixture(false, false, false);
            Array.Resize(ref truncated, truncated.Length - 1);
            bool truncatedRejected = false;
            try { ParseLobbyFixture(truncated); } catch (InvalidOperationException) { truncatedRejected = true; }
            if (!truncatedRejected) throw new InvalidOperationException("menu_fixture_truncation_selftest_failed");
            // Order: B2 only after a grade reply and once; BA after B2; BC after BA (repeatable); CC after BC.
            if (NextPostLoginStep(0x30, 0xb2, 6, true, true, true, 1, 1, true, true, true, 3, 0) != "menu_out_of_order" ||
                NextPostLoginStep(0x30, 0xb2, 6, true, true, true, 1, 1, true, true, true, 3, 1) != "login_check" ||
                NextPostLoginStep(0x30, 0xb2, 6, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 1) != "menu_out_of_order" ||
                NextPostLoginStep(0x30, 0xba, 6, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 0) != "menu_out_of_order" ||
                NextPostLoginStep(0x30, 0xba, 6, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 1) != "menu_ba" ||
                NextPostLoginStep(0x30, 0xbc, 6, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 1) != "menu_out_of_order" ||
                NextPostLoginStep(0x30, 0xbc, 6, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3, 5) != "menu_bc" ||
                NextPostLoginStep(0x30, 0xbc, 6, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3, MenuRepeatLimit) != "menu_out_of_order" ||
                NextPostLoginStep(0x30, 0xcc, 14, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 2) != "menu_out_of_order" ||
                NextPostLoginStep(0x30, 0xcc, 14, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3) != "menu_cc" ||
                NextPostLoginStep(0x30, 0xcc, 13, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3) != "invalid_header" ||
                NextPostLoginStep(0x30, 0xb2, 7, true, true, true, 1, 1, true, true, true, 3, 1) != "invalid_header")
                throw new InvalidOperationException("menu_order_selftest_failed");
            // Cipher continuity: B2, BA, BC, CC(known page), CC(unknown page), BC, then 10/B6.
            byte[] plain = new byte[6 * 3 + 14 * 2 + 6 + 7];
            int pos = 0;
            foreach (int action in new[] { 0xb2, 0xba, 0xbc }) { new byte[] { 0, 0x30, 0, 6, (byte)action, 0 }.CopyTo(plain, pos); pos += 6; }
            new byte[] { 0, 0x30, 0, 14, 0xcc, 0, 3, 0, 0, 0, 0, 0, 0, 0 }.CopyTo(plain, pos); pos += 14;
            new byte[] { 0, 0x30, 0, 14, 0xcc, 0, 9, 0, 0, 0, 1, 2, 3, 4 }.CopyTo(plain, pos); pos += 14;
            new byte[] { 0, 0x30, 0, 6, 0xbc, 0 }.CopyTo(plain, pos); pos += 6;
            new byte[] { 0, 0x10, 0, 7, 0xb6, 0, 1 }.CopyTo(plain, pos);
            byte[] wire = (byte[])plain.Clone();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);
            Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            string[] want = { "login_check", "menu_ba", "menu_bc", "menu_cc", "menu_cc", "menu_bc", "lobby_b6" };
            int stage = 0, bcs = 0, ccs = 0, matched = 0; pos = 0;
            foreach (string expected in want)
            {
                incoming.Apply(wire, pos, 6);
                int type = (wire[pos] << 8) | wire[pos + 1], length = (wire[pos + 2] << 8) | wire[pos + 3];
                int action = wire[pos + 4] | (wire[pos + 5] << 8);
                string step = NextPostLoginStep(type, action, length, true, true, true, 1, 1, true, true, true, 3, 1,
                    0, 0, 0, stage, bcs, ccs);
                if (step != expected) throw new InvalidOperationException("menu_chain_selftest_failed");
                pos += 6;
                byte[] body = new byte[length - 6];
                Array.Copy(wire, pos, body, 0, body.Length);
                incoming.Apply(body, 0, body.Length);
                pos += body.Length;
                if (step == "login_check") stage = 1;
                else if (step == "menu_ba") stage = 2;
                else if (step == "menu_bc") { stage = 3; bcs++; }
                else if (step == "menu_cc")
                {
                    ccs++;
                    if (fixture.Pages.ContainsKey(BitConverter.ToString(body).Replace("-", "").ToLowerInvariant())) matched++;
                }
            }
            if (pos != wire.Length || matched != 1 || bcs != 2)
                throw new InvalidOperationException("menu_chain_alignment_selftest_failed");
        }

        private static void SelfTestLobbySession()
        {
            // Fixture: reward record required, catalog checked.
            if (ParseLobbyFixture(SyntheticLobbyFixture(false, false, false)).RewardRecord == null)
                throw new InvalidOperationException("reward_fixture_selftest_failed");
            foreach (bool dropReward in new[] { true, false })
            {
                bool rejected = false;
                try { ParseLobbyFixture(SyntheticLobbyFixture(false, false, false, 47, dropReward, dropReward ? 3043117 : 5135224)); }
                catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("reward_fixture_reject_selftest_failed");
            }
            // Claimed-95 consistency: 4 records, reward copied exactly except the instance ID.
            byte[] reward = ParseLobbyFixture(SyntheticLobbyFixture(false, false, false)).RewardRecord;
            byte[] page = BuildLocalClassPropertyResponse(reward);
            if ((page[6] | (page[7] << 8)) != 4 || Le32(page, 155) != LocalRewardInstanceId || Le32(page, 159) != 3043117)
                throw new InvalidOperationException("reward_page_selftest_failed");
            for (int n = 4; n < 49; n++)
                if (page[155 + n] != reward[n]) throw new InvalidOperationException("reward_record_copy_selftest_failed");
            for (int n = 155 + 49; n < page.Length; n++)
                if (page[n] != 0) throw new InvalidOperationException("reward_page_tail_selftest_failed");
            byte[] three = BuildLocalClassPropertyResponse(null);
            for (int n = 0; n < 155; n++)
                if (n != 6 && page[n] != three[n]) throw new InvalidOperationException("reward_page_prefix_selftest_failed");
            bool badReward = false;
            try { BuildLocalClassPropertyResponse(new byte[49]); } catch (InvalidOperationException) { badReward = true; }
            if (!badReward) throw new InvalidOperationException("reward_record_check_selftest_failed");
            // Grade 95: claimed (1,1,2) vs unclaimed (0,0,2); every other byte identical.
            byte[] claimed = BuildLocalGradeList(true), unclaimed = BuildLocalGradeList(false);
            int at95 = 7 + 13 * Array.IndexOf(LocalGradeIds, (byte)95);
            if (Le32(claimed, at95 + 1) != 1 || Le32(claimed, at95 + 5) != 1 || Le32(claimed, at95 + 9) != 2 ||
                Le32(unclaimed, at95 + 1) != 0 || Le32(unclaimed, at95 + 5) != 0 || Le32(unclaimed, at95 + 9) != 2)
                throw new InvalidOperationException("grade95_selftest_failed");
            for (int n = 0; n < claimed.Length; n++)
                if ((n < at95 + 1 || n > at95 + 8) && claimed[n] != unclaimed[n])
                    throw new InvalidOperationException("grade95_isolation_selftest_failed");
            // B6 and room list replies, bodies, order.
            byte[] b6 = BuildB6Reply(), rooms = BuildEmptyRoomList();
            if (b6.Length != 7 || b6[0] != 2 || b6[1] != 0x10 || b6[3] != 7 || b6[4] != 0xb7 || b6[6] != 1 ||
                rooms.Length != 16 || rooms[1] != 0x40 || rooms[3] != 16 || rooms[4] != 0x85 || (rooms.Length - 6 - 10) % 223 != 0)
                throw new InvalidOperationException("lobby_reply_layout_selftest_failed");
            for (int n = 6; n < rooms.Length; n++) if (rooms[n] != 0) throw new InvalidOperationException("room_list_empty_selftest_failed");
            if (!IsB6Body(new byte[] { 1 }) || IsB6Body(new byte[] { 2 }) || IsB6Body(new byte[0]) ||
                !IsRoomPollBody(new byte[] { 0x0a, 0, 0, 0, 0, 0, 0, 0x46 }) || IsRoomPollBody(new byte[] { 0x0a, 0, 0, 0, 0, 0, 0, 0x47 }))
                throw new InvalidOperationException("lobby_body_selftest_failed");
            if (NextPostLoginStep(0x10, 0xb6, 7, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 1) != "menu_out_of_order" ||
                NextPostLoginStep(0x10, 0xb6, 7, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3) != "lobby_b6" ||
                NextPostLoginStep(0x10, 0xb6, 7, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3, 0, 0, MenuRepeatLimit) != "menu_out_of_order" ||
                NextPostLoginStep(0x10, 0xb6, 8, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3) != "invalid_header" ||
                NextPostLoginStep(0x40, 0x84, 14, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 0) != "menu_out_of_order" ||
                NextPostLoginStep(0x40, 0x84, 14, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3) != "room_list" ||
                NextPostLoginStep(0x40, 0x84, 13, true, true, true, 1, 1, true, true, true, 3, 1, 0, 0, 0, 3) != "invalid_header")
                throw new InvalidOperationException("lobby_order_selftest_failed");
            // 1.23 no session expiry: idle waits are polling slices at any elapsed time (here up
            // to 30 days); an incomplete frame still has FrameBudgetMs after its first byte;
            // no cumulative request caps remain.
            long thirtyDays = 30L * 24 * 3600 * 1000;
            if (RemainingSessionBudgetMs(100000, -1, NoDeadlineMs) != IdlePollMs ||
                RemainingSessionBudgetMs(thirtyDays, -1, NoDeadlineMs) != IdlePollMs ||
                RemainingSessionBudgetMs(thirtyDays, thirtyDays - 1000, NoDeadlineMs) != FrameBudgetMs - 1000 ||
                RemainingSessionBudgetMs(thirtyDays, thirtyDays - FrameBudgetMs, NoDeadlineMs) != 0 ||
                SessionHeaderLimit != int.MaxValue || PostLoginHeaderLimit != int.MaxValue ||
                MenuRepeatLimit != int.MaxValue || GradeRequestLimit != int.MaxValue ||
                GuardAnswerLimit != int.MaxValue || UnsupportedObserveLimit != int.MaxValue)
                throw new InvalidOperationException("session_deadline_selftest_failed");
            // Cipher continuity across the lobby: BC, B6, three polls, a clock, then 40/80.
            byte[] plain = new byte[6 + 7 + 14 * 3 + 6 + 6];
            int pos = 0;
            new byte[] { 0, 0x30, 0, 6, 0xbc, 0 }.CopyTo(plain, pos); pos += 6;
            new byte[] { 0, 0x10, 0, 7, 0xb6, 0, 1 }.CopyTo(plain, pos); pos += 7;
            for (int n = 0; n < 3; n++) { new byte[] { 0, 0x40, 0, 14, 0x84, 0, 0x0a, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(plain, pos); pos += 14; }
            new byte[] { 0, 0x10, 0, 6, 0x92, 0 }.CopyTo(plain, pos); pos += 6;
            new byte[] { 0, 0x40, 0, 6, 0x80, 0 }.CopyTo(plain, pos);
            byte[] wire = (byte[])plain.Clone();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);
            Cipher incoming = new Cipher(Encoding.ASCII.GetBytes("abcde"));
            string[] want = { "menu_bc", "lobby_b6", "room_list", "room_list", "room_list", "clock", "unsupported_header" };
            int b6s = 0, polls = 0; pos = 0;
            foreach (string expected in want)
            {
                incoming.Apply(wire, pos, 6);
                int type = (wire[pos] << 8) | wire[pos + 1], length = (wire[pos + 2] << 8) | wire[pos + 3];
                int action = wire[pos + 4] | (wire[pos + 5] << 8);
                string step = NextPostLoginStep(type, action, length, true, true, true, 1, 1, true, true, true, 3, 2,
                    0, 0, 0, 3, 1, 5, b6s);
                if (step != expected) throw new InvalidOperationException("lobby_chain_selftest_failed");
                pos += 6;
                byte[] body = new byte[length - 6];
                Array.Copy(wire, pos, body, 0, body.Length);
                incoming.Apply(body, 0, body.Length);
                pos += body.Length;
                if (step == "lobby_b6") { if (!IsB6Body(body)) throw new InvalidOperationException("lobby_chain_b6_selftest_failed"); b6s++; }
                if (step == "room_list") { if (!IsRoomPollBody(body)) throw new InvalidOperationException("lobby_chain_poll_selftest_failed"); polls++; }
            }
            if (pos != wire.Length || b6s != 1 || polls != 3)
                throw new InvalidOperationException("lobby_chain_alignment_selftest_failed");
        }

        // 1.20 automated startup-to-lobby run (offline, no network, no game): replays the
        // post-login request sequence the real client sent in v1.18 plus the guild-less
        // official continuation, then `polls` lobby polls with a clock every 10 polls, through
        // the real ObservePostLogin, cipher and framing. Returns a summary; throws on any
        // reply that differs from the expected type/action/length or content rule.
        public static string RunScriptedSession(string capturePath, string lobbyFixturePath, int polls, bool claimed95)
        {
            LobbyFixture fixture = LoadLobbyFixture(lobbyFixturePath);
            List<byte[]> requests = new List<byte[]>();
            List<string> expected = new List<string>();
            Action<int, int, byte[], string> add = (type, action, body, reply) =>
            {
                byte[] frame = new byte[6 + body.Length];
                frame[0] = (byte)(type >> 8); frame[1] = (byte)type; frame[2] = (byte)(frame.Length >> 8); frame[3] = (byte)frame.Length;
                frame[4] = (byte)action; frame[5] = (byte)(action >> 8);
                body.CopyTo(frame, 6);
                requests.Add(frame);
                if (reply != null) expected.Add(reply);
            };
            byte[] none = new byte[0], one = { 1, 0, 0, 0 };
            add(0x10, 0x92, none, "010/93/14"); add(0x48, 0x80, none, "048/81/68"); add(0x10, 0xd0, none, "010/d1/8");
            add(0x31, 0x88, none, "031/89/18"); add(0x10, 0x92, none, "010/93/14");
            add(0x30, 0x84, new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "030/85/3928");
            add(0x30, 0x92, none, "030/93/3507"); add(0x30, 0x90, none, "030/91/3507");
            add(0x10, 0xa8, new byte[4], "010/a9/3008");
            add(0x30, 0x86, one, "030/87/87"); add(0x40, 0xa0, none, "040/a1/10"); add(0x30, 0x88, one, "030/89/366");
            add(0x30, 0xa0, none, "030/a1/345");
            for (int n = 1; n <= 5; n++) add(0x30, 0xb4, new byte[] { (byte)n, 0, 0, 0 }, "030/b5/25");
            byte[] answer = new byte[118];
            for (int n = 0; n < answer.Length; n++) answer[n] = (byte)(n * 13);
            add(0x48, 0x42, answer, null);
            byte[] levelOne = { 1, 0, 0x61, 0xa6, 0x4c, 0, 0xe8, 0x03, 0, 0 };
            add(0x30, 0xb2, none, "030/b3/46");
            add(0x31, 0x8a, levelOne, "031/18b/520");   // GetLevelUpItem, as the v1.20 client sent it
            add(0x30, 0xba, none, "030/bb/14"); add(0x30, 0xbc, none, "030/bd/47");
            foreach (string page in new[] { "0100000000000000", "0200000000000000", "0300000000000000", "03000000d9f2d401", "030000006b00d601" })
            {
                byte[] body = new byte[8];
                for (int n = 0; n < 8; n++) body[n] = Convert.ToByte(page.Substring(2 * n, 2), 16);
                add(0x30, 0xcc, body, "030/cd/1810");
            }
            add(0x10, 0x92, none, "010/93/14"); add(0x30, 0xa0, none, "030/a1/345");
            add(0x31, 0x8a, new byte[] { 2, 100, 0, 0, 0, 0, 0, 0, 0, 0 }, "031/18b/520");
            byte[] questBody = { 0x02, 0x70, 0xb7, 0x01, 0x11, 0xe2, 0xcf, 0x01, 0xa9, 0x03, 0, 0 };  // synthetic
            add(0x30, 0xce, questBody, "030/cf/18");     // UpdateQuest right after LoginCheck All Green
            for (int n = 0; n < 70; n++) add(0x10, 0x92, none, "010/93/14");   // long main-menu idle
            add(0x30, 0xbc, none, "030/bd/47"); add(0x10, 0xb6, new byte[] { 1 }, "210/b7/7");   // Lobby click
            for (int n = 0; n < polls; n++)
            {
                add(0x40, 0x84, new byte[] { 0x0a, 0, 0, 0, 0, 0, 0, 0x46 }, "040/85/16");
                if (n % 10 == 9) add(0x10, 0x92, none, "010/93/14");
                if (n == polls / 2)
                    add(0x31, 0x8a, levelOne, "031/18b/520");   // a repeated level grant fails again
            }
            add(0x30, 0xbc, none, "030/bd/47"); add(0x30, 0xa0, none, "030/a1/345");   // back to the main menu
            add(0x30, 0xbc, none, "030/bd/47"); add(0x10, 0xb6, new byte[] { 1 }, "210/b7/7");   // second lobby entry
            for (int n = 0; n < 5; n++) add(0x40, 0x84, new byte[] { 0x0a, 0, 0, 0, 0, 0, 0, 0x46 }, "040/85/16");
            List<byte> stream = new List<byte>();
            foreach (byte[] request in requests) stream.AddRange(request);
            byte[] wire = stream.ToArray();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);

            Probe probe = new Probe();
            byte[] guard = LoadCapturedInitialization(capturePath);
            try { probe.SetCapturedInitialization(guard); } finally { Array.Clear(guard, 0, guard.Length); }
            probe.SetLobbyFixture(fixture);
            probe.Channel95Claimed = claimed95;
            probe.overall = Stopwatch.StartNew();
            ScriptedStream scripted = new ScriptedStream(wire);
            string end = "";
            try { probe.ObservePostLogin(scripted, new Cipher(Encoding.ASCII.GetBytes("abcde")), new Cipher(Encoding.ASCII.GetBytes("abcde")), 0); }
            catch (ProbeFailure failure) { end = failure.Code; }

            byte[] output = scripted.Output.ToArray();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(output, 0, output.Length);
            List<string> actual = new List<string>();
            List<byte[]> frames = new List<byte[]>();
            for (int at = 0; at + 6 <= output.Length;)
            {
                int type = (output[at] << 8) | output[at + 1], total = (output[at + 2] << 8) | output[at + 3];
                int action = output[at + 4] | (output[at + 5] << 8);
                byte[] frame = new byte[total];
                Array.Copy(output, at, frame, 0, total);
                frames.Add(frame);
                actual.Add(type.ToString("x3") + "/" + action.ToString("x2") + "/" + total);
                at += total;
            }
            if (actual.Count != expected.Count)
                throw new InvalidOperationException("scripted_reply_count " + actual.Count + " != " + expected.Count);
            for (int n = 0; n < actual.Count; n++)
                if (actual[n] != expected[n])
                    throw new InvalidOperationException("scripted_reply_mismatch at " + n + ": " + actual[n] + " != " + expected[n]);
            // Content checks on the replies that carry state.
            byte[] page0 = frames[5];
            int records = page0[6] | (page0[7] << 8);
            byte[] grade = frames[12];
            int at95 = 7 + 13 * Array.IndexOf(LocalGradeIds, (byte)95);
            if (records != (claimed95 ? 4 : 3) || Le32(grade, at95 + 1) != (claimed95 ? 1 : 0))
                throw new InvalidOperationException("scripted_claimed95_state_inconsistent");
            if (claimed95 && (Le32(page0, 155) != LocalRewardInstanceId || Le32(page0, 159) != RewardCatalogId))
                throw new InvalidOperationException("scripted_reward_record_missing");
            if (!SameBytes(frames[expected.IndexOf("030/b3/46")], fixture.B3) ||
                !SameBytes(frames[expected.IndexOf("030/bb/14")], fixture.BB) ||
                !SameBytes(frames[expected.IndexOf("030/bd/47")], fixture.BD))
                throw new InvalidOperationException("scripted_menu_frames_differ");
            byte[] questAck = frames[expected.IndexOf("030/cf/18")];
            for (int n = 0; n < 12; n++)
                if (questAck[6 + n] != questBody[n]) throw new InvalidOperationException("scripted_quest_echo_differs");
            // No duplication: the inventory the server would serve after two rejected grants
            // is byte-identical to the one served at login (state is never mutated).
            byte[] afterSession = BuildLocalClassPropertyResponse(claimed95 ? fixture.RewardRecord : null);
            if (!SameBytes(afterSession, frames[5]))
                throw new InvalidOperationException("scripted_inventory_changed_after_rejected_grant");
            ProbeResult r = probe.Result;
            if (r.LobbyEnteredAtMs < 0 || r.RoomListReplies != polls + 5 || r.UnansweredRequestCount != 0 ||
                r.MenuCcReplies != 5 || r.AddItemFailureReplies != 3 || r.LevelUpGrantFailureReplies != 2 ||
                r.AddItemUnansweredCount != 0 || r.B6Replies != 2 || r.QuestUpdateReplies != 1 || r.MainMenuEnteredAtMs < 0 || end != "peer_closed_before_header")
                throw new InvalidOperationException("scripted_result_inconsistent");
            return "requests=" + requests.Count + " replies=" + actual.Count + " polls=" + r.RoomListReplies +
                " lobby_entered_ms=" + r.LobbyEnteredAtMs + " claimed95=" + r.Channel95Claimed + " reward=" + r.RewardRecordServed +
                " unanswered=" + r.UnansweredRequestCount + " end=" + end + " headers_kept=" + r.PostLoginHeaders.Length +
                "+" + r.RecentHeaders.Length + " counts=" + string.Join(",", r.RequestCounts);
        }

        // 1.23 offline persistence check: ONE server instance serves two complete client
        // sessions (version, login, startup, Store Get_Cash repeats, lobby polls) through the
        // real ServeStream path, then shuts down. Verifies fresh per-session state, reconnect
        // (the GameGuard init is replayed again), no request cap (session 1 sends `polls`
        // room polls), separate client-session and server-shutdown log lines, and the
        // console-close handler. Returns a summary; throws on any deviation.
        public static string RunScriptedReconnect(string capturePath, string lobbyFixturePath, string logPath, int polls)
        {
            LobbyFixture fixture = LoadLobbyFixture(lobbyFixturePath);
            Probe probe = new Probe();
            byte[] guard = LoadCapturedInitialization(capturePath);
            try { probe.SetCapturedInitialization(guard); } finally { Array.Clear(guard, 0, guard.Length); }
            probe.SetLobbyFixture(fixture);
            probe.overall = Stopwatch.StartNew();
            if (File.Exists(logPath)) File.Delete(logPath);
            probe.SessionLogPath = logPath;
            int[] sessionPolls = { polls, 10 };
            List<string> summaries = new List<string>();
            for (int s = 0; s < 2; s++)
            {
                byte[] wire = ScriptedClientSession(sessionPolls[s]);
                ScriptedStream scripted = new ScriptedStream(wire);
                lock (probe.gate) { probe.BeginSessionLocked(probe.overall.ElapsedMilliseconds); }
                int phase = 0;
                string end;
                try { probe.ServeStream(scripted, 0, ref phase); lock (probe.gate) { end = probe.result.Status; } }
                catch (Exception ex) { end = probe.RecordFailure(ex, phase); }
                ProbeResult r = probe.Result;
                lock (probe.gate) { probe.EndSessionLocked(end); }
                byte[] output = scripted.Output.ToArray();
                new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(output, 0, output.Length);
                int guardReplies = 0, cashReplies = 0, roomLists = 0;
                for (int at = 0; at + 6 <= output.Length;)
                {
                    int type = (output[at] << 8) | output[at + 1], total = (output[at + 2] << 8) | output[at + 3];
                    int action = output[at + 4] | (output[at + 5] << 8);
                    if (type == 0x48 && action == 0x81) guardReplies++;
                    if (type == 0x31 && action == 0x89) cashReplies++;
                    if (type == 0x40 && action == 0x85) roomLists++;
                    at += total;
                }
                string counts = string.Join(",", r.RequestCounts);
                if (end != "post_login_peer_closed_before_header" || r.SessionNumber != s + 1 || guardReplies != 1 ||
                    cashReplies != 3 || r.CashReplies != 3 || roomLists != sessionPolls[s] || r.RoomListReplies != sessionPolls[s] ||
                    r.MainMenuEnteredAtMs < 0 || r.LobbyEnteredAtMs < 0 || r.UnansweredRequestCount != 0 ||
                    !counts.Contains("40/84=" + sessionPolls[s]) || !counts.Contains("30/b4=5"))
                    throw new InvalidOperationException("scripted_reconnect_session_" + (s + 1) + "_inconsistent: end=" + end +
                        " cash=" + cashReplies + " rooms=" + roomLists + " counts=" + counts);
                summaries.Add("session" + (s + 1) + ": polls=" + roomLists + " cash=" + cashReplies + " gg=" + guardReplies + " end=" + end);
            }
            probe.Stop("scripted_shutdown");
            string[] lines = File.ReadAllLines(logPath);
            if (lines.Length != 3 || !lines[0].Contains("\"event\":\"client_session_end\",\"session\":1,") ||
                !lines[1].Contains("\"event\":\"client_session_end\",\"session\":2,") ||
                !lines[2].Contains("\"event\":\"server_shutdown\"") || !lines[2].Contains("\"reason\":\"scripted_shutdown\"") ||
                !lines[2].Contains("\"client_sessions\":2") || probe.CompletedSessionCount != 2)
                throw new InvalidOperationException("scripted_reconnect_log_inconsistent");
            // Console close: the handler itself stops the server and logs the shutdown once.
            Probe closing = new Probe();
            closing.overall = Stopwatch.StartNew();
            string closeLog = logPath + ".close";
            if (File.Exists(closeLog)) File.Delete(closeLog);
            closing.SessionLogPath = closeLog;
            if (!ConsoleGuard.SimulateForTest(closing, 2) || !ConsoleGuard.StopRequested || ConsoleGuard.StopEvent != "console_close" ||
                closing.ServerEndReason != "console_close")
                throw new InvalidOperationException("console_close_handler_inconsistent");
            closing.Stop("second_stop_ignored");
            string[] closeLines = File.ReadAllLines(closeLog);
            if (closeLines.Length != 1 || !closeLines[0].Contains("\"reason\":\"console_close\""))
                throw new InvalidOperationException("console_close_log_inconsistent");
            Probe interrupted = new Probe();
            interrupted.overall = Stopwatch.StartNew();
            if (!ConsoleGuard.SimulateForTest(interrupted, 0) || !ConsoleGuard.StopRequested || ConsoleGuard.StopEvent != "ctrl_c" ||
                interrupted.ServerEndReason != "")
                throw new InvalidOperationException("ctrl_c_handler_inconsistent");   // Ctrl+C: graceful path, no hard stop
            File.Delete(closeLog);
            return string.Join("; ", summaries) + "; log lines=" + lines.Length + " (2 client sessions + server_shutdown); console_close and ctrl_c handlers OK";
        }

        // One full client connection: version, login (invented password), startup, Store
        // Get_Cash twice, lobby entry and `polls` room polls; then the stream ends.
        private static byte[] ScriptedClientSession(int polls)
        {
            return ScriptedClientSession(polls, null);
        }

        // `lobbyActions` adds client frames after lobby entry, before the polls.
        private static byte[] ScriptedClientSession(int polls, Action<Action<int, int, byte[]>> lobbyActions)
        {
            List<byte> plain = new List<byte>();
            Action<int, int, byte[]> add = (type, action, body) =>
            {
                int total = 6 + body.Length;
                plain.AddRange(new byte[] { (byte)(type >> 8), (byte)type, (byte)(total >> 8), (byte)total, (byte)action, (byte)(action >> 8) });
                plain.AddRange(body);
            };
            add(0x10, 0x90, new byte[20]);
            byte[] login = new byte[85];
            Encoding.ASCII.GetBytes(DummyEmail).CopyTo(login, 0);
            Encoding.ASCII.GetBytes(DummyPassword).CopyTo(login, 64);
            add(0x10, 0x84, login);
            byte[] none = new byte[0], one = { 1, 0, 0, 0 };
            add(0x10, 0x92, none); add(0x48, 0x80, none); add(0x10, 0xd0, none); add(0x31, 0x88, none); add(0x10, 0x92, none);
            add(0x30, 0x84, new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            add(0x30, 0x92, none); add(0x30, 0x90, none); add(0x10, 0xa8, new byte[4]);
            add(0x30, 0x86, one); add(0x40, 0xa0, none); add(0x30, 0x88, one); add(0x30, 0xa0, none);
            for (int n = 1; n <= 5; n++) add(0x30, 0xb4, new byte[] { (byte)n, 0, 0, 0 });
            add(0x30, 0xb2, none);
            add(0x31, 0x8a, new byte[] { 1, 0, 0x61, 0xa6, 0x4c, 0, 0xe8, 0x03, 0, 0 });
            add(0x30, 0xba, none); add(0x30, 0xbc, none);
            foreach (string page in new[] { "0100000000000000", "0200000000000000", "0300000000000000", "03000000d9f2d401", "030000006b00d601" })
            {
                byte[] body = new byte[8];
                for (int n = 0; n < 8; n++) body[n] = Convert.ToByte(page.Substring(2 * n, 2), 16);
                add(0x30, 0xcc, body);
            }
            add(0x10, 0x92, none); add(0x30, 0xa0, none);
            add(0x31, 0x8a, new byte[] { 2, 100, 0, 0, 0, 0, 0, 0, 0, 0 });
            add(0x30, 0xce, new byte[] { 2, 0x70, 0xb7, 1, 0x11, 0xe2, 0xcf, 1, 0xa9, 3, 0, 0 });
            add(0x31, 0x88, none); add(0x31, 0x88, none);                 // Store: Get_Cash, twice
            add(0x30, 0xbc, none); add(0x10, 0xb6, new byte[] { 1 });      // Lobby
            if (lobbyActions != null) lobbyActions(add);
            for (int n = 0; n < polls; n++)
            {
                add(0x40, 0x84, new byte[] { 0x0a, 0, 0, 0, 0, 0, 0, 0x46 });
                if (n % 15 == 14) add(0x10, 0x92, none);
            }
            byte[] wire = plain.ToArray();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(wire, 0, wire.Length);
            return wire;
        }

        // Serves one scripted connection on `probe`; returns (type, action, body) of every
        // server frame, decrypted.
        private static List<Tuple<int, int, byte[]>> ServeScripted(Probe probe, byte[] wire, out string end)
        {
            ScriptedStream scripted = new ScriptedStream(wire);
            lock (probe.gate) { probe.BeginSessionLocked(probe.overall.ElapsedMilliseconds); }
            int phase = 0;
            try { probe.ServeStream(scripted, 0, ref phase); lock (probe.gate) { end = probe.result.Status; } }
            catch (Exception ex) { end = probe.RecordFailure(ex, phase); }
            lock (probe.gate) { probe.EndSessionLocked(end); }
            byte[] output = scripted.Output.ToArray();
            new Cipher(Encoding.ASCII.GetBytes("abcde")).Apply(output, 0, output.Length);
            List<Tuple<int, int, byte[]>> frames = new List<Tuple<int, int, byte[]>>();
            for (int at = 0; at + 6 <= output.Length;)
            {
                int type = (output[at] << 8) | output[at + 1], total = (output[at + 2] << 8) | output[at + 3];
                int action = output[at + 4] | (output[at + 5] << 8);
                byte[] body = new byte[total - 6];
                Array.Copy(output, at + 6, body, 0, body.Length);
                frames.Add(Tuple.Create(type, action, body));
                at += total;
            }
            return frames;
        }

        private static byte[] Body(params int[] le32)
        {
            byte[] b = new byte[le32.Length * 4];
            for (int n = 0; n < le32.Length; n++) PutLe32(b, 4 * n, le32[n]);
            return b;
        }

        // 1.24 account checks: baseline wire identity with v1.23, pagination, equip rules,
        // file-store persistence/backup/restore, 30/81 layout, and a two-connection scripted
        // client (equip in connection 1, read back in connection 2 from the saved file).
        public static string SelfTestAccount(string capturePath, string lobbyFixturePath, string tempDirectory)
        {
            List<string> passed = new List<string>();
            Action<bool, string> check = (ok, name) => { if (!ok) throw new InvalidOperationException("account_selftest_failed: " + name); passed.Add(name); };
            LobbyFixture fixture = LoadLobbyFixture(lobbyFixturePath);
            byte[] reward = fixture.RewardRecord;

            // 1. Baseline = v1.23 fixture bytes.
            AccountState b = AccountState.CreateBaseline(reward);
            check(b.Validate() == null, "baseline_valid");
            check(SameBytes(AccountWire.PropertyPage(b, 1), BuildLocalClassPropertyResponse(reward)), "baseline_inventory_page_identical");
            check(SameBytes(AccountWire.PropertyPage(AccountState.CreateBaseline(null), 1), BuildLocalClassPropertyResponse(null)), "baseline_unclaimed_page_identical");
            check(SameBytes(AccountWire.AvatarList(b), BuildLocalAvatarList()), "baseline_avatar_list_identical");
            check(SameBytes(AccountWire.EquippedAvatar(b), BuildLocalEquippedAvatar()), "baseline_equipped_avatar_identical");
            check(SameBytes(AccountWire.Equipment(b, 1), BuildLocalClassEquipment()), "baseline_equipment_identical");
            check(SameBytes(AccountWire.Cash(b), BuildLocalCashReply()), "baseline_cash_identical");
            string guid = "00000000-0000-4000-8000-000000000001", token = new string('A', 30);
            check(SameBytes(BuildLoginSuccess(guid, token, b), BuildLoginSuccess(guid, token)), "baseline_login_identical");
            check(AccountState.Parse(b.Serialize()).Serialize() == b.Serialize(), "serialize_roundtrip");

            // 2. Pagination: 300 grants -> pages of 80 ascending, cursor = last + 1, no loss/duplicates.
            AccountState many = AccountState.CreateBaseline(reward);
            byte[] sample = (byte[])reward.Clone();
            for (int n = 0; n < 300; n++) many.Grant(sample);
            check(many.Validate() == null && many.Items.Count == 304, "grants_valid_unique");
            HashSet<int> seen = new HashSet<int>();
            int cursor = 1, pages = 0, lastCount = 80;
            while (lastCount == 80)
            {
                byte[] page = AccountWire.PropertyPage(many, cursor);
                lastCount = page[6] | (page[7] << 8);
                int prev = 0;
                for (int n = 0; n < lastCount; n++)
                {
                    int inst = Le32(page, 8 + 49 * n);
                    if (inst <= prev || !seen.Add(inst)) throw new InvalidOperationException("account_selftest_failed: page_order");
                    prev = inst;
                }
                for (int n = 8 + 49 * lastCount; n < page.Length; n++) if (page[n] != 0) throw new InvalidOperationException("account_selftest_failed: page_tail");
                if (lastCount > 0) cursor = prev + 1;
                pages++;
            }
            check(seen.Count == 304 && pages == 4, "pagination_304_records_4_pages_no_loss");

            // 3. Equip rules.
            AccountState e = AccountState.CreateBaseline(reward);
            ItemRecord scroll = e.Grant(MakeTestRecord(2030247, 85582, 1001));
            ItemRecord exo2 = e.Grant(MakeTestRecord(2040298, 87118, 1101));
            check(e.Equip(1, 10, scroll.Instance) == null && e.FindAvatar(1).Slots[10] == scroll.Instance, "equip_scroll_slot10");
            check(e.Equip(1, 11, 1003) == null && e.Equip(1, 12, exo2.Instance) == null, "equip_two_exo_slots");
            check(e.Equip(1, 12, 1003) == null && e.FindAvatar(1).Slots[11] == 0 && e.FindAvatar(1).Slots[12] == 1003, "exo_moves_between_slots");
            check(e.Equip(1, 10, 1003) == "slot_family_mismatch", "exo_refused_in_scroll_slot");
            check(e.Equip(1, 0, scroll.Instance) == "slot0_not_class", "slot0_class_only");
            check(e.Equip(1, 10, 999999) == "item_not_owned", "unowned_refused");
            check(e.Equip(2, 10, scroll.Instance) == "avatar_not_owned", "unowned_avatar_refused");
            check(e.Equip(1, 45, scroll.Instance) == "slot_out_of_range", "slot_range");
            check(e.Unequip(1, 10) == null && e.FindAvatar(1).Slots[10] == 0, "unequip");
            check(e.Unequip(1, 0) == null && e.FindAvatar(1).Slots[0] == 1001, "slot0_unequip_noop");
            bool endMatched;
            check(e.OwnsCatalog(2030247, 1001, out endMatched) && endMatched && !e.OwnsCatalog(2030999, 0, out endMatched), "item_check_ownership");

            // 4. 30/81 layout.
            e.Level = 18; e.Experience = 1763532;
            e.Equip(1, 10, scroll.Instance);
            byte[] info = AccountWire.UserInfo(e);
            check(info.Length == 1567 && info[1] == 0x30 && info[4] == 0x81 && Le32(info, 6) == 1 && AsciiZ(info, 10, 20) == "AsterLocal" &&
                Le32(info, 30) == 18 && Le32(info, 34) == 1763532 && Le32(info, 38) == 1000176 && Le32(info, 38 + 40) == 2030247 &&
                Le32(info, 38 + 48) == 2040035 && AsciiZ(info, 6 + 1521, 8) == "US" && AsciiZ(info, 6 + 1529, 8) == "NA", "user_info_layout");

            // 5. File store: create, change, reload, backup, restore, reject corrupt files.
            Directory.CreateDirectory(tempDirectory);
            string file = Path.Combine(tempDirectory, "account-selftest-" + Guid.NewGuid().ToString("N") + ".txt");
            AccountStore store = new AccountStore(file);
            try
            {
                AccountState created = store.LoadOrCreate(AccountState.CreateBaseline(reward));
                check(created.Serialize() == AccountState.CreateBaseline(reward).Serialize(), "store_created_from_baseline");
                check(store.Update(s => { s.Grant(MakeTestRecord(2030247, 85582, 1001)); return null; }) == null, "store_grant");
                string backup = store.Backup(tempDirectory, "selftest");
                check(store.Update(s => s.Equip(1, 10, 1005)) == null && store.Load().FindAvatar(1).Slots[10] == 1005, "store_equip_persisted");
                check(store.Update(s => s.Equip(1, 10, 424242)) == "item_not_owned" && store.Load().FindAvatar(1).Slots[10] == 1005, "store_refused_change_not_written");
                store.Restore(backup);
                check(store.Load().FindAvatar(1).Slots[10] == 0 && store.Load().FindItem(1005) != null, "store_restore");
                File.Delete(backup);
                File.WriteAllText(file, "rf-account-v1\naccount 1 AsterLocal 0 0 0 0 9 1005 US NA\n");
                bool rejected = false;
                try { store.Load(); } catch (InvalidDataException) { rejected = true; }
                check(rejected, "store_rejects_invalid_file");
            }
            finally
            {
                foreach (string f in new[] { file, file + ".bak" }) if (File.Exists(f)) File.Delete(f);
            }

            // 6. Two scripted connections against one store: equip in the first, read back in the second.
            string liveFile = Path.Combine(tempDirectory, "account-scripted-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                AccountStore liveStore = new AccountStore(liveFile);
                AccountState seed = AccountState.CreateBaseline(reward);
                ItemRecord seededScroll = seed.Grant(MakeTestRecord(2030247, 85582, 1001));
                liveStore.Replace(seed);
                Probe probe = new Probe();
                byte[] guard = LoadCapturedInitialization(capturePath);
                try { probe.SetCapturedInitialization(guard); } finally { Array.Clear(guard, 0, guard.Length); }
                probe.SetLobbyFixture(fixture);
                probe.Accounts = liveStore;
                probe.overall = Stopwatch.StartNew();
                byte[] name = new byte[20];
                Encoding.ASCII.GetBytes("AsterLocal").CopyTo(name, 0);
                string end;
                List<Tuple<int, int, byte[]>> first = ServeScripted(probe, ScriptedClientSession(3, add =>
                {
                    add(0x1f, 0x10, new byte[0]);                                     // keepalive, no reply
                    add(0x40, 0xa2, Body(1));                                         // select avatar 1
                    add(0x30, 0xd6, Body(2030247, 1001));                             // item check (owned)
                    byte[] equip = new byte[9]; PutLe32(equip, 0, 1); equip[4] = 10; PutLe32(equip, 5, seededScroll.Instance);
                    add(0x40, 0xa4, equip);                                           // equip scroll, slot 10
                    add(0x30, 0xd6, Body(2030999, 1000));                             // item check (not owned): unanswered
                    byte[] bad = new byte[9]; PutLe32(bad, 0, 1); bad[4] = 11; PutLe32(bad, 5, 777777);
                    add(0x40, 0xa4, bad);                                             // unowned: unanswered, state kept
                    add(0x40, 0xa6, new byte[] { 1, 0, 0, 0, 12 });                   // clear empty slot 12
                    add(0x30, 0x80, name);                                            // Create Room -> GET_USER_INFO
                }), out end);
                ProbeResult r1 = probe.Result;
                Func<List<Tuple<int, int, byte[]>>, int, int, int> count = (frames, t, a) => { int c = 0; foreach (var f in frames) if (f.Item1 == t && f.Item2 == a) c++; return c; };
                check(count(first, 0x30, 0x81) == 1 && count(first, 0x30, 0xd7) == 1 && count(first, 0x40, 0xa3) == 1 &&
                      count(first, 0x40, 0xa5) == 1 && count(first, 0x40, 0xa7) == 1, "scripted_replies_once_each");
                check(r1.UserInfoReplies == 1 && r1.ItemCheckReplies == 1 && r1.EquipChanges == 1 && r1.LobbyActionRejects == 2 &&
                      r1.KeepaliveCount == 1 && r1.UnansweredRequestCount == 2 && r1.AccountSource == "store", "scripted_counters");
                check(liveStore.Load().FindAvatar(1).Slots[10] == seededScroll.Instance, "equip_saved_to_file");
                foreach (var f in first)
                    if (f.Item1 == 0x30 && f.Item2 == 0x81)
                        check(Le32(f.Item3, 32 + 40) == 2030247, "user_info_shows_equipped_scroll_after_equip");
                List<Tuple<int, int, byte[]>> second = ServeScripted(probe, ScriptedClientSession(2), out end);
                byte[] equipment = null, page = null;
                foreach (var f in second) { if (f.Item1 == 0x30 && f.Item2 == 0x89) equipment = f.Item3; if (f.Item1 == 0x30 && f.Item2 == 0x85) page = f.Item3; }
                check(equipment != null && Le32(equipment, 40) == seededScroll.Instance && Le32(equipment, 0) == 1001, "reconnect_equipment_from_saved_state");
                check(page != null && (page[0] | (page[1] << 8)) == 5, "reconnect_inventory_has_granted_item");
                probe.Stop("selftest");
            }
            finally
            {
                foreach (string f in new[] { liveFile, liveFile + ".bak" }) if (File.Exists(f)) File.Delete(f);
            }
            // 7. 1.26 currency + purchases through the real ServeStream path, two connections.
            string shopFile = Path.Combine(tempDirectory, "account-shop-" + Guid.NewGuid().ToString("N") + ".txt");
            string shopLog = shopFile + ".session.jsonl";
            try
            {
                AccountStore shopStore = new AccountStore(shopFile);
                AccountState seed = AccountState.CreateBaseline(reward);
                shopStore.Replace(seed);
                ItemCatalog catalog = new ItemCatalog();
                byte[] observedScroll = MakeTestRecord(2030834, 20046, 0);
                observedScroll[20] = 0x5a;                                            // a marker only an observed record has
                catalog.Records[2030834] = observedScroll;
                Probe probe = new Probe();
                byte[] guard = LoadCapturedInitialization(capturePath);
                try { probe.SetCapturedInitialization(guard); } finally { Array.Clear(guard, 0, guard.Length); }
                probe.SetLobbyFixture(fixture);
                probe.Accounts = shopStore;
                probe.ItemRecords = catalog;
                probe.overall = Stopwatch.StartNew();
                probe.SessionLogPath = shopLog;
                Func<int, int, byte[]> buy = (cat, itemEnd) => { byte[] req = new byte[9]; PutLe32(req, 1, cat); PutLe32(req, 5, itemEnd); return req; };
                Func<List<Tuple<int, int, byte[]>>, int, int, List<byte[]>> bodies = (frames, t, a) => { List<byte[]> l = new List<byte[]>(); foreach (var fr in frames) if (fr.Item1 == t && fr.Item2 == a) l.Add(fr.Item3); return l; };
                string end;
                // Unlimited off: refused, unanswered, nothing saved.
                List<Tuple<int, int, byte[]>> refused = ServeScripted(probe, ScriptedClientSession(1, add => add(0x31, 0x80, buy(2030834, 0))), out end);
                check(bodies(refused, 0x31, 0x81).Count == 0 && shopStore.Load().Items.Count == 4 && probe.Result.LobbyActionRejects == 1, "purchase_refused_without_unlimited_currency");
                check(shopStore.Update(s => { s.UnlimitedCurrency = true; return null; }) == null, "unlimited_currency_enabled");
                List<Tuple<int, int, byte[]>> shop = ServeScripted(probe, ScriptedClientSession(1, add =>
                {
                    add(0x31, 0x88, new byte[0]);                                     // Store opens: Get_Cash
                    add(0x31, 0x80, buy(2030834, 0));                                 // observed scroll
                    add(0x31, 0x80, buy(1099999, 1000));                              // unobserved catalog
                    add(0x31, 0x80, buy(1099999, 1000));                              // bought again: a second item
                    add(0x30, 0xd6, Body(2030834, 0));
                    byte[] eq = new byte[9]; PutLe32(eq, 0, 1); eq[4] = 10; PutLe32(eq, 5, 1005);
                    add(0x40, 0xa4, eq);                                              // equip the bought scroll
                    add(0x31, 0x86, Body(1006));                                      // UNPACK an owned item: refused
                    add(0x31, 0xaa, new byte[] { 7, 0, 0, 0 });                       // unknown request: unanswered, logged live
                    add(0x31, 0x8a, new byte[] { 0, 0, 0xbc, 0xf9, 0x1e, 0, 0x2b, 0x04, 0, 0 });   // 1.28: the startup-regression ADD_ITEM (kind 0): answered with observed failure, logged
                }), out end);
                List<byte[]> refusals = bodies(shop, 0x31, 0x187);
                check(refusals.Count == 1 && refusals[0].Length == 514 && (refusals[0][0] | (refusals[0][1] << 8)) == 10001 &&
                      Encoding.ASCII.GetString(refusals[0], 2, 13) == "FAIL(unknown)" && probe.Result.PackageRefusals == 1, "unpack_refused_in_captured_failure_form");
                check(shopStore.Load().FindItem(1006) != null, "refused_unpack_keeps_package");
                string[] live = File.ReadAllLines(shopLog);
                check(Array.Exists(live, l => l.Contains("\"package_request_refused\"") && l.Contains("\"31/86\"") && l.Contains("ee030000") && l.Contains("instance 1006")) &&
                      Array.Exists(live, l => l.Contains("\"unanswered_request\"") && l.Contains("\"31/aa\"") && l.Contains("07000000")), "live_request_log_lines");
                // 1.28 regression fix: an unrecognized ADD_ITEM is answered with the observed
                // 31/18B failure (not left silent, which hung the client) and logged/counted.
                check(bodies(shop, 0x31, 0x18b).Count == 3 && probe.Result.AddItemUnrecognizedFailures == 1 &&
                      probe.Result.AddItemFailureReplies == 3 &&
                      Array.Exists(live, l => l.Contains("\"add_item_unrecognized_failure\"") && l.Contains("0000bcf91e002b040000")),
                      "add_item_unrecognized_answered_with_failure_and_logged");
                List<byte[]> buys = bodies(shop, 0x31, 0x81);
                check(buys.Count == 3 && Le32(buys[0], 0) == 1005 && Le32(buys[1], 0) == 1006 && Le32(buys[2], 0) == 1007 &&
                      Le32(buys[0], 4) == AccountState.DefaultUnlimitedBalance, "purchase_replies_unique_instances_and_balance");
                List<byte[]> cash = bodies(shop, 0x31, 0x89);
                check(cash.Count >= 1 && Le32(cash[cash.Count - 1], 4) == AccountState.DefaultUnlimitedBalance && Le32(cash[cash.Count - 1], 8) == 0, "cash_reply_shows_unlimited_astros");
                AccountState saved = shopStore.Load();
                check(saved.Items.Count == 7 && saved.FindItem(1005).Raw[20] == 0x5a && saved.FindItem(1006).Word8 == AccountState.ReferenceWord8 &&
                      saved.FindItem(1006).ItemEnd == 1000 && saved.FindItem(1007).Catalog == 1099999, "purchases_saved_observed_and_reference_records");
                check(saved.FindAvatar(1).Slots[10] == 1005 && probe.Result.PurchaseReplies == 3 && probe.Result.PurchaseObservedRecords == 1, "bought_scroll_equipped");
                string[] ledger = File.ReadAllLines(shopFile + ".purchases.log");
                check(ledger.Length == 3 && ledger[0].Contains("catalog=2030834") && ledger[0].Contains("record=observed") && ledger[2].Contains("instance=1007") && ledger[2].Contains("charged=0"), "purchase_ledger");
                List<Tuple<int, int, byte[]>> again = ServeScripted(probe, ScriptedClientSession(1), out end);
                byte[] login = null, page = null, equipment = null;
                foreach (var fr in again) { if (fr.Item1 == 0x10 && fr.Item2 == 0x85) login = fr.Item3; if (fr.Item1 == 0x30 && fr.Item2 == 0x85) page = fr.Item3; if (fr.Item1 == 0x30 && fr.Item2 == 0x89) equipment = fr.Item3; }
                check(login != null && Le32(login, 32) == AccountState.DefaultUnlimitedBalance && page != null && (page[0] | (page[1] << 8)) == 7 &&
                      equipment != null && Le32(equipment, 40) == 1005, "reconnect_shows_balance_items_equipment");
                check(shopStore.Update(s => { s.UnlimitedCurrency = false; return null; }) == null && shopStore.Load().EffectiveCarats == 0, "unlimited_off_restores_stored_balance");
                probe.Stop("selftest");
            }
            finally
            {
                foreach (string f in new[] { shopFile, shopFile + ".bak", shopFile + ".purchases.log", shopLog }) if (File.Exists(f)) File.Delete(f);
            }
            return passed.Count + " account checks passed: " + string.Join(", ", passed);
        }

        private static byte[] MakeTestRecord(int catalog, int word8, int itemEnd)
        {
            byte[] r = new byte[49];
            PutLe32(r, 4, catalog); PutLe32(r, 8, word8); PutLe32(r, 29, itemEnd);
            return r;
        }

        private static bool SameBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int n = 0; n < a.Length; n++) if (a[n] != b[n]) return false;
            return true;
        }

        private sealed class Cipher
        {
            private readonly byte[] state = new byte[256];
            private int i;
            private int j;
            public Cipher(byte[] key)
            {
                for (int n = 0; n < 256; n++) state[n] = (byte)n;
                int other = 0;
                for (int n = 0; n < 256; n++)
                {
                    other = (other + state[n] + key[n % key.Length]) & 255;
                    byte temp = state[n]; state[n] = state[other]; state[other] = temp;
                }
            }
            public void Apply(byte[] bytes, int start, int count)
            {
                for (int n = start; n < start + count; n++)
                {
                    i = (i + 1) & 255; j = (j + state[i]) & 255;
                    byte temp = state[i]; state[i] = state[j]; state[j] = temp;
                    bytes[n] ^= state[(state[i] + state[j]) & 255];
                }
            }
        }
    }
}

// 1.24 persistent local account state (C# 5; compiled together with RFHandshakeProbe.cs).
//
// One authoritative account: identity, level/experience, balances, avatars with 45
// equipment slots each (item INSTANCE IDs), and owned 49-byte inventory records. Login,
// inventory pages, avatar list, equipment, GET_USER_INFO and the My Info equipment
// requests all read/write this state. It is stored as a small text file, replaced
// atomically (temp file + File.Replace with a .bak copy) under a machine-wide mutex, so
// the server and the admin tool never interleave writes.
//
// Evidence used here (official captures, rf_equip_trace.py / rf_property_pages.py):
// - inventory pages: records ascend by instance ID, 80 per page, request cursor = last + 1;
// - equipment refs are instance IDs; the class instance (slot 0) is shared by all avatars;
// - slot <-> catalog family pairs observed in 40 equipment replies (SlotFamilies below).
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace RFLocalHandshake
{
    public sealed class ItemRecord
    {
        public byte[] Raw = new byte[ItemRecord.Size];   // instance ID at +0, catalog at +4
        public const int Size = 49;
        public int Instance { get { return Le32(Raw, 0); } }
        public int Catalog { get { return Le32(Raw, 4); } }
        public int Word8 { get { return Le32(Raw, 8); } }
        public int ItemEnd { get { return Le32(Raw, 29); } }

        internal static int Le32(byte[] b, int o) { return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24); }
        internal static void Put32(byte[] b, int o, int v) { for (int n = 0; n < 4; n++) b[o + n] = (byte)(v >> (8 * n)); }
    }

    public sealed class AvatarState
    {
        public const int SlotCount = 45;
        public int Id;
        public int[] Slots = new int[SlotCount];
    }

    public sealed class AccountState
    {
        public const string Schema = "rf-account-v2";        // 1.26: + currency line
        public const string SchemaV1 = "rf-account-v1";      // still readable (no currency line)
        public int AccountId = 1;
        public string Name = "AsterLocal";
        public int Level;   // 0 = the v1.18-v1.23 wire value (client still shows Lv.1); admin may set 1..255
        public long Experience;
        public int Cash;     // Astros: 31/89 second field (rf-boss-baseline 23, rf-startup 40; Gemnet: Astros)
        public int Medals;   // 31/89 third field (0 in all captures)
        // 1.26 Carats: login body +32 (rf-boss-baseline 15535; Gemnet LoginRes.Carats) and the
        // balance field of the 31/81 buy reply (Gemnet BuyItemRes.Carats).
        public int Carats;
        // 1.26 local admin setting: both balances are reported as UnlimitedBalance and purchases
        // cost nothing. Stored balances stay unchanged underneath (turning it off restores them).
        public bool UnlimitedCurrency;
        public int UnlimitedBalance = DefaultUnlimitedBalance;
        // 8 digits: the fields are int32 (protocol; Gemnet int); 21x headroom below 2^31-1 so a
        // client-side addition cannot overflow. On-screen fit is checked in the real client.
        public const int DefaultUnlimitedBalance = 99999999;
        public const int MaxUnlimitedBalance = 999999999;
        public int EffectiveCarats { get { return UnlimitedCurrency ? UnlimitedBalance : Carats; } }
        public int EffectiveAstros { get { return UnlimitedCurrency ? UnlimitedBalance : Cash; } }
        public int CurrentAvatar = 1;
        public int NextInstance = 1005;
        public string Country = "US";
        public string Region = "NA";
        public readonly List<AvatarState> Avatars = new List<AvatarState>();
        public readonly List<ItemRecord> Items = new List<ItemRecord>();

        // The v1.18-v1.23 fixture as account state: avatar 1 with class instance 1001 in slot 0;
        // class 1001 (1000176), rod 1002 (5135224), default Exo 1003 (2040035); plus, when the
        // claimed-95 experiment is on, reward 1004 = the exact observed 3043117 record.
        public static AccountState CreateBaseline(byte[] rewardRecord)
        {
            AccountState s = new AccountState();
            AvatarState avatar = new AvatarState { Id = 1 };
            avatar.Slots[0] = 1001;
            s.Avatars.Add(avatar);
            s.Items.Add(MakeRecord(1001, 1000176, 20046, 0));
            s.Items.Add(MakeRecord(1002, 5135224, 85582, 1000));
            s.Items.Add(MakeRecord(1003, 2040035, 85582, 1000));
            if (rewardRecord != null)
            {
                if (rewardRecord.Length != ItemRecord.Size) throw new InvalidOperationException("reward_record_invalid");
                ItemRecord reward = new ItemRecord { Raw = (byte[])rewardRecord.Clone() };
                ItemRecord.Put32(reward.Raw, 0, 1004);
                s.Items.Add(reward);
            }
            return s;
        }

        private static ItemRecord MakeRecord(int instance, int catalog, int word8, int itemEnd)
        {
            ItemRecord r = new ItemRecord();
            ItemRecord.Put32(r.Raw, 0, instance);
            ItemRecord.Put32(r.Raw, 4, catalog);
            ItemRecord.Put32(r.Raw, 8, word8);
            ItemRecord.Put32(r.Raw, 29, itemEnd);
            return r;
        }

        public ItemRecord FindItem(int instance)
        {
            foreach (ItemRecord r in Items) if (r.Instance == instance) return r;
            return null;
        }

        public AvatarState FindAvatar(int id)
        {
            foreach (AvatarState a in Avatars) if (a.Id == id) return a;
            return null;
        }

        public bool OwnsCatalog(int catalog, int itemEnd, out bool endMatched)
        {
            endMatched = false;
            bool owned = false;
            foreach (ItemRecord r in Items)
            {
                if (r.Catalog != catalog) continue;
                owned = true;
                if (r.ItemEnd == itemEnd) endMatched = true;
            }
            return owned;
        }

        // Records with instance >= cursor, ascending, at most `max` (the official page size is 80).
        public List<ItemRecord> Page(int cursor, int max)
        {
            List<ItemRecord> sorted = new List<ItemRecord>(Items);
            sorted.Sort((a, b) => ((uint)a.Instance).CompareTo((uint)b.Instance));
            List<ItemRecord> page = new List<ItemRecord>();
            foreach (ItemRecord r in sorted)
            {
                if ((uint)r.Instance < (uint)cursor) continue;
                if (page.Count == max) break;
                page.Add(r);
            }
            return page;
        }

        // Observed slot -> catalog family (catalog / 10000) pairs, 3 captures, 40 equipment
        // replies (rf_item_records.py). A family that was observed in some slots may only go
        // to those slots; a family never observed equipped is not restricted here (the client
        // decides). Slot 0 holds the class item only.
        private static readonly Dictionary<int, int[]> SlotFamilies = new Dictionary<int, int[]> {
            { 100, new[] { 0 } }, { 105, new[] { 1, 34 } }, { 106, new[] { 3, 35 } }, { 107, new[] { 4, 36 } },
            { 108, new[] { 5, 37 } }, { 109, new[] { 6, 38 } }, { 102, new[] { 7 } }, { 103, new[] { 8 } },
            { 104, new[] { 9 } }, { 203, new[] { 10 } }, { 204, new[] { 11, 12 } }, { 301, new[] { 14, 39 } },
            { 303, new[] { 15, 40 } }, { 302, new[] { 16, 41 } }, { 305, new[] { 17, 42 } }, { 306, new[] { 18, 43 } },
            { 304, new[] { 19, 44 } }, { 503, new[] { 22 } }, { 508, new[] { 23, 24, 25 } }, { 206, new[] { 27 } },
            { 308, new[] { 31 } }, { 309, new[] { 32 } }, { 307, new[] { 42 } } };

        public static string CheckSlotFamily(int slot, int catalog)
        {
            if (slot < 0 || slot >= AvatarState.SlotCount) return "slot_out_of_range";
            int family = catalog / 10000;
            if (slot == 0 && family != 100) return "slot0_not_class";
            int[] allowed;
            if (!SlotFamilies.TryGetValue(family, out allowed)) return null;
            return Array.IndexOf(allowed, slot) >= 0 ? null : "slot_family_mismatch";
        }

        // My Info 40/A4: put an owned instance into a slot of an owned avatar. Returns null on
        // success or a reason; on a reason the state is unchanged.
        public string Equip(int avatarId, int slot, int instance)
        {
            AvatarState avatar = FindAvatar(avatarId);
            if (avatar == null) return "avatar_not_owned";
            ItemRecord item = FindItem(instance);
            if (item == null) return "item_not_owned";
            string family = CheckSlotFamily(slot, item.Catalog);
            if (family != null) return family;
            // An instance occupies at most one slot of an avatar (moving Exo 11 <-> 12).
            for (int n = 0; n < AvatarState.SlotCount; n++)
                if (n != slot && avatar.Slots[n] == instance) avatar.Slots[n] = 0;
            avatar.Slots[slot] = instance;
            return null;
        }

        // My Info 40/A6: empty a slot. Slot 0 (class) is never emptied: the v1.11 client sent
        // 40/A6 slot 0 once and the header-only ack let it continue, so that stays a no-op ack.
        public string Unequip(int avatarId, int slot)
        {
            AvatarState avatar = FindAvatar(avatarId);
            if (avatar == null) return "avatar_not_owned";
            if (slot < 0 || slot >= AvatarState.SlotCount) return "slot_out_of_range";
            if (slot > 0) avatar.Slots[slot] = 0;
            return null;
        }

        public string SelectAvatar(int avatarId)
        {
            if (FindAvatar(avatarId) == null) return "avatar_not_owned";
            CurrentAvatar = avatarId;
            return null;
        }

        // Equipment references whose instance is not owned (admin repair reports these).
        public List<string> DanglingReferences()
        {
            List<string> found = new List<string>();
            foreach (AvatarState a in Avatars)
                for (int n = 0; n < AvatarState.SlotCount; n++)
                    if (a.Slots[n] != 0 && FindItem(a.Slots[n]) == null)
                        found.Add(a.Id + ":" + n + ":" + a.Slots[n]);
            return found;
        }

        public int RepairDangling()
        {
            int fixedCount = 0;
            foreach (AvatarState a in Avatars)
                for (int n = 1; n < AvatarState.SlotCount; n++)
                    if (a.Slots[n] != 0 && FindItem(a.Slots[n]) == null) { a.Slots[n] = 0; fixedCount++; }
            return fixedCount;
        }

        // Grant: copy an observed record for the catalog, assign the next local instance ID.
        public ItemRecord Grant(byte[] observedRecord)
        {
            if (observedRecord == null || observedRecord.Length != ItemRecord.Size) throw new InvalidOperationException("grant_record_invalid");
            if (NextInstance <= 0) throw new InvalidOperationException("instance_space_exhausted");
            while (FindItem(NextInstance) != null) NextInstance++;
            ItemRecord r = new ItemRecord { Raw = (byte[])observedRecord.Clone() };
            ItemRecord.Put32(r.Raw, 0, NextInstance++);
            Items.Add(r);
            return r;
        }

        // 1.26 Store purchase (31/80). Only free admin purchases exist: the server has no price
        // table, so without unlimited currency it cannot charge correctly and refuses (no state
        // change). The record is the observed record for the catalog when its item_end matches
        // the request; otherwise the Gemnet record shape (+8 = 85582, the most common observed
        // value; item_end from the request; all other bytes zero). Returns null or a reason;
        // `granted` receives the new record.
        public const int ReferenceWord8 = 85582;

        public string Purchase(int catalog, int itemEnd, byte[] observedRecord, out ItemRecord granted, out bool usedObservedRecord)
        {
            granted = null;
            usedObservedRecord = false;
            if (!UnlimitedCurrency) return "purchase_requires_unlimited_currency";
            if (catalog <= 0) return "catalog_invalid";
            if (itemEnd < 0) return "item_end_invalid";
            byte[] raw;
            if (observedRecord != null && ItemRecord.Le32(observedRecord, 4) == catalog && ItemRecord.Le32(observedRecord, 29) == itemEnd)
            {
                raw = (byte[])observedRecord.Clone();
                usedObservedRecord = true;
            }
            else
            {
                raw = new byte[ItemRecord.Size];
                ItemRecord.Put32(raw, 4, catalog);
                ItemRecord.Put32(raw, 8, ReferenceWord8);
                ItemRecord.Put32(raw, 29, itemEnd);
            }
            granted = Grant(raw);
            return null;
        }

        public string Validate()
        {
            if (AccountId <= 0) return "account_id_invalid";
            if (Cash < 0 || Medals < 0 || Carats < 0) return "balance_negative";
            if (UnlimitedBalance < 1 || UnlimitedBalance > MaxUnlimitedBalance) return "unlimited_balance_out_of_range";
            if (string.IsNullOrEmpty(Name) || Name.Length >= 20) return "name_invalid";
            foreach (char c in Name + Country + Region) if (c <= 32 || c > 126) return "text_not_ascii";
            if (Level < 0 || Level > 255 || Experience < 0 || Experience > uint.MaxValue) return "level_invalid";
            if (Avatars.Count < 1 || Avatars.Count > 20) return "avatar_count_invalid";
            if (FindAvatar(CurrentAvatar) == null) return "current_avatar_invalid";
            HashSet<int> seen = new HashSet<int>();
            foreach (ItemRecord r in Items)
            {
                if (r.Raw == null || r.Raw.Length != ItemRecord.Size || r.Instance <= 0) return "item_record_invalid";
                if (!seen.Add(r.Instance)) return "duplicate_instance";
                if (r.Instance == AccountId || FindAvatar(r.Instance) != null) return "instance_collides_with_id";
            }
            HashSet<int> avatarIds = new HashSet<int>();
            foreach (AvatarState a in Avatars)
            {
                if (a.Id <= 0 || !avatarIds.Add(a.Id)) return "avatar_id_invalid";
                if (a.Slots == null || a.Slots.Length != AvatarState.SlotCount) return "slots_invalid";
                if (a.Slots[0] == 0) return "class_slot_empty";
            }
            return null;
        }

        public string Serialize()
        {
            StringBuilder text = new StringBuilder();
            text.Append(Schema).Append('\n');
            text.Append("account ").Append(AccountId).Append(' ').Append(Name).Append(' ').Append(Level).Append(' ')
                .Append(Experience).Append(' ').Append(Cash).Append(' ').Append(Medals).Append(' ').Append(CurrentAvatar)
                .Append(' ').Append(NextInstance).Append(' ').Append(Country).Append(' ').Append(Region).Append('\n');
            foreach (AvatarState a in Avatars)
            {
                text.Append("avatar ").Append(a.Id).Append(' ');
                for (int n = 0; n < AvatarState.SlotCount; n++) text.Append(n == 0 ? "" : ",").Append(a.Slots[n]);
                text.Append('\n');
            }
            text.Append("currency ").Append(Carats).Append(' ').Append(UnlimitedCurrency ? 1 : 0).Append(' ').Append(UnlimitedBalance).Append('\n');
            foreach (ItemRecord r in Items) text.Append("item ").Append(Hex(r.Raw)).Append('\n');
            return text.ToString();
        }

        public static AccountState Parse(string text)
        {
            string[] lines = text.Replace("\r", "").Split('\n');
            if (lines.Length < 2 || (lines[0] != Schema && lines[0] != SchemaV1)) throw new InvalidDataException("account_schema_mismatch");
            AccountState s = new AccountState();
            bool sawAccount = false;
            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (line.Length == 0) continue;
                string[] f = line.Split(' ');
                if (f[0] == "currency" && f.Length == 4 && lines[0] == Schema)
                {
                    s.Carats = Int(f[1]);
                    if (f[2] != "0" && f[2] != "1") throw new InvalidDataException("currency_flag_invalid");
                    s.UnlimitedCurrency = f[2] == "1";
                    s.UnlimitedBalance = Int(f[3]);
                }
                else if (f[0] == "account" && f.Length == 11 && !sawAccount)
                {
                    sawAccount = true;
                    s.AccountId = Int(f[1]); s.Name = f[2]; s.Level = Int(f[3]);
                    s.Experience = long.Parse(f[4], CultureInfo.InvariantCulture);
                    s.Cash = Int(f[5]); s.Medals = Int(f[6]); s.CurrentAvatar = Int(f[7]); s.NextInstance = Int(f[8]);
                    s.Country = f[9]; s.Region = f[10];
                }
                else if (f[0] == "avatar" && f.Length == 3)
                {
                    string[] slots = f[2].Split(',');
                    if (slots.Length != AvatarState.SlotCount) throw new InvalidDataException("avatar_slots_invalid");
                    AvatarState a = new AvatarState { Id = Int(f[1]) };
                    for (int n = 0; n < slots.Length; n++) a.Slots[n] = Int(slots[n]);
                    s.Avatars.Add(a);
                }
                else if (f[0] == "item" && f.Length == 2 && f[1].Length == ItemRecord.Size * 2)
                    s.Items.Add(new ItemRecord { Raw = Unhex(f[1]) });
                else throw new InvalidDataException("account_line_invalid:" + i);
            }
            if (!sawAccount) throw new InvalidDataException("account_line_missing");
            string invalid = s.Validate();
            if (invalid != null) throw new InvalidDataException("account_invalid:" + invalid);
            return s;
        }

        private static int Int(string v) { return int.Parse(v, NumberStyles.Integer, CultureInfo.InvariantCulture); }

        internal static string Hex(byte[] b)
        {
            StringBuilder t = new StringBuilder(b.Length * 2);
            foreach (byte x in b) t.Append(x.ToString("x2"));
            return t.ToString();
        }

        internal static byte[] Unhex(string h)
        {
            byte[] b = new byte[h.Length / 2];
            for (int n = 0; n < b.Length; n++) b[n] = byte.Parse(h.Substring(2 * n, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return b;
        }
    }

    // File-backed store. Every change is load -> modify -> validate -> atomic replace, under
    // a machine-wide mutex, so a reconnect or a server restart sees exactly the saved state.
    public sealed class AccountStore
    {
        private readonly string path;
        private const string MutexName = "Global\\RFLocalAccountStore_v1";

        public AccountStore(string path) { this.path = Path.GetFullPath(path); }
        public string FilePath { get { return path; } }

        private T WithLock<T>(Func<T> body)
        {
            using (Mutex mutex = new Mutex(false, MutexName))
            {
                bool owned;
                try { owned = mutex.WaitOne(5000); }
                catch (AbandonedMutexException) { owned = true; }
                if (!owned) throw new TimeoutException("account_store_busy");
                try { return body(); }
                finally { mutex.ReleaseMutex(); }
            }
        }

        public bool Exists { get { return File.Exists(path); } }

        public AccountState Load()
        {
            return WithLock(() => AccountState.Parse(File.ReadAllText(path, Encoding.ASCII)));
        }

        // Creates the file from `initial` only if it does not exist yet; returns the stored state.
        public AccountState LoadOrCreate(AccountState initial)
        {
            return WithLock(() =>
            {
                if (!File.Exists(path)) WriteAtomic(initial);
                return AccountState.Parse(File.ReadAllText(path, Encoding.ASCII));
            });
        }

        // Applies `change` to the stored state; it returns null to commit or a reason to discard.
        public string Update(Func<AccountState, string> change)
        {
            return WithLock(() =>
            {
                AccountState state = AccountState.Parse(File.ReadAllText(path, Encoding.ASCII));
                string reason = change(state);
                if (!string.IsNullOrEmpty(reason)) return reason;   // PowerShell delegates return "" for none
                string invalid = state.Validate();
                if (invalid != null) return "invalid_after_change:" + invalid;
                WriteAtomic(state);
                return null;
            });
        }

        public void Replace(AccountState state)
        {
            string invalid = state.Validate();
            if (invalid != null) throw new InvalidDataException("account_invalid:" + invalid);
            WithLock(() => { WriteAtomic(state); return 0; });
        }

        public string Backup(string directory, string label)
        {
            return WithLock(() =>
            {
                Directory.CreateDirectory(directory);
                string target = Path.Combine(directory, "account-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") +
                    (string.IsNullOrEmpty(label) ? "" : "-" + label) + ".txt");
                AccountState.Parse(File.ReadAllText(path, Encoding.ASCII));   // only valid state is backed up
                File.Copy(path, target, false);
                return target;
            });
        }

        public void Restore(string backupFile)
        {
            AccountState state = AccountState.Parse(File.ReadAllText(backupFile, Encoding.ASCII));
            Replace(state);
        }

        private void WriteAtomic(AccountState state)
        {
            string directory = Path.GetDirectoryName(path);
            Directory.CreateDirectory(directory);
            string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            byte[] bytes = Encoding.ASCII.GetBytes(state.Serialize());
            try
            {
                using (FileStream f = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    f.Write(bytes, 0, bytes.Length);
                    f.Flush(true);
                }
                if (File.Exists(path)) File.Replace(temp, path, path + ".bak");
                else File.Move(temp, path);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
    }

    // Observed item records (private/fixtures/item-records.v1.tsv from rf_item_records.py).
    public sealed class ItemCatalog
    {
        public readonly Dictionary<int, byte[]> Records = new Dictionary<int, byte[]>();
        public readonly Dictionary<int, string> Slots = new Dictionary<int, string>();

        public static ItemCatalog Load(string tsv)
        {
            ItemCatalog c = new ItemCatalog();
            foreach (string line in File.ReadAllLines(tsv, Encoding.ASCII))
            {
                if (line.Length == 0 || line[0] == '#') continue;
                string[] f = line.Split('\t');
                if (f.Length != 8 || f[7].Length != ItemRecord.Size * 2) throw new InvalidDataException("item_records_line_invalid");
                byte[] raw = AccountState.Unhex(f[7]);
                int catalog = int.Parse(f[0], CultureInfo.InvariantCulture);
                if (ItemRecord.Le32(raw, 4) != catalog || ItemRecord.Le32(raw, 0) != 0) throw new InvalidDataException("item_records_catalog_mismatch");
                c.Records[catalog] = raw;
                c.Slots[catalog] = f[6];
            }
            return c;
        }
    }

    // Wire builders reading AccountState. Header: type BE16, total BE16, action LE16.
    public static class AccountWire
    {
        private static byte[] Frame(int type, int action, int bodyLength)
        {
            int total = 6 + bodyLength;
            byte[] f = new byte[total];
            f[0] = (byte)(type >> 8); f[1] = (byte)type; f[2] = (byte)(total >> 8); f[3] = (byte)total;
            f[4] = (byte)action; f[5] = (byte)(action >> 8);
            return f;
        }

        // 30/85: LE16 count, 80 x 49-byte records (unused records zero), total 3928.
        public static byte[] PropertyPage(AccountState s, int cursor)
        {
            byte[] f = Frame(0x30, 0x85, 3922);
            List<ItemRecord> page = s.Page(cursor, 80);
            f[6] = (byte)page.Count; f[7] = (byte)(page.Count >> 8);
            for (int n = 0; n < page.Count; n++) Array.Copy(page[n].Raw, 0, f, 8 + 49 * n, 49);
            return f;
        }

        // 30/87: count byte, then 20 LE32 avatar IDs.
        public static byte[] AvatarList(AccountState s)
        {
            byte[] f = Frame(0x30, 0x87, 81);
            f[6] = (byte)s.Avatars.Count;
            for (int n = 0; n < s.Avatars.Count; n++) ItemRecord.Put32(f, 7 + 4 * n, s.Avatars[n].Id);
            return f;
        }

        // 40/A1: the selected avatar.
        public static byte[] EquippedAvatar(AccountState s)
        {
            byte[] f = Frame(0x40, 0xa1, 4);
            ItemRecord.Put32(f, 6, s.CurrentAvatar);
            return f;
        }

        // 30/89: 45 LE32 instance refs + 180-byte tail (zero in every capture).
        public static byte[] Equipment(AccountState s, int avatarId)
        {
            byte[] f = Frame(0x30, 0x89, 360);
            AvatarState a = s.FindAvatar(avatarId);
            if (a != null) for (int n = 0; n < AvatarState.SlotCount; n++) ItemRecord.Put32(f, 6 + 4 * n, a.Slots[n]);
            return f;
        }

        // 31/89: account ID, cash, medals (three LE32).
        public static byte[] Cash(AccountState s)
        {
            byte[] f = Frame(0x31, 0x89, 12);
            ItemRecord.Put32(f, 6, s.AccountId); ItemRecord.Put32(f, 10, s.EffectiveAstros); ItemRecord.Put32(f, 14, s.Medals);
            return f;
        }

        // 30/81 GET_USER_INFO (1561-byte body), fields mapped in rf-boss-baseline
        // (rf_userinfo_fields.py): +0 account ID, +4 name (20), +24 level, +28 experience,
        // +32 45 LE32 CATALOG IDs of the current avatar's equipped instances, +1521 country,
        // +1529 region. Every other byte is zero here (official values there are unidentified:
        // +824, +836, +1484..+1517). EXPERIMENTAL layout beyond the mapped fields.
        public static byte[] UserInfo(AccountState s)
        {
            byte[] f = Frame(0x30, 0x81, 1561);
            int b = 6;
            ItemRecord.Put32(f, b, s.AccountId);
            PutText(f, b + 4, 20, s.Name);
            ItemRecord.Put32(f, b + 24, s.Level);
            ItemRecord.Put32(f, b + 28, (int)(uint)s.Experience);
            AvatarState a = s.FindAvatar(s.CurrentAvatar);
            for (int n = 0; n < AvatarState.SlotCount && a != null; n++)
            {
                ItemRecord item = a.Slots[n] == 0 ? null : s.FindItem(a.Slots[n]);
                if (item != null) ItemRecord.Put32(f, b + 32 + 4 * n, item.Catalog);
            }
            PutText(f, b + 1521, 8, s.Country);
            PutText(f, b + 1529, 8, s.Region);
            return f;
        }

        internal static void PutText(byte[] f, int offset, int width, string value)
        {
            if (value.Length >= width) throw new InvalidOperationException("text_too_long");
            for (int n = 0; n < value.Length; n++) f[offset + n] = (byte)value[n];
        }

        // 31/81 buy reply (Gemnet BuyItemRes; no capture): LE32 new instance (ServerID), LE32 Carats.
        public static byte[] BuyReply(AccountState s, int instance)
        {
            byte[] f = Frame(0x31, 0x81, 8);
            ItemRecord.Put32(f, 6, instance);
            ItemRecord.Put32(f, 10, s.EffectiveCarats);
            return f;
        }

        // 30/D7 body 01: the reply to every captured 30/D6 (4/4, each naming an owned catalog).
        public static byte[] ItemCheckOk() { byte[] f = Frame(0x30, 0xd7, 1); f[6] = 1; return f; }
    }
}

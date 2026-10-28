using System;
using System.IO;
using RFLocalHandshake;

internal static class Program
{
    private static int Main(string[] args)
    {
        string privateRoot = null;
        if (args.Length == 1 && (args[0] == "--help" || args[0] == "-h"))
        {
            Usage();
            return 0;
        }
        if (args.Length == 2 && args[0] == "--private-root")
        {
            privateRoot = Path.GetFullPath(args[1]);
        }
        else if (args.Length != 0)
        {
            Usage();
            return 2;
        }

        string capture = null;
        string fixture = null;
        if (privateRoot != null)
        {
            capture = Path.Combine(privateRoot, "captures", "rf-startup.pcapng");
            fixture = Path.Combine(privateRoot, "fixtures", "lobby-boss-v2.bin");
            bool missing = false;
            foreach (string path in new[] { capture, fixture })
            {
                if (!File.Exists(path))
                {
                    Console.Error.WriteLine("Missing required private fixture: " + path);
                    missing = true;
                }
            }
            if (missing) return 2;
        }

        int passed = 0;
        int failed = 0;
        string temporary = null;
        try
        {
            temporary = Directory.CreateTempSubdirectory("rumble-preservation-checks-").FullName;
            Action<string, Func<string>> check = (name, run) =>
            {
                try
                {
                    string summary = run();
                    Console.WriteLine("PASS " + name + (string.IsNullOrEmpty(summary) ? "" : ": " + summary));
                    passed++;
                }
                catch (Exception error)
                {
                    Console.Error.WriteLine("FAIL " + name + ": " + error.GetType().Name + ": " + error.Message);
                    failed++;
                }
            };

            check("synthetic protocol self-tests", () => { Probe.SelfTest(); return "completed"; });
            check("plaza loopback integration", () => PlazaSelfTest.Run(Path.Combine(temporary, "plaza.jsonl")));

            if (privateRoot != null)
            {
                check("claimed lobby session", () => Probe.RunScriptedSession(capture, fixture, 160, true));
                check("unclaimed lobby session", () => Probe.RunScriptedSession(capture, fixture, 20, false));
                check("persistent reconnect", () => Probe.RunScriptedReconnect(capture, fixture,
                    Path.Combine(temporary, "reconnect.jsonl"), 3000));
                check("account persistence", () => Probe.SelfTestAccount(capture, fixture,
                    Path.Combine(temporary, "accounts")));
            }
            else
            {
                Console.WriteLine("NOT RUN: four private-fixture groups (supply --private-root to include them).");
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("FAIL test setup: " + error.GetType().Name + ": " + error.Message);
            failed++;
        }
        finally
        {
            if (temporary != null)
            {
                try { Directory.Delete(temporary, true); }
                catch (Exception error)
                {
                    Console.Error.WriteLine("FAIL temporary directory cleanup: " + error.Message);
                    failed++;
                }
            }
        }
        Console.WriteLine("Check groups: " + passed + " passed, " + failed + " failed.");
        return failed == 0 ? 0 : 1;
    }

    private static void Usage()
    {
        Console.WriteLine("Usage: Preservation.Checks [--private-root PATH]");
        Console.WriteLine("Default: synthetic protocol and localhost plaza integration tests.");
        Console.WriteLine("With --private-root: also validate captured lobby sessions, reconnects and temporary account persistence.");
        Console.WriteLine("Private fixtures are read only. Test accounts and logs use an isolated temporary directory.");
    }
}

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

const int DefaultPort = 3389;
const int DefaultTimeoutMs = 2000;      // default timeout (ms)
const int DefaultMaxConcurrency = 200;  // default concurrency
const uint DefaultMaxAllowed = 0;       // default safety cap (0 = unlimited)

string? rangeArg = null;
int timeoutMs = DefaultTimeoutMs;
int maxConcurrency = DefaultMaxConcurrency;
uint maxAllowed = DefaultMaxAllowed;

// If no args, prompt for range and optional timeout/concurrency/maxAllowed
if (args.Length == 0)
{
    Console.WriteLine("Enter an IP range in the form: <startIP>-<endIP>");
    Console.WriteLine("Example: 192.168.1.1-192.168.1.254");
    Console.Write("> ");
    var input = Console.ReadLine();
    if (string.IsNullOrWhiteSpace(input))
    {
        Console.WriteLine("No range provided. Exiting.");
        return;
    }
    rangeArg = input.Trim();

    Console.Write($"Timeout in ms (default {DefaultTimeoutMs}): ");
    input = Console.ReadLine();
    if (int.TryParse(input, out var t)) timeoutMs = Math.Max(100, t);

    Console.Write($"Max threads / concurrency (default {DefaultMaxConcurrency}): ");
    input = Console.ReadLine();
    if (int.TryParse(input, out var c)) maxConcurrency = Math.Max(1, c);

    Console.Write($"Max addresses allowed (0 = unlimited, default {DefaultMaxAllowed}): ");
    input = Console.ReadLine();
    if (long.TryParse(input, out var m) && m >= 0) maxAllowed = (uint)Math.Min(m, uint.MaxValue);
}
else
{
    // args: <range> [timeoutMs] [maxConcurrency] [maxAllowed]
    rangeArg = args[0];

    if (args.Length > 1 && int.TryParse(args[1], out var t)) timeoutMs = Math.Max(100, t);
    if (args.Length > 2 && int.TryParse(args[2], out var c)) maxConcurrency = Math.Max(1, c);
    if (args.Length > 3 && long.TryParse(args[3], out var m) && m >= 0) maxAllowed = (uint)Math.Min(m, uint.MaxValue);
}

try
{
    // normalize dashes (handle en-dash/em-dash)
    rangeArg = rangeArg.Replace('–', '-').Replace('—', '-');
    var (start, end) = ParseRangeToBounds(rangeArg);
    ulong total = (ulong)end - (ulong)start + 1UL;

    if (maxAllowed != 0 && total > maxAllowed)
    {
        Console.WriteLine($"Range too large (> {maxAllowed} addresses). Narrow the range or set maxAllowed to 0 to allow larger scans.");
        return;
    }

    if (total == 0)
    {
        Console.WriteLine("No addresses in range. Exiting.");
        return;
    }

    Console.WriteLine($"Scanning {total} addresses for RDP (port {DefaultPort}) with timeout {timeoutMs}ms and concurrency {maxConcurrency}...");

    // progress tuning: choose how often to print ETA based on total
    int progressInterval;
    if (total <= 100) progressInterval = 1;
    else if (total <= 1000) progressInterval = 10;
    else if (total <= 10_000) progressInterval = 50;
    else progressInterval = 500;

    var openHosts = new ConcurrentBag<IPAddress>();
    var running = new ConcurrentBag<Task<(uint idx, bool open)>>();
    int checkedCount = 0;
    var sem = new SemaphoreSlim(maxConcurrency);
    var sw = Stopwatch.StartNew();

    // iterate numeric; do not materialize list
    for (uint cur = start; ; )
    {
        await sem.WaitAsync().ConfigureAwait(false);
        uint ipUint = cur;
        var task = Task.Run(async () =>
        {
            try
            {
                var ip = UIntToIp(ipUint);
                var open = await CheckRdpAsync(ip, DefaultPort, timeoutMs).ConfigureAwait(false);
                var c = Interlocked.Increment(ref checkedCount);

                // compute ETA
                string etaText = "--:--:--";
                if (c > 0)
                {
                    var elapsed = sw.Elapsed;
                    var remaining = (long)total - c;
                    if (remaining > 0)
                    {
                        double secondsPerCheck = elapsed.TotalSeconds / c;
                        var etaSeconds = secondsPerCheck * remaining;
                        var eta = TimeSpan.FromSeconds(Math.Max(0, etaSeconds));
                        etaText = FormatTimeSpan(eta);
                    }
                    else
                    {
                        etaText = "00:00:00";
                    }
                }

                if ((c % progressInterval) == 0 || open)
                {
                    Console.WriteLine($"Checked: {c}/{total}  Open so far: {openHosts.Count}  ETA: {etaText}  Threads: {maxConcurrency}");
                }
                return (ipUint, open);
            }
            finally
            {
                sem.Release();
            }
        });

        running.Add(task);

        // advance cur safely
        if (cur == end) break;
        cur++;

        // periodically clean up completed tasks to add to results
        while (running.TryTake(out var completedTask) && completedTask.IsCompleted)
        {
            var result = await completedTask.ConfigureAwait(false);
            if (result.open) openHosts.Add(UIntToIp(result.idx));
        }
    }

    // wait for remaining tasks and collect results
    while (running.TryTake(out var remaining))
    {
        var res = await remaining.ConfigureAwait(false);
        if (res.open) openHosts.Add(UIntToIp(res.idx));
    }

    sw.Stop();
    Console.WriteLine();
    Console.WriteLine($"Scan complete. {openHosts.Count} hosts with port {DefaultPort} open. Elapsed: {FormatTimeSpan(sw.Elapsed)}");
    foreach (var h in openHosts) Console.WriteLine(h);
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
}

// parse start-end or single IP and return numeric bounds (inclusive)
static (uint start, uint end) ParseRangeToBounds(string input)
{
    if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("Empty range.");

    if (input.Contains("-"))
    {
        var parts = input.Split('-', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2) throw new ArgumentException("Invalid range format. Use startIP-endIP.");
        if (!IPAddress.TryParse(parts[0].Trim(), out var start)) throw new ArgumentException("Invalid start IP.");
        if (!IPAddress.TryParse(parts[1].Trim(), out var end)) throw new ArgumentException("Invalid end IP.");
        if (start.AddressFamily != AddressFamily.InterNetwork || end.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 supported.");

        uint s = IpToUInt(start);
        uint e = IpToUInt(end);
        if (s > e) throw new ArgumentException("Start IP must be <= end IP.");
        return (s, e);
    }

    if (!IPAddress.TryParse(input.Trim(), out var single)) throw new ArgumentException("Invalid IP.");
    var u = IpToUInt(single);
    return (u, u);
}

static uint IpToUInt(IPAddress ip)
{
    var bytes = ip.GetAddressBytes();
    if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
    return BitConverter.ToUInt32(bytes, 0);
}

static IPAddress UIntToIp(uint ip)
{
    var bytes = BitConverter.GetBytes(ip);
    if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
    return new IPAddress(bytes);
}

static async Task<bool> CheckRdpAsync(IPAddress ip, int port, int timeoutMs)
{
    using var tcp = new TcpClient(AddressFamily.InterNetwork);
    try
    {
        var connectTask = tcp.ConnectAsync(ip, port);
        var delayTask = Task.Delay(timeoutMs);
        var completed = await Task.WhenAny(connectTask, delayTask).ConfigureAwait(false);
        if (completed != connectTask) return false;
        if (connectTask.IsFaulted) return false;
        return tcp.Connected;
    }
    catch
    {
        return false;
    }
}

static string FormatTimeSpan(TimeSpan ts)
{
    return string.Format("{0:D2}:{1:D2}:{2:D2}", (int)ts.TotalHours, ts.Minutes, ts.Seconds);
}

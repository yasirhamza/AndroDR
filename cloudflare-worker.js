const APK_URL = "https://github.com/yasirhamza/androdr-releases/releases/download/latest/app-debug.apk";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Proxy the APK download through Cloudflare
    if (url.pathname === "/download") {
      const apk = await fetch(APK_URL, { redirect: "follow" });
      if (!apk.ok) {
        return new Response("Failed to download APK", { status: 502 });
      }
      return new Response(apk.body, {
        headers: {
          "Content-Type": "application/vnd.android.package-archive",
          "Content-Disposition": "attachment; filename=AndroDR.apk",
          "Cache-Control": "public, max-age=3600",
        },
      });
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AndroDR — Android Security Scanner</title>
  <style>
    :root {
      --bg: #0f1117;
      --surface: #1a1d27;
      --border: #2a2d3a;
      --text: #e4e6ed;
      --text-muted: #9ca3b4;
      --accent: #4f8cff;
      --accent-hover: #6ba0ff;
      --green: #34d399;
      --red: #f87171;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }
    .container { max-width: 720px; margin: 0 auto; padding: 0 24px; }
    header { padding: 48px 0 32px; text-align: center; }
    header h1 { font-size: 2.4rem; font-weight: 700; letter-spacing: -0.02em; }
    header h1 .shield { color: var(--green); }
    header p.tagline { color: var(--text-muted); font-size: 1.1rem; margin-top: 8px; }
    .download-section { text-align: center; padding: 32px 0; }
    .download-btn {
      display: inline-block; background: var(--accent); color: #fff;
      text-decoration: none; padding: 14px 36px; border-radius: 8px;
      font-size: 1.1rem; font-weight: 600; transition: background 0.2s;
    }
    .download-btn:hover { background: var(--accent-hover); }
    .download-meta { color: var(--text-muted); font-size: 0.85rem; margin-top: 12px; }
    .download-meta a { color: var(--accent); text-decoration: none; }
    .download-meta a:hover { text-decoration: underline; }
    hr { border: none; border-top: 1px solid var(--border); margin: 32px 0; }
    .privacy h2 { font-size: 1.6rem; font-weight: 700; margin-bottom: 16px; }
    .privacy h3 { font-size: 1.15rem; font-weight: 600; margin-top: 28px; margin-bottom: 8px; }
    .privacy p { margin-bottom: 12px; color: var(--text); }
    .privacy strong { color: #fff; }
    .privacy ul { margin: 8px 0 12px 20px; color: var(--text); }
    .privacy li { margin-bottom: 4px; }
    .privacy table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.9rem; }
    .privacy th { text-align: left; padding: 8px 12px; background: var(--surface); border: 1px solid var(--border); color: var(--text-muted); font-weight: 600; }
    .privacy td { padding: 8px 12px; border: 1px solid var(--border); }
    .privacy code { background: var(--surface); padding: 2px 6px; border-radius: 3px; font-size: 0.88em; }
    footer { text-align: center; padding: 32px 0 48px; color: var(--text-muted); font-size: 0.85rem; }
    footer a { color: var(--accent); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
    nav { display: flex; justify-content: center; gap: 24px; margin-top: 16px; }
    nav a { color: var(--text-muted); text-decoration: none; font-size: 0.9rem; }
    nav a:hover { color: var(--accent); }
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1><span class="shield">&#x1f6e1;</span> AndroDR</h1>
    <p class="tagline">Open-source Android security scanner &amp; endpoint detection</p>
    <nav>
      <a href="https://github.com/yasirhamza/AndroDR">GitHub</a>
      <a href="#privacy">Privacy Policy</a>
      <a href="#download">Download</a>
    </nav>
  </header>
  <section class="download-section" id="download">
    <a class="download-btn" href="/download">Download Latest APK</a>
    <p class="download-meta">
      Free &amp; open source &middot; No accounts &middot; No tracking
    </p>
  </section>
  <hr>
  <!-- ANDRODR:PRIVACY:START -->
  <section class="privacy" id="privacy">
    <h2>Privacy Policy</h2>
    <p><em>Last updated: 2026-03-26</em></p>
    <h3>Our Philosophy</h3>
    <p>AndroDR is an open-source security tool built on a simple principle: <strong>your data stays on your device</strong>. The entire source code is publicly auditable — you don't have to trust our words, you can read the code.</p>
    <p>We believe security tools should give users full visibility and control, not create new surveillance risks. AndroDR collects no accounts, no analytics, no telemetry, and phones home to no servers.</p>
    <h3>What AndroDR Does</h3>
    <ul>
      <li>Checks installed apps against known malware and stalkerware databases</li>
      <li>Matches app signing certificates against known malicious certificate hashes</li>
      <li>Detects apps with dangerous permission combinations</li>
      <li>Identifies sideloaded apps from untrusted sources</li>
      <li>Detects accessibility service and device admin abuse</li>
      <li>Monitors DNS queries for connections to known command-and-control servers</li>
      <li>Audits device security settings (screen lock, bootloader, debug mode, patch level)</li>
      <li>Analyzes Android bug reports for spyware indicators (user-initiated only)</li>
    </ul>
    <h3>Data That Stays On Your Device</h3>
    <p>All scan data is stored locally in an on-device database. <strong>None of it is ever transmitted to us or any third party.</strong></p>
    <table>
      <thead><tr><th>Data</th><th>Purpose</th><th>Storage</th></tr></thead>
      <tbody>
        <tr><td>Installed app list</td><td>Scanned for threat detection</td><td>On-device database</td></tr>
        <tr><td>DNS queries</td><td>Checked against domain blocklist</td><td>On-device database</td></tr>
        <tr><td>Device security flags</td><td>Posture assessment</td><td>On-device database</td></tr>
        <tr><td>Scan results and history</td><td>Track security state over time</td><td>On-device database</td></tr>
        <tr><td>Security reports</td><td>User-initiated export only</td><td>Device storage</td></tr>
      </tbody>
    </table>
    <p><strong>We cannot see your scan results.</strong> There is no cloud backend, no remote dashboard, no server-side processing. Cloud backup is disabled — your scan data is never uploaded to Google's backup service.</p>
    <h3>Permissions and Why We Need Them</h3>
    <table>
      <thead><tr><th>Permission</th><th>Why it's needed</th></tr></thead>
      <tbody>
        <tr><td><code>QUERY_ALL_PACKAGES</code></td><td>To scan all installed apps for malware indicators</td></tr>
        <tr><td><code>INTERNET</code></td><td>To fetch publicly available threat intelligence feeds (no user data sent)</td></tr>
        <tr><td><code>FOREGROUND_SERVICE</code></td><td>To run the DNS monitoring VPN service in the background</td></tr>
        <tr><td><code>ACCESS_NETWORK_STATE</code></td><td>To check network connectivity before fetching IOC feed updates</td></tr>
        <tr><td><code>READ_LOGS</code></td><td>To capture AndroDR's own process log for user-initiated security reports</td></tr>
        <tr><td><code>MANAGE_EXTERNAL_STORAGE</code></td><td>To scan external storage for known spyware file artifacts</td></tr>
      </tbody>
    </table>
    <h3>Network Requests AndroDR Makes</h3>
    <p>AndroDR fetches publicly available threat intelligence feeds to keep its detection databases current. These requests contain <strong>no user data, no device identifiers, and no information about your installed apps</strong>.</p>
    <table>
      <thead><tr><th>Feed</th><th>Source</th><th>What's fetched</th></tr></thead>
      <tbody>
        <tr><td>Stalkerware indicators</td><td>AssoEchap (GitHub)</td><td>Known stalkerware package names</td></tr>
        <tr><td>Spyware domain IOCs</td><td>mvt-project (GitHub)</td><td>Known spyware C2 domains</td></tr>
        <tr><td>Known app database</td><td>UAD / Plexus</td><td>Legitimate app lists for false positive reduction</td></tr>
      </tbody>
    </table>
    <p>All requests are unauthenticated public HTTP GET requests. No API keys, no cookies, no tracking headers.</p>
    <h3>DNS Monitoring</h3>
    <p>AndroDR's DNS monitor uses a local VPN to intercept DNS queries <strong>on your device only</strong>. DNS queries are resolved locally — no traffic is routed to external servers. The VPN does not route, inspect, or modify your web traffic. You can enable or disable DNS monitoring at any time.</p>
    <h3>Bug Report Analysis</h3>
    <p>AndroDR can analyze Android bug report files (<code>.zip</code>) that you manually provide. Everything is processed <strong>entirely on-device</strong> — no part of the bug report is transmitted anywhere.</p>
    <h3>What Exported Reports Contain</h3>
    <p>When you export a security report, it includes device information, scan results, DNS event logs, and application logs. Reports are generated only when you tap the export button. You choose who to share them with. <strong>We never see your reports.</strong></p>
    <h3>What We Do NOT Collect</h3>
    <ul>
      <li>No personal information (name, email, phone number)</li>
      <li>No device identifiers (IMEI, serial number, advertising ID)</li>
      <li>No location data</li>
      <li>No browsing history or message content</li>
      <li>No photos or files</li>
      <li>No usage analytics or telemetry</li>
      <li>No crash reporting or analytics SDKs</li>
      <li>No data shared with third parties</li>
      <li>No advertising SDKs</li>
      <li>No cloud backup of app data</li>
    </ul>
    <h3>Data Sharing</h3>
    <p>AndroDR shares data <strong>only when you explicitly choose to</strong> — via user-initiated report export through the Android share sheet. Nothing is sent anywhere without your explicit action.</p>
    <h3>Data Retention and Deletion</h3>
    <ul>
      <li>Scan history and DNS events are stored on-device indefinitely until you clear them</li>
      <li>Cloud backup is disabled</li>
      <li>Uninstalling AndroDR deletes all stored data</li>
      <li>You can clear all app data via Android Settings &gt; Apps &gt; AndroDR &gt; Clear Data</li>
    </ul>
    <h3>Open Source Transparency</h3>
    <p>AndroDR's source code is <a href="https://github.com/yasirhamza/AndroDR">publicly available</a>. Every detection heuristic, every network request, every data storage operation is visible in the code.</p>
    <h3>Google Play Data Safety Alignment</h3>
    <ul>
      <li><strong>Data collected:</strong> Installed app list (on-device only, never transmitted)</li>
      <li><strong>Data shared:</strong> None</li>
      <li><strong>Data encrypted in transit:</strong> N/A — no user data is transmitted</li>
      <li><strong>Data deletion:</strong> Available via app uninstall or clearing app data</li>
    </ul>
    <h3>Children's Privacy</h3>
    <p>AndroDR does not knowingly collect any data from children under 13. The app does not collect data from anyone — it operates entirely on-device.</p>
    <h3>International Users (GDPR / CCPA)</h3>
    <p><strong>EU users (GDPR):</strong> No personal data is collected or processed by the developer. All data resides on your device under your control. Uninstalling the app erases all data.</p>
    <p><strong>California users (CCPA):</strong> AndroDR does not sell, share, or disclose personal information to any third party.</p>
    <h3>Changes to This Policy</h3>
    <p>If this policy changes, the updated version will be published here and the "last updated" date will be revised.</p>
    <h3>Contact</h3>
    <p>For privacy questions: <a href="mailto:privacy@androdr.dev">privacy@androdr.dev</a><br>
    GitHub: <a href="https://github.com/yasirhamza/AndroDR/issues">github.com/yasirhamza/AndroDR/issues</a></p>
  </section>
  <!-- ANDRODR:PRIVACY:END -->
  <footer>
    <p>&copy; 2026 AndroDR. Open source under the project license.</p>
    <p><a href="https://github.com/yasirhamza/AndroDR">Source Code</a></p>
  </footer>
</div>
</body>
</html>`;

    return new Response(html, {
      headers: { "Content-Type": "text/html;charset=UTF-8" },
    });
  },
};

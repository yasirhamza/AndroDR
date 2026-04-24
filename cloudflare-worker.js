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
<p><em>Last updated: 2026-04-25</em></p>
<h2>Our Philosophy</h2>
<p>AndroDR is an open-source security tool built on a simple principle: <strong>your data stays on your device</strong>. The entire source code is publicly auditable — you don't have to trust our words, you can read the code.</p>
<p>We believe security tools should give users full visibility and control, not create new surveillance risks. AndroDR collects no accounts, no analytics, no telemetry, and phones home to no servers. Everything it does happens on your device, under your control.</p>
<hr />
<h2>What AndroDR Does</h2>
<p>AndroDR scans your device for security threats:
- Checks installed apps against known malware and stalkerware databases
- Matches app signing certificates against known malicious certificate hashes
- Detects apps with dangerous permission combinations
- Identifies sideloaded apps from untrusted sources
- Detects accessibility service and device admin abuse
- Optionally monitors DNS queries for connections to known command-and-control servers (<strong>optional</strong> DNS monitoring — you must explicitly enable the local VPN)
- Audits device security settings (screen lock, bootloader, debug mode, patch level)
- Analyzes Android bug reports for spyware indicators (user-initiated only)
- Evaluates detection rules expressed as auditable YAML — detection logic is not hidden inside compiled code
- Imports and exports STIX2-compatible indicators for interoperability with other forensic tools</p>
<hr />
<h2>Data That Stays On Your Device</h2>
<p>All scan data is stored locally in an on-device database. <strong>None of it is ever transmitted to us or any third party.</strong></p>
<table>
<thead>
<tr>
<th>Data</th>
<th>Purpose</th>
<th>Storage</th>
</tr>
</thead>
<tbody>
<tr>
<td>Installed app list (names, permissions, signing certs)</td>
<td>Scanned for threat detection</td>
<td>On-device Room database</td>
</tr>
<tr>
<td>DNS queries (domain names, timestamps)</td>
<td>Checked against domain blocklist</td>
<td>On-device Room database</td>
</tr>
<tr>
<td>Device security flags</td>
<td>Posture assessment</td>
<td>On-device Room database</td>
</tr>
<tr>
<td>Scan results and history</td>
<td>Track security state over time</td>
<td>On-device Room database</td>
</tr>
<tr>
<td>Security reports</td>
<td>User-initiated export only</td>
<td>Device storage, shared via Android share sheet</td>
</tr>
<tr>
<td>Forensic timeline events (e.g., device admin grants)</td>
<td>Displayed in the timeline screen; included in exported reports</td>
<td>On-device Room database</td>
</tr>
<tr>
<td>Bug report analysis findings</td>
<td>Displayed with scan results; original bug report ZIP is discarded after analysis</td>
<td>On-device Room database</td>
</tr>
</tbody>
</table>
<p><strong>We cannot see your scan results.</strong> There is no cloud backend, no remote dashboard, no server-side processing. Cloud backup is disabled (<code>android:allowBackup="false"</code>) — your scan data is never uploaded to Google's backup service.</p>
<hr />
<h2>Permissions and Why We Need Them</h2>
<table>
<thead>
<tr>
<th>Permission</th>
<th>Why it's needed</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>QUERY_ALL_PACKAGES</code></td>
<td>To scan all installed apps for malware indicators. A security scanner cannot detect threats in apps it cannot see. Without this permission, Android limits package visibility and malware could hide from detection.</td>
</tr>
<tr>
<td><code>INTERNET</code></td>
<td>To fetch publicly available threat intelligence feeds (IOC lists). No user data is sent.</td>
</tr>
<tr>
<td><code>FOREGROUND_SERVICE</code></td>
<td>To run the DNS monitoring VPN service while the app is in the background.</td>
</tr>
<tr>
<td><code>ACCESS_NETWORK_STATE</code></td>
<td>To check network connectivity before fetching IOC feed updates.</td>
</tr>
<tr>
<td><code>READ_LOGS</code></td>
<td>To capture AndroDR's own process log for inclusion in user-initiated security reports. This permission reads only the app's own log output (<code>logcat --pid</code>), not system-wide logs. It is used exclusively when you manually export a report.</td>
</tr>
<tr>
<td><code>MANAGE_EXTERNAL_STORAGE</code></td>
<td>To scan external storage for known spyware file artifacts. On Android 11+, scoped storage prevents apps from checking arbitrary file paths without this permission. AndroDR checks a small set of known artifact paths documented in forensic research — it does not browse or index your files.</td>
</tr>
</tbody>
</table>
<hr />
<h2>Network Requests AndroDR Makes</h2>
<p>AndroDR fetches publicly available threat intelligence feeds to keep its detection databases current. These requests contain <strong>no user data, no device identifiers, and no information about your installed apps</strong>.</p>
<table>
<thead>
<tr>
<th>Feed</th>
<th>Source</th>
<th>What's fetched</th>
<th>Requests per update</th>
</tr>
</thead>
<tbody>
<tr>
<td>Stalkerware indicators</td>
<td>AssoEchap/stalkerware-indicators (GitHub)</td>
<td>Known stalkerware package names</td>
<td>1 HTTP GET</td>
</tr>
<tr>
<td>Mercenary spyware domain IOCs</td>
<td>mvt-project/mvt-indicators (GitHub)</td>
<td>Known spyware C2 domains from multiple campaigns (Pegasus, Predator, RCS Lab, etc.)</td>
<td>1 index fetch + 1 per campaign (~10-20 requests)</td>
</tr>
<tr>
<td>Known app database (UAD)</td>
<td>Universal Android Debloater (GitHub)</td>
<td>Legitimate app lists for false positive reduction</td>
<td>1 HTTP GET</td>
</tr>
<tr>
<td>Known app database (Plexus)</td>
<td>Plexus (techlore.tech)</td>
<td>App compatibility data</td>
<td>~19 paginated requests</td>
</tr>
<tr>
<td>MalwareBazaar APK + cert hashes</td>
<td>abuse.ch MalwareBazaar public API</td>
<td>Hashes of known malicious APKs and the cert hashes that signed them</td>
<td>1 API request per refresh</td>
</tr>
<tr>
<td>ThreatFox indicators</td>
<td>abuse.ch ThreatFox public API</td>
<td>Command-and-control domain / IP indicators</td>
<td>1 API request per refresh</td>
</tr>
<tr>
<td>Stalkerware cert-hash indicators</td>
<td>AssoEchap/stalkerware-indicators (GitHub)</td>
<td>Cert hashes of known stalkerware signers</td>
<td>1 HTTP GET</td>
</tr>
</tbody>
</table>
<p>All requests are unauthenticated public HTTP GET requests. No API keys, no authentication tokens, no cookies, and no tracking headers are sent. You can verify this in the source code at <code>app/src/main/java/com/androdr/ioc/feeds/</code>.</p>
<p>All ingesters run inside a dispatcher that deduplicates indicators across feeds before writing to the on-device database. Each feed is independently auditable in <code>app/src/main/java/com/androdr/ioc/feeds/</code>.</p>
<hr />
<h2>DNS Monitoring</h2>
<p>AndroDR's DNS monitor uses a local VPN to intercept DNS queries <strong>on your device only</strong>. This is how it detects connections to known malicious domains.</p>
<ul>
<li>DNS queries are resolved locally — <strong>no traffic is routed to external servers</strong></li>
<li>DNS event logs are stored on-device only</li>
<li>The VPN does not route, inspect, or modify your web traffic, app data, or any non-DNS network activity</li>
<li>You can enable or disable DNS monitoring at any time</li>
</ul>
<hr />
<h2>Bug Report Analysis</h2>
<p>AndroDR can analyze Android bug report files (<code>.zip</code>) that you manually provide. This feature:</p>
<ul>
<li>Reads the bug report ZIP file you select — which may contain sensitive system logs, process lists, and device state</li>
<li>Scans for spyware indicators: C2 beacon patterns, suspicious process names, base64 exfiltration blobs, abnormal wakelocks, and crash patterns</li>
<li>Processes everything <strong>entirely on-device</strong> — no part of the bug report is transmitted anywhere</li>
<li>Does not retain the original bug report file — only the analysis findings are stored in scan results</li>
</ul>
<p>AndroDR retains only the analysis findings — flagged app names, indicator matches, detected patterns — in the scan result. The original bug report ZIP is not stored on-device after analysis completes.</p>
<p>Bug report files are among the most sensitive files on an Android device. AndroDR reads them only when you explicitly choose to analyze one.</p>
<hr />
<h2>What Exported Reports Contain</h2>
<p>When you export a security report, it includes:</p>
<ul>
<li><strong>Device information:</strong> manufacturer, model, Android version, API level, security patch date</li>
<li><strong>Scan results:</strong> flagged apps with package names, risk levels, and reasons</li>
<li><strong>DNS event log:</strong> recent DNS queries with domain names, timestamps, and blocked/allowed status</li>
<li><strong>Application log:</strong> up to 300 lines of AndroDR's own process log (not system-wide logs)</li>
</ul>
<p>Reports are generated only when you tap the export button. You choose who to share them with via the Android share sheet. <strong>We never see your reports.</strong></p>
<hr />
<h2>What We Do NOT Collect</h2>
<ul>
<li>No personal information (name, email, phone number)</li>
<li>No device identifiers (IMEI, serial number, advertising ID)</li>
<li>No location data</li>
<li>No browsing history</li>
<li>No message content</li>
<li>No photos or files</li>
<li>No usage analytics or telemetry</li>
<li>No automatic crash reporting or analytics SDKs</li>
<li>No data shared with third parties</li>
<li>No advertising SDKs</li>
<li>No cloud backup of app data</li>
</ul>
<hr />
<h2>Data Sharing</h2>
<p>AndroDR shares data <strong>only when you explicitly choose to</strong>:</p>
<ul>
<li><strong>Report export:</strong> You generate a security report and share it via the Android share sheet. You choose the recipient. We never see it. Review the "What Exported Reports Contain" section above to understand what is included.</li>
<li><strong>No automatic sharing:</strong> Nothing is sent anywhere without your explicit action.</li>
</ul>
<hr />
<h2>Data Retention and Deletion</h2>
<ul>
<li>Scan history and DNS events are stored on-device indefinitely until you clear them</li>
<li>Cloud backup is disabled — your data is not backed up to Google's servers</li>
<li>Uninstalling AndroDR deletes all stored data from the device</li>
<li>You can clear all app data at any time via Android Settings &gt; Apps &gt; AndroDR &gt; Clear Data</li>
</ul>
<hr />
<h2>Open Source Transparency</h2>
<p>AndroDR's source code is publicly available. Every detection heuristic, every network request, every data storage operation is visible in the code. This is intentional — security tools that operate as black boxes ask for trust they haven't earned.</p>
<ul>
<li><strong>Repository:</strong> github.com/yasirhamza/AndroDR</li>
<li><strong>Detection logic:</strong> <code>app/src/main/java/com/androdr/scanner/</code></li>
<li><strong>Network requests:</strong> <code>app/src/main/java/com/androdr/ioc/feeds/</code></li>
<li><strong>Data storage:</strong> <code>app/src/main/java/com/androdr/data/</code></li>
</ul>
<p>If you find a privacy concern in the code, open an issue or contact us directly.</p>
<hr />
<h2>Google Play Data Safety Alignment</h2>
<p>For Google Play's Data Safety section, AndroDR declares:</p>
<ul>
<li><strong>Data collected:</strong> Installed app list (package names, permissions, signing certs — on-device only, never transmitted); device info (model, OS version, security patch level — included in user-initiated reports only); DNS query domain names (only when the optional DNS VPN is enabled — on-device only, auto-deleted after 30 days); diagnostic info (app-own logcat — included in user-initiated reports only)</li>
<li><strong>Data shared:</strong> None — user-initiated report sharing is under user control and not considered "sharing with third parties"</li>
<li><strong>Data encrypted in transit:</strong> N/A — no user data is transmitted; all outbound requests are inbound-only IOC feed downloads over HTTPS</li>
<li><strong>Data encrypted at rest:</strong> Yes — Room database is stored on Android's encrypted file system; cached reports reside in the app's private storage directory</li>
<li><strong>Data deletion:</strong> Users can clear all stored data at any time via Android Settings &gt; Apps &gt; AndroDR &gt; Clear Data, or by uninstalling the app; DNS events are also automatically deleted after 30 days</li>
<li><strong>Optional data collection:</strong> DNS query monitoring is entirely optional — the local VPN must be explicitly enabled by the user</li>
</ul>
<hr />
<h2>Children's Privacy</h2>
<p>AndroDR does not knowingly collect any data from children under 13. The app does not collect data from anyone — it operates entirely on-device.</p>
<hr />
<h2>International Users (GDPR / CCPA)</h2>
<p>AndroDR processes no personal data on any server. All processing occurs on your device. As a result:</p>
<ul>
<li><strong>EU users (GDPR):</strong> No personal data is collected or processed by the developer. Your rights under GDPR (access, rectification, erasure, portability) are fulfilled by the fact that all data resides on your device under your control. Uninstalling the app erases all data. The data controller for on-device data is you.</li>
<li><strong>California users (CCPA):</strong> AndroDR does not sell, share, or disclose personal information to any third party. There is no personal information to sell because none is collected.</li>
</ul>
<hr />
<h2>Governing Law</h2>
<p>This privacy policy is governed by the laws of the jurisdiction in which the developer resides. Disputes related to this policy shall be resolved in the courts of that jurisdiction.</p>
<hr />
<h2>Changes to This Policy</h2>
<p>If this policy changes, the updated version will be published in the repository and the "last updated" date will be revised. Since AndroDR collects no data, meaningful policy changes are unlikely.</p>
<hr />
<h2>Contact</h2>
<p>For privacy questions or concerns:
- Email: yhamad.dev@gmail.com
- GitHub: github.com/yasirhamza/AndroDR/issues</p>
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

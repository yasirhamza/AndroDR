# Import fixtures (manual)

`run.sh` drives live scans of installed APKs and cannot import a file, so rules that fire only on
an imported bug report or intrusion log are checked by hand in the release battery: push the zip to
the device's Downloads, open Dashboard → Analyze a File, pick it, and compare with the expected
result below. Every file here is synthetic; none holds real device data.

| Fixture | Rule | Must show | Must not show |
|---|---|---|---|
| `androdr_110_uninstalled_ioc_bugreport.zip` | androdr-110 | exactly 1 finding, "Known malicious app was uninstalled (possible anti-forensics)", HIGH, for `calldetaila.ndcallhisto.rytogetan.ynumber` (bundled CallPhantom IOC); 1 open HIGH alert on the Dashboard; Overall Risk HIGH | a finding for the clean uninstall `com.example.notes` or the install `com.example.camera` |

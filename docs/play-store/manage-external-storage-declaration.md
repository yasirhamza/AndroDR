# MANAGE_EXTERNAL_STORAGE Permission Declaration

## For Google Play Console: Sensitive Permission Declaration

### Why does your app need MANAGE_EXTERNAL_STORAGE?

AndroDR is a security scanner that checks for known spyware file artifacts on external storage. Spyware such as Pegasus, Predator, and commercial stalkerware place hidden files at specific paths on external storage (e.g., `/sdcard/.hidden_config`, `/sdcard/Android/data/.system_update`) as part of their persistence mechanism.

### What does your app do with this permission?

AndroDR uses `MANAGE_EXTERNAL_STORAGE` exclusively to check whether specific known-malicious file paths exist on external storage. It:

- Checks a fixed list of 5 known spyware artifact paths
- Only calls `File.exists()` and `File.lastModified()` on these paths
- Does NOT read file contents
- Does NOT list directory contents
- Does NOT access photos, videos, or user documents
- Does NOT write to external storage

### Why can't you use scoped storage instead?

Scoped storage (MediaStore, SAF) only provides access to media files and user-selected documents. Spyware artifacts are hidden files placed outside of standard media directories. Detecting their presence requires checking arbitrary file paths, which is only possible with `MANAGE_EXTERNAL_STORAGE`.

### Category

**Security / antivirus / device protection** — AndroDR scans for indicators of compromise (IOCs) including file system artifacts left by known spyware families.

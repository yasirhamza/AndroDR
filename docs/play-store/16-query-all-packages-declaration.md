# QUERY_ALL_PACKAGES Declaration

## Permission requested
`android.permission.QUERY_ALL_PACKAGES`

## Core functionality that requires this permission
AndroDR is a security and endpoint detection app (EDR) that scans all installed applications on the device to detect malware, stalkerware, and spyware. The app compares every installed package against threat intelligence databases containing known malicious package names, certificate hashes, and APK file hashes.

## Why QUERY_ALL_PACKAGES is necessary
Without this permission, Android's package visibility filtering (introduced in Android 11) restricts which apps AndroDR can see. A malicious app that is not declared in a `<queries>` manifest element would be invisible to the scanner, defeating the purpose of a security scan. Spyware and stalkerware specifically avoid declaring themselves in ways that would make them discoverable through filtered queries.

AndroDR must enumerate ALL installed packages to:
1. Compare package names against known malware IOC databases
2. Extract and verify APK signing certificates against threat intelligence feeds
3. Compute SHA-256 file hashes for VirusTotal-compatible malware identification
4. Detect sideloaded apps not installed from trusted app stores
5. Identify apps with surveillance permission clusters (camera, microphone, location, SMS, contacts)
6. Detect accessibility service abuse and device administrator abuse

## App category
Antivirus / Security / Device Protection

## Similar apps using this permission
- Lookout Mobile Security
- Malwarebytes Mobile Security
- Bitdefender Mobile Security
- Norton Mobile Security
- MVT (Mobile Verification Toolkit)

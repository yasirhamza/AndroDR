# OEM Allowlist Audit Report

UAD packages analyzed: 7
- AOSP/Google (skipped, covered unconditionally): 2
- Vendor-mapped: 4
- Unmapped: 1

## Conditional block: huawei
manufacturer_match: huawei, honor
brand_match: huawei, honor

Currently allowlisted (1 prefix):
  - com.huawei.

Proposed additions (1):
  - com.hihonor.   # UAD: com.hihonor.appmarket, com.hihonor.calendar (2 packages)

## Conditional block: samsung
manufacturer_match: samsung
brand_match: samsung

Currently allowlisted (1 prefix):
  - com.samsung.

Proposed additions: none

## Unmapped UAD prefixes (1)

Packages whose second-segment word is not recognized as belonging to any conditional block. Consider adding a new conditional block or extending the script's VENDOR_WORD_TO_BLOCK table.

  - com.nothing.   # UAD: com.nothing.launcher (1 package)

## Unconditional matches (skipped from per-vendor analysis)

  - com.google.   # UAD: com.google.android.gms (1 package, covered by aosp_prefixes)
  - com.qualcomm.   # UAD: com.qualcomm.atfwd (1 package, covered by chipset_prefixes)

# Exynos4 microG installer for LineageOS 23.2

Optional TWRP add-on for HTML6405's Vanilla LineageOS 23.2 (Android 16, ARM32).
It installs upstream microG Services 0.3.18.252432 and Companion as privileged
apps. The optional legacy GSF Proxy is omitted. Companion is the microG store
placeholder. Runtime grants and Google registration remain user choices.

## Compatibility and installation

- Tested on GT-N8010 with TWRP 3.7.0_9-0 and the published LineageOS 23.2 build
  1795348601. The writer also recognizes GT-N8000, but this installer has not
  been tested there. GT-N8013 is covered only if Recovery reports GT-N8010
  and all layout/ROM checks pass. No physical N8013 test was performed.
- Install only alongside a matching Vanilla ROM with 2 GiB SYSTEM and an
  accessible, supported /data layout. Back up your device. The installer
  refuses existing microG/GApps packages or leftover package data. For fresh
  ROM installation, flash Vanilla and then the add-on in TWRP before booting.
  You can also install it over a compatible existing Vanilla setup that passes
  the same clean-state checks. Keep the recovery log if installation refuses.
- Download the r4 ZIP and its SHA-256 sidecar from Releases. Verify the digest
  before handing this unsigned Recovery ZIP to TWRP. The APKs inside retain
  upstream signatures. Once Android starts, open microG Settings and run
  Self-Check. An absent GSF Proxy is expected.
- The transaction keeps its rollback journal and recovery helper under
  `/data/local/tmp/exynos4-google-services-recovery/`. Preserve this directory
  and the Recovery log after an error. If Recovery reports incomplete rollback,
  stay in Recovery and recover using the verified backup or the logged helper
  for that exact transaction.

## What passed

The published ZIP matches the tested installer byte for byte. GT-N8010 passed
clean TWRP installation, an Enforcing boot, spoofing and package-signature
checks, 14 privileged permission grants, and local AVC/AAC playback. During two
consecutive TWRP installations of the same published Vanilla ROM, all add-on
file hashes, package IDs and compared permission grants survived. Recovery was
unchanged, and microG Settings opened after the second boot.

Updates to a different ROM version, app-private data contents, Google sign-in,
push delivery and Play Integrity are outside this test evidence. LineageOS 21
requires a separate installer and validation.

## Source and inputs

This repository archives the exact reviewed r4 writer template and packaging
scripts, the host fixture results, and the package manifests. The original
scripts retain their checkout-relative paths and Android SDK requirements.
The release ZIP itself includes the generated writer and exact file table.
The standalone SHA-256 file is the tested binary reference.

- [microG release and corresponding source](https://github.com/microg/GmsCore/releases/tag/v0.3.18.252432).
  Exact APK versions, original URLs, signing certificate digest and payload
  hashes are recorded in `payload-manifest.json`.
- [Pinned MindTheGapps release](https://github.com/MindTheGapps/16.0.0-arm/releases/tag/MindTheGapps-16.0.0-arm-20261023_034858)
  supplies the unmodified static ARM toybox used by the Recovery writer.
  No Google APKs from that archive are included.
  [Toybox source](https://github.com/landley/toybox).
- Upstream license texts are in `upstream/`. In-archive TEST and UNVERIFIED
  annotations predate device testing and remain part of the exact verified r4
  bytes. This README records the later results.

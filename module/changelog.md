## Niseko — Downstream Improvements Port

Niseko is a fork of [JingMatrix/TEESimulator](https://github.com/JingMatrix/TEESimulator) with downstream improvements ported from [Enginex0/TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS).

### Ported Improvements

- **Full-type key persistence** (symmetric + asymmetric with byte-identical metadata)
- **Grant plane virtualization** (caller-binding + access-vector gating, SDK≥36)
- **Anti-detection** (Duck Detector: auth ordering, SecurityLevel.KEYSTORE, SSE normalization)
- **Device capability mirroring** (canAttestDeviceIds — forge health, mirror capability)
- **TEE latency simulation** (log-normal model + StrongBox floors)
- **AOSP-compliant authorize_create** enforcement
- **Google Wallet compatibility** (INCLUDE_UNIQUE_ID stripping)
- **Key lifecycle sync** (clearNamespace, migrateKeyNamespace via maintenance binder)
- **Action button** with Vol+ confirmation and 22-language i18n
- **Debug diagnostic purge** on boot for release builds

### Excluded (by design)

- System property spoofing (BootStateManager, vbmeta props)
- PIF integration (PatchLevelManager, BulletinPoller)
- Rust native certificate generation (NativeCertGen)

### Credits

- [JingMatrix](https://github.com/JingMatrix) — original TEESimulator
- [Enginex0](https://github.com/Enginex0) — downstream improvements
- [Andrea-lyz](https://github.com/Andrea-lyz) — key persistence, Duck Detector fixes

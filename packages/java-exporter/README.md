# Pure Java 21+ `SVA-ER/1` & `OPEG/1` Exporter (`SvaEr1Exporter.java`)

Zero-dependency single-file exporter for Java agent engines (including [`fraynix-agency-platform`](https://github.com/eyeoverthink/fraynix-agency-platform) `workspace-engine` — `WorldVerify`, `WorkflowEvidence`, `Witness042`) to emit standard `SVA-ER/1` receipts and `OPEG/1` `S4_COMMIT` envelopes verifiable offline by `@eyeoverthink/ai-receipt`, Node V8, W3C Browser WebCrypto, Single-File Java 25, and `receipt-lab.html`.

## Quick Verification (< 2 seconds, 0 dependencies)

```bash
java packages/java-exporter/SvaEr1Exporter.java
```

## Drop-In Integration (`fraynix-agency-platform` `workspace-engine`)

Copy `SvaEr1Exporter.java` into `workspace-engine/src/main/java/fraymus/workspace/` (add `package fraymus.workspace;` at line 1) and call it after `WorldVerify` / `WorkflowEvidence` completes an independent outcome check:

```java
var bundle = SvaEr1Exporter.export(
    "Fraynix Agency Platform",
    taskId,
    verifiedOutcomeMap,
    List.of(new SvaEr1Exporter.Event("workspace.verify", "WorldVerify", checkMeta, Instant.now())),
    agencyPrivateKey,
    agencyPublicKeyHex,
    "unattested", // or "attested" when clock-synced
    Instant.now()
);
String receiptJson = SvaEr1Exporter.canonical(bundle.receipt());
String opegJson = SvaEr1Exporter.canonical(bundle.opegEnvelope());
```

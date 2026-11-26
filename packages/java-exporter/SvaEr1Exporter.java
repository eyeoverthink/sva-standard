// Zero-dependency Pure Java (JDK 21+) SVA-ER/1 Receipt & OPEG/1 Envelope Exporter.
// Drop-in single-file exporter for Java agent engines (e.g. eyeoverthink/fraynix-agency-platform
// workspace-engine WorldVerify / WorkflowEvidence) to emit standard SVA-ER/1 receipts and OPEG/1
// S4_COMMIT envelopes verifiable offline by @eyeoverthink/ai-receipt, receipt-lab.html, and sva-standard.
//
// Run standalone demo (emits signed SVA-ER/1 receipt + deliverable + OPEG/1 envelope as JSON):
//   java packages/java-exporter/SvaEr1Exporter.java

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

public final class SvaEr1Exporter {
  // RFC 8410 ASN.1 PKCS#8 prefix for a raw 32-byte Ed25519 private seed
  private static final byte[] ED25519_PKCS8_PREFIX = hexToBytes("302e020100300506032b657004220420");
  private static final DateTimeFormatter RFC3339_UTC =
      DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

  public record Event(String kind, String actor, Map<String, Object> data, Instant timestamp) {}
  public record ExportBundle(Map<String, Object> receipt, String deliverableJcs, Map<String, Object> opegEnvelope) {}

  public static KeyPair generateKeyPair() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  public static PrivateKey privateKeyFromSeedHex(String seedHex) throws Exception {
    byte[] seed = hexToBytes(seedHex);
    if (seed.length != 32) throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
    byte[] der = new byte[ED25519_PKCS8_PREFIX.length + 32];
    System.arraycopy(ED25519_PKCS8_PREFIX, 0, der, 0, ED25519_PKCS8_PREFIX.length);
    System.arraycopy(seed, 0, der, ED25519_PKCS8_PREFIX.length, 32);
    return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
  }

  public static String rawPublicKeyHex(KeyPair kp) {
    byte[] spki = kp.getPublic().getEncoded();
    byte[] raw = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
    return bytesToHex(raw);
  }

  public static ExportBundle export(
      String agencyName,
      String missionId,
      Map<String, Object> deliverableObj,
      List<Event> events,
      PrivateKey privateKey,
      String publicKeyHex,
      String clockStatus,
      Instant issuedAt) throws Exception {
    if (!List.of("attested", "drift", "unattested").contains(clockStatus)) {
      throw new IllegalArgumentException("clockStatus must be attested, drift, or unattested");
    }
    String delivJcs = canonical(deliverableObj);
    String delivSha = sha256Hex(delivJcs.getBytes(StandardCharsets.UTF_8));
    String issuedIso = RFC3339_UTC.format(issuedAt);

    List<Map<String, Object>> rows = new ArrayList<>();
    String prev = "0".repeat(64);
    int seq = 1;
    for (Event ev : events) {
      Map<String, Object> data = new LinkedHashMap<>(ev.data());
      data.putIfAbsent("missionId", missionId);
      Map<String, Object> core = new LinkedHashMap<>();
      core.put("seq", seq);
      core.put("ts", RFC3339_UTC.format(ev.timestamp()));
      core.put("kind", ev.kind());
      core.put("actor", ev.actor());
      core.put("data", data);
      core.put("prev", prev);
      String ehash = sha256Hex(canonical(core).getBytes(StandardCharsets.UTF_8));
      String sig = ed25519Sign(privateKey, ehash);
      Map<String, Object> row = new LinkedHashMap<>(core);
      row.put("hash", ehash);
      row.put("sig", sig);
      row.put("signer", publicKeyHex);
      rows.add(row);
      prev = ehash;
      seq++;
    }

    // Terminal mission.complete entry binding deliverableSha256
    Map<String, Object> compData = new LinkedHashMap<>();
    compData.put("id", missionId);
    compData.put("resultHash", delivSha);
    Map<String, Object> compCore = new LinkedHashMap<>();
    compCore.put("seq", seq);
    compCore.put("ts", issuedIso);
    compCore.put("kind", "mission.complete");
    compCore.put("actor", agencyName);
    compCore.put("data", compData);
    compCore.put("prev", prev);
    String compHash = sha256Hex(canonical(compCore).getBytes(StandardCharsets.UTF_8));
    String compSig = ed25519Sign(privateKey, compHash);
    Map<String, Object> compRow = new LinkedHashMap<>(compCore);
    compRow.put("hash", compHash);
    compRow.put("sig", compSig);
    compRow.put("signer", publicKeyHex);
    rows.add(compRow);

    // Build RFC 6962 (0x00 leaf / 0x01 node, odd-node promotion) Merkle tree
    List<List<String>> levels = new ArrayList<>();
    List<String> leafLevel = new ArrayList<>();
    for (Map<String, Object> r : rows) leafLevel.add(merkleLeaf((String) r.get("hash")));
    levels.add(leafLevel);
    while (levels.get(levels.size() - 1).size() > 1) {
      List<String> cur = levels.get(levels.size() - 1);
      List<String> nxt = new ArrayList<>();
      for (int i = 0; i < cur.size(); i += 2) {
        nxt.add(i + 1 < cur.size() ? merkleNode(cur.get(i), cur.get(i + 1)) : cur.get(i));
      }
      levels.add(nxt);
    }
    String root = levels.get(levels.size() - 1).get(0);

    List<Map<String, Object>> entriesWithProof = new ArrayList<>();
    for (int i = 0; i < rows.size(); i++) {
      Map<String, Object> r = new LinkedHashMap<>(rows.get(i));
      r.put("proof", proofFor(levels, i));
      entriesWithProof.add(r);
    }

    Map<String, Object> clock = new LinkedHashMap<>();
    clock.put("status", clockStatus);
    clock.put("issuedAt", issuedIso);
    clock.put("maxSkewSec", 300);

    Map<String, Object> statement = new LinkedHashMap<>();
    statement.put("type", "sva-er.statement");
    statement.put("missionId", missionId);
    statement.put("deliverableSha256", delivSha);
    statement.put("merkleRoot", root);
    statement.put("merkle", "rfc6962-sha256");
    statement.put("size", entriesWithProof.size());
    statement.put("entries", entriesWithProof.size());
    statement.put("clock", clock);

    String stmtSig = ed25519Sign(privateKey, canonical(statement));

    Map<String, Object> agency = new LinkedHashMap<>();
    agency.put("name", agencyName);
    agency.put("publicKey", publicKeyHex);

    Map<String, Object> receipt = new LinkedHashMap<>();
    receipt.put("spec", "sva-er/1");
    receipt.put("agency", agency);
    receipt.put("statement", statement);
    receipt.put("statementSig", stmtSig);
    receipt.put("entries", entriesWithProof);

    Map<String, Object> sanitizer = new LinkedHashMap<>();
    sanitizer.put("status", "SUCCESS");
    sanitizer.put("rSan", deliverableObj);
    sanitizer.put("rSanSha256", delivSha);

    Map<String, Object> opeg = new LinkedHashMap<>();
    opeg.put("spec", "opeg/1");
    opeg.put("state", "S4_COMMIT");
    opeg.put("mode", "EXECUTE_AND_RECEIVE");
    opeg.put("receiptFormat", "sva-er/1");
    opeg.put("sourcePriority", List.of("runtime_receipt", "sanitized_output", "model_narrative"));
    opeg.put("sanitizer", sanitizer);
    opeg.put("receipt", receipt);

    return new ExportBundle(receipt, delivJcs, opeg);
  }

  private static List<Map<String, Object>> proofFor(List<List<String>> levels, int index) {
    List<Map<String, Object>> steps = new ArrayList<>();
    int idx = index;
    for (int lvl = 0; lvl < levels.size() - 1; lvl++) {
      List<String> row = levels.get(lvl);
      if (idx % 2 == 0 && idx + 1 == row.size()) {
        idx /= 2;
        continue;
      }
      Map<String, Object> step = new LinkedHashMap<>();
      step.put("hash", (idx % 2 == 0) ? row.get(idx + 1) : row.get(idx - 1));
      step.put("left", (idx % 2 == 1));
      steps.add(step);
      idx /= 2;
    }
    return steps;
  }

  private static String ed25519Sign(PrivateKey key, String msg) throws Exception {
    Signature sig = Signature.getInstance("Ed25519");
    sig.initSign(key);
    sig.update(msg.getBytes(StandardCharsets.UTF_8));
    return bytesToHex(sig.sign());
  }

  private static String merkleLeaf(String hashHex) throws Exception {
    byte[] h = hashHex.getBytes(StandardCharsets.UTF_8);
    byte[] buf = new byte[1 + h.length];
    buf[0] = 0x00;
    System.arraycopy(h, 0, buf, 1, h.length);
    return sha256Hex(buf);
  }

  private static String merkleNode(String leftHex, String rightHex) throws Exception {
    byte[] l = leftHex.getBytes(StandardCharsets.UTF_8);
    byte[] r = rightHex.getBytes(StandardCharsets.UTF_8);
    byte[] buf = new byte[1 + l.length + r.length];
    buf[0] = 0x01;
    System.arraycopy(l, 0, buf, 1, l.length);
    System.arraycopy(r, 0, buf, 1 + l.length, r.length);
    return sha256Hex(buf);
  }

  public static String sha256Hex(byte[] data) throws Exception {
    return bytesToHex(MessageDigest.getInstance("SHA-256").digest(data));
  }

  // RFC 8785 JCS canonical JSON serializer (matches SvaConformance.java)
  public static String canonical(Object val) {
    if (val == null) return "null";
    if (val instanceof Boolean b) return b ? "true" : "false";
    if (val instanceof Integer i) return Integer.toString(i);
    if (val instanceof Long l) return formatEsNumber((double) l);
    if (val instanceof Double d) return formatEsNumber(d);
    if (val instanceof String s) return quoteJson(s);
    if (val instanceof List<?> list) {
      StringBuilder sb = new StringBuilder("[");
      for (int i = 0; i < list.size(); i++) {
        if (i > 0) sb.append(',');
        sb.append(canonical(list.get(i)));
      }
      return sb.append(']').toString();
    }
    if (val instanceof Map<?, ?> map) {
      List<String> keys = new ArrayList<>();
      for (Map.Entry<?, ?> e : map.entrySet()) {
        if (e.getValue() != null) keys.add(String.valueOf(e.getKey()));
      }
      keys.sort(Comparator.naturalOrder());
      StringBuilder sb = new StringBuilder("{");
      for (int i = 0; i < keys.size(); i++) {
        if (i > 0) sb.append(',');
        String k = keys.get(i);
        sb.append(quoteJson(k)).append(':').append(canonical(map.get(k)));
      }
      return sb.append('}').toString();
    }
    throw new IllegalArgumentException("Unsupported JSON type: " + val.getClass());
  }

  private static String formatEsNumber(double d) {
    if (!Double.isFinite(d)) return "null";
    if (d == 0.0) return "0";
    String sign = d < 0 ? "-" : "";
    BigDecimal bd = new BigDecimal(Double.toString(Math.abs(d))).stripTrailingZeros();
    String digits = bd.unscaledValue().toString();
    int k = digits.length();
    int n = k - bd.scale();
    if (k <= n && n <= 21) return sign + digits + "0".repeat(n - k);
    if (0 < n && n <= 21) return sign + digits.substring(0, n) + "." + digits.substring(n);
    if (-6 < n && n <= 0) return sign + "0." + "0".repeat(-n) + digits;
    int exp = n - 1;
    String expStr = "e" + (exp >= 0 ? "+" : "-") + Math.abs(exp);
    return (k == 1) ? (sign + digits + expStr) : (sign + digits.charAt(0) + "." + digits.substring(1) + expStr);
  }

  private static String quoteJson(String s) {
    StringBuilder sb = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\b' -> sb.append("\\b");
        case '\f' -> sb.append("\\f");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
          else sb.append(c);
        }
      }
    }
    return sb.append('"').toString();
  }

  private static byte[] hexToBytes(String hex) {
    byte[] out = new byte[hex.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static String bytesToHex(byte[] bytes) {
    char[] digits = "0123456789abcdef".toCharArray();
    char[] hex = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xff;
      hex[i * 2] = digits[v >>> 4];
      hex[i * 2 + 1] = digits[v & 0x0f];
    }
    return new String(hex);
  }

  public static void main(String[] args) throws Exception {
    KeyPair kp = generateKeyPair();
    String pubHex = rawPublicKeyHex(kp);
    Instant now = Instant.parse("2026-11-26T20:00:00.000Z");

    Map<String, Object> deliverable = new LinkedHashMap<>();
    deliverable.put("engine", "fraynix-workspace-engine");
    deliverable.put("checkKind", "physics_end_state");
    deliverable.put("verified", true);
    deliverable.put("bodyCount", 4);
    deliverable.put("finalEnergyJ", 12.5);

    List<Event> events = List.of(
        new Event("workspace.tool_call", "world-verify", Map.of("tool", "WorldPhysics.step", "ticks", 120), now.minusSeconds(2)),
        new Event("workspace.artifact_check", "witness-042", Map.of("outcome", "match", "tolerance", 0.001), now.minusSeconds(1))
    );

    ExportBundle bundle = export(
        "Fraynix Agency Platform",
        "fraynix-world-001",
        deliverable,
        events,
        kp.getPrivate(),
        pubHex,
        "unattested",
        now
    );

    Map<String, Object> out = new LinkedHashMap<>();
    out.put("receipt", bundle.receipt());
    out.put("deliverable", bundle.deliverableJcs());
    out.put("opegEnvelope", bundle.opegEnvelope());
    System.out.println(canonical(out));
  }
}

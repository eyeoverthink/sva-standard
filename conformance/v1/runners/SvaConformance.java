// Reference Verifier #3: Single-File Pure Java (JDK 17+, ZERO external dependencies).
// Runs directly with: java conformance/v1/runners/SvaConformance.java [conformance/v1/vectors.json]
// Verifies JCS (RFC 8785), RFC 6962 Merkle (0x00/0x01 + odd promotion), AER/1, VSC/1, vsc-revoke/1, and EMA/1.

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SvaConformance {
  private static final String EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  // ASN.1 SubjectPublicKeyInfo DER prefix for raw 32-byte Ed25519 public key (RFC 8410)
  private static final byte[] ED25519_SPKI_PREFIX = hexToBytes("302a300506032b6570032100");
  private static final Pattern HEX64 = Pattern.compile("^[0-9a-fA-F]{64}$");
  private static final Pattern HEX128 = Pattern.compile("^[0-9a-fA-F]{128}$");
  private static final Pattern HEX16 = Pattern.compile("^[0-9a-f]{16}$");
  private static final Pattern SKILL_NAME = Pattern.compile("^[a-z][a-z0-9_-]{1,63}$");
  private static final Pattern STRICT_B64 = Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
  private static final Pattern SQUEEZE_DIGITS = Pattern.compile("(?<=\\d)[\\s.\\-()]+(?=\\d)");

  public static void main(String[] args) throws Exception {
    long t0 = System.nanoTime();
    Path vecPath = args.length > 0 ? Path.of(args[0]) : Path.of("conformance", "v1", "vectors.json");
    String raw = Files.readString(vecPath, StandardCharsets.UTF_8);
    Map<String, Object> doc = asObj(JsonParser.parse(raw));
    List<Object> vectors = asList(doc.get("vectors"));

    List<Map<String, Object>> failures = new ArrayList<>();
    for (Object item : vectors) {
      Map<String, Object> v = asObj(item);
      String id = asStr(v.get("id"));
      String suite = asStr(v.get("suite"));
      boolean expectOk = Boolean.TRUE.equals(v.get("expectOk"));
      boolean got = verifyVector(suite, asObj(v.get("input")));
      if (got != expectOk) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("id", id);
        f.put("suite", suite);
        f.put("expected", expectOk);
        f.put("got", got);
        f.put("description", asStr(v.get("description")));
        failures.add(f);
      }
    }

    double ms = Math.round(((System.nanoTime() - t0) / 1e6) * 100.0) / 100.0;
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("runtime", "java:" + System.getProperty("java.version") + " (single-file pure JDK, zero deps)");
    result.put("total", vectors.size());
    result.put("passed", vectors.size() - failures.size());
    result.put("failed", failures.size());
    result.put("durationMs", ms);
    result.put("failures", failures);
    System.out.println(toPrettyJson(result));
    System.exit(failures.isEmpty() ? 0 : 1);
  }

  private static boolean verifyVector(String suite, Map<String, Object> input) {
    try {
      return switch (suite) {
        case "jcs" -> {
          String rawJson = asStr(input.get("rawJson"));
          Object val = rawJson != null ? JsonParser.parse(rawJson) : input.get("value");
          yield canonical(val).equals(asStr(input.get("expected")));
        }
        case "merkle" -> verifyMerkle(input);
        case "aer1" -> verifyAer1(input);
        case "vsc1" -> verifyVsc1(input);
        case "ema1" -> verifyEma1(input);
        case "wasm_exec" -> verifyWasmExec(input);
        default -> false;
      };
    } catch (Exception e) {
      return false;
    }
  }

  // ==================== RFC 8785 JCS Canonicalization ====================
  public static String formatEsNumber(double d) {
    if (!Double.isFinite(d)) return "null";
    if (d == 0.0) return "0"; // normalizes -0.0 to 0
    String sign = d < 0 ? "-" : "";
    BigDecimal bd = new BigDecimal(Double.toString(Math.abs(d))).stripTrailingZeros();
    String digits = bd.unscaledValue().toString();
    int k = digits.length();
    int n = k - bd.scale(); // 10^(n-1) <= |d| < 10^n
    if (k <= n && n <= 21) return sign + digits + "0".repeat(n - k);
    if (0 < n && n <= 21) return sign + digits.substring(0, n) + "." + digits.substring(n);
    if (-6 < n && n <= 0) return sign + "0." + "0".repeat(-n) + digits;
    int exp = n - 1;
    String expStr = "e" + (exp >= 0 ? "+" : "-") + Math.abs(exp);
    if (k == 1) return sign + digits + expStr;
    return sign + digits.charAt(0) + "." + digits.substring(1) + expStr;
  }

  public static String canonical(Object val) {
    if (val == null) return "null";
    if (val instanceof Boolean b) return b ? "true" : "false";
    if (val instanceof Long l) return formatEsNumber((double) l);
    if (val instanceof Integer i) return Integer.toString(i);
    if (val instanceof Double d) return formatEsNumber(d);
    if (val instanceof String s) return quoteJsonString(s);
    if (val instanceof List<?> list) {
      StringBuilder sb = new StringBuilder("[");
      for (int i = 0; i < list.size(); i++) {
        if (i > 0) sb.append(',');
        sb.append(canonical(list.get(i)));
      }
      return sb.append(']').toString();
    }
    if (val instanceof Map<?, ?> map) {
      // TreeMap sorts strings by UTF-16 code units (exact RFC 8785 JCS order)
      TreeMap<String, Object> sorted = new TreeMap<>();
      for (Map.Entry<?, ?> e : map.entrySet()) sorted.put(String.valueOf(e.getKey()), e.getValue());
      StringBuilder sb = new StringBuilder("{");
      boolean first = true;
      for (Map.Entry<String, Object> e : sorted.entrySet()) {
        if (!first) sb.append(',');
        first = false;
        sb.append(quoteJsonString(e.getKey())).append(':').append(canonical(e.getValue()));
      }
      return sb.append('}').toString();
    }
    throw new IllegalArgumentException("Unsupported JCS value: " + val.getClass());
  }

  private static String quoteJsonString(String s) {
    StringBuilder sb = new StringBuilder(s.length() + 2);
    sb.append('"');
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

  // ==================== Crypto Primitives (SHA-256, Ed25519, HMAC-SHA256) ====================
  private static String sha256(byte[] data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    return bytesToHex(md.digest(data));
  }

  private static String sha256(String text) throws Exception {
    return sha256(text.getBytes(StandardCharsets.UTF_8));
  }

  private static String merkleLeaf(String leafHex) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update((byte) 0x00);
    md.update(leafHex.getBytes(StandardCharsets.UTF_8));
    return bytesToHex(md.digest());
  }

  private static String merkleNode(String leftHex, String rightHex) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update((byte) 0x01);
    md.update(leftHex.getBytes(StandardCharsets.UTF_8));
    md.update(rightHex.getBytes(StandardCharsets.UTF_8));
    return bytesToHex(md.digest());
  }

  private static boolean ed25519Verify(String pubHex, String msg, String sigHex) {
    try {
      if (pubHex == null || sigHex == null || !HEX64.matcher(pubHex).matches() || !HEX128.matcher(sigHex).matches()) return false;
      byte[] rawPub = hexToBytes(pubHex);
      byte[] spki = new byte[ED25519_SPKI_PREFIX.length + rawPub.length];
      System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
      System.arraycopy(rawPub, 0, spki, ED25519_SPKI_PREFIX.length, rawPub.length);
      PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
      Signature sig = Signature.getInstance("Ed25519");
      sig.initVerify(key);
      sig.update(msg.getBytes(StandardCharsets.UTF_8));
      return sig.verify(hexToBytes(sigHex));
    } catch (Exception e) {
      return false;
    }
  }

  private static String hmacTag(String keyHex, String value) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(keyHex.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    byte[] out = mac.doFinal(value.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
    return bytesToHex(out).substring(0, 16);
  }

  // ==================== RFC 6962 Merkle Verifier ====================
  private static List<Boolean> expectedSteps(int seq, int size) {
    if (seq < 1 || size < 1 || seq > size) return null;
    List<Boolean> steps = new ArrayList<>();
    int idx = seq - 1, len = size;
    while (len > 1) {
      if (idx % 2 == 0 && idx + 1 == len) { idx /= 2; len = (len + 1) / 2; continue; }
      steps.add(idx % 2 == 1);
      idx /= 2;
      len = (len + 1) / 2;
    }
    return steps;
  }

  private static boolean verifyMerkle(Map<String, Object> in) throws Exception {
    String leaf = asStr(in.get("leaf"));
    String root = asStr(in.get("root"));
    Integer seq = asSafeInt(in.get("seq"));
    Integer size = asSafeInt(in.get("size"));
    List<Object> path = asList(in.get("path"));
    if (leaf == null || root == null || seq == null || size == null || path == null) return false;
    if (!HEX64.matcher(leaf).matches() || !HEX64.matcher(root).matches()) return false;
    List<Boolean> exp = expectedSteps(seq, size);
    if (exp == null || exp.size() != path.size()) return false;
    String h = merkleLeaf(leaf);
    for (int i = 0; i < path.size(); i++) {
      Map<String, Object> step = asObj(path.get(i));
      if (step == null) return false;
      String sh = asStr(step.get("hash"));
      boolean left = Boolean.TRUE.equals(step.get("left"));
      if (sh == null || !HEX64.matcher(sh).matches() || left != exp.get(i)) return false;
      h = left ? merkleNode(sh, h) : merkleNode(h, sh);
    }
    return h.equals(root);
  }

  // ==================== AER/1 Verifier ====================
  private static boolean verifyAer1(Map<String, Object> in) throws Exception {
    Map<String, Object> receipt = asObj(in.get("receipt"));
    String deliverable = asStr(in.get("deliverable"));
    if (receipt == null || !"aer/1".equals(asStr(receipt.get("spec")))) return false;
    Map<String, Object> agency = asObj(receipt.get("agency"));
    Map<String, Object> st = asObj(receipt.get("statement"));
    List<Object> entries = asList(receipt.get("entries"));
    if (agency == null || st == null || entries == null) return false;
    String pub = asStr(agency.get("publicKey"));
    String stType = asStr(st.get("type"));
    String missionId = asStr(st.get("missionId"));
    String delivHash = asStr(st.get("deliverableSha256"));
    String merkleRoot = asStr(st.get("merkleRoot"));
    Integer size = asSafeInt(st.get("size"));
    Integer count = asSafeInt(st.get("entries"));
    if (pub == null || !HEX64.matcher(pub).matches()) return false;
    if (!"aer.statement".equals(stType) || missionId == null || missionId.isEmpty()) return false;
    if (delivHash == null || !HEX64.matcher(delivHash).matches() || merkleRoot == null || !HEX64.matcher(merkleRoot).matches()) return false;
    if (size == null || size < 1 || count == null || count < 1) return false;
    if (!"rfc6962-sha256".equals(asStr(st.get("merkle")))) return false;
    Map<String, Object> clock = asObj(st.get("clock"));
    if (clock == null) return false;
    String cs = asStr(clock.get("status"));
    String issuedAt = asStr(clock.get("issuedAt"));
    if (cs == null || !Set.of("attested", "drift", "unattested").contains(cs) || issuedAt == null || issuedAt.isEmpty()) return false;
    if (!ed25519Verify(pub, canonical(st), asStr(receipt.get("statementSig")))) return false;
    if (entries.size() != count) return false;

    Set<Integer> seen = new HashSet<>();
    boolean hasComplete = false;
    for (Object item : entries) {
      Map<String, Object> e = asObj(item);
      if (e == null) return false;
      Integer seq = asSafeInt(e.get("seq"));
      if (seq == null || seq < 1 || seq > size || !seen.add(seq)) return false;
      Map<String, Object> core = new LinkedHashMap<>();
      core.put("seq", e.get("seq"));
      core.put("ts", e.get("ts"));
      core.put("kind", e.get("kind"));
      core.put("actor", e.get("actor"));
      core.put("data", e.get("data"));
      core.put("prev", e.get("prev"));
      String hash = asStr(e.get("hash"));
      if (!sha256(canonical(core)).equals(hash)) return false;
      if (!pub.equals(asStr(e.get("signer"))) || !ed25519Verify(pub, hash, asStr(e.get("sig")))) return false;

      Map<String, Object> mIn = new HashMap<>();
      mIn.put("leaf", hash); mIn.put("seq", seq); mIn.put("size", size); mIn.put("root", merkleRoot); mIn.put("path", e.get("proof"));
      if (!verifyMerkle(mIn)) return false;

      Map<String, Object> data = asObj(e.get("data"));
      if (data == null) return false;
      if (!Objects.equals(missionId, asStr(data.get("id"))) && !Objects.equals(missionId, asStr(data.get("missionId")))) return false;
      if ("mission.complete".equals(asStr(e.get("kind")))) {
        if (!Objects.equals(delivHash, asStr(data.get("resultHash")))) return false;
        hasComplete = true;
      }
    }
    if (!hasComplete) return false;
    if (deliverable != null && !sha256(deliverable).equals(delivHash)) return false;
    return true;
  }

  // ==================== VSC/1 & vsc-revoke/1 Verifier ====================
  private static boolean verifyVsc1(Map<String, Object> doc) throws Exception {
    if (doc == null) return false;
    String spec = asStr(doc.get("spec"));
    if ("vsc-revoke/1".equals(spec)) {
      String target = asStr(doc.get("targetCodeSha256"));
      String kind = asStr(doc.get("kind"));
      Map<String, Object> ce = asObj(doc.get("counterexample"));
      String signer = asStr(doc.get("signer"));
      String sig = asStr(doc.get("sig"));
      if (target == null || !HEX64.matcher(target).matches()) return false;
      if (kind == null || !Set.of("crash", "wrong_output", "nondeterministic", "invariant_violation").contains(kind)) return false;
      if (ce == null || !ce.containsKey("input") || ce.get("input") == null) return false;
      if (signer == null || sig == null || !HEX64.matcher(signer).matches() || !HEX128.matcher(sig).matches()) return false;
      Map<String, Object> unsigned = new LinkedHashMap<>(doc);
      unsigned.remove("sig");
      return ed25519Verify(signer, canonical(unsigned), sig);
    }
    if (!"vsc/1".equals(spec)) return false;
    String name = asStr(doc.get("name"));
    String runtime = asStr(doc.get("runtime"));
    String encoding = asStr(doc.get("encoding"));
    String code = asStr(doc.get("code"));
    String codeSha = asStr(doc.get("codeSha256"));
    List<Object> caps = asList(doc.get("capabilities"));
    List<Object> tests = asList(doc.get("tests"));
    String signer = asStr(doc.get("signer"));
    String sig = asStr(doc.get("sig"));
    if (name == null || !SKILL_NAME.matcher(name).matches() || Set.of("__proto__", "constructor", "prototype").contains(name)) return false;
    if (runtime == null || !Set.of("wasm-core-1", "js-pure-es2022").contains(runtime)) return false;
    String expectedEnc = "wasm-core-1".equals(runtime) ? "base64" : "utf8";
    if (!expectedEnc.equals(encoding)) return false;
    if (caps == null || !caps.isEmpty() || tests == null || tests.isEmpty()) return false;
    if (code == null || codeSha == null || !HEX64.matcher(codeSha).matches()) return false;
    byte[] codeBytes;
    if ("base64".equals(encoding)) {
      if (!STRICT_B64.matcher(code).matches()) return false;
      codeBytes = Base64.getDecoder().decode(code);
    } else {
      codeBytes = code.getBytes(StandardCharsets.UTF_8);
    }
    if (!sha256(codeBytes).equals(codeSha)) return false;
    if ("wasm-core-1".equals(runtime)) {
      byte[] magic = new byte[] { 0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00 };
      if (codeBytes.length < 8) return false;
      for (int i = 0; i < 8; i++) if (codeBytes[i] != magic[i]) return false;
    }
    if (signer == null || sig == null || !HEX64.matcher(signer).matches() || !HEX128.matcher(sig).matches()) return false;
    Map<String, Object> unsigned = new LinkedHashMap<>(doc);
    unsigned.remove("sig");
    return ed25519Verify(signer, canonical(unsigned), sig);
  }

  // ==================== EMA/1 Verifier ====================
  private static boolean verifyEma1(Map<String, Object> in) throws Exception {
    Map<String, Object> a = asObj(in.get("attestation"));
    String outbound = asStr(in.get("outboundPayload"));
    String hmacKeyHex = asStr(in.get("hmacKeyHex"));
    List<Object> originals = asList(in.get("originals"));
    if (a == null || !"ema/1".equals(asStr(a.get("spec")))) return false;
    String mode = asStr(a.get("mode"));
    if (mode == null || !Set.of("SEALED_EGRESS", "ONLY_ON_DEVICE").contains(mode)) return false;
    if (!"clean".equals(asStr(a.get("audit")))) return false;
    String outSha = asStr(a.get("outboundSha256"));
    Long egressBytes = asSafeLong(a.get("egressBytes"));
    Long totalWithheld = asSafeLong(a.get("totalWithheld"));
    Map<String, Object> withheld = asObj(a.get("withheld"));
    List<Object> tags = asList(a.get("tags"));
    if (outSha == null || !HEX64.matcher(outSha).matches() || egressBytes == null || egressBytes < 0) return false;
    if (totalWithheld == null || totalWithheld < 0 || withheld == null || tags == null) return false;
    long sum = 0;
    for (Object v : withheld.values()) {
      Long n = asSafeLong(v);
      if (n == null || n < 0) return false;
      if (Long.MAX_VALUE - sum < n) return false;
      sum += n;
    }
    if (sum != totalWithheld || tags.size() != totalWithheld) return false;
    Map<String, Long> tagCounts = new HashMap<>();
    for (Object tObj : tags) {
      Map<String, Object> t = asObj(tObj);
      String tt = t != null ? asStr(t.get("type")) : null;
      String tg = t != null ? asStr(t.get("tag")) : null;
      if (tt == null || tt.isEmpty() || tg == null || !HEX16.matcher(tg).matches()) return false;
      tagCounts.merge(tt, 1L, Long::sum);
    }
    for (Map.Entry<String, Object> entry : withheld.entrySet()) {
      Long expectedCount = asSafeLong(entry.getValue());
      if (!Objects.equals(expectedCount, tagCounts.getOrDefault(entry.getKey(), 0L))) return false;
    }
    for (String tt : tagCounts.keySet()) {
      if (!withheld.containsKey(tt)) return false;
    }
    if ("ONLY_ON_DEVICE".equals(mode)) {
      if (egressBytes != 0L || !EMPTY_SHA256.equals(outSha)) return false;
      Object rawAirgap = a.get("airgap");
      if (rawAirgap != null) {
        Map<String, Object> airgap = asObj(rawAirgap);
        if (airgap == null || !Long.valueOf(0L).equals(asSafeLong(airgap.get("networkInterfaces"))) || !Boolean.TRUE.equals(airgap.get("verified"))) return false;
      }
    }
    String signer = asStr(a.get("signer"));
    String sig = asStr(a.get("sig"));
    if (signer == null || sig == null || !HEX64.matcher(signer).matches() || !HEX128.matcher(sig).matches()) return false;
    Map<String, Object> unsigned = new LinkedHashMap<>(a);
    unsigned.remove("sig");
    if (!ed25519Verify(signer, canonical(unsigned), sig)) return false;

    if (outbound != null) {
      byte[] ob = outbound.getBytes(StandardCharsets.UTF_8);
      if (!sha256(ob).equals(outSha) || (long) ob.length != egressBytes) return false;
    }
    List<Object> origList = originals != null ? originals : List.of();
    if (!origList.isEmpty() && outbound != null) {
      String lower = outbound.toLowerCase(Locale.ROOT);
      String squeezed = SQUEEZE_DIGITS.matcher(outbound).replaceAll("");
      for (Object oObj : origList) {
        Map<String, Object> o = asObj(oObj);
        String val = o != null ? asStr(o.get("value")) : null;
        if (val == null) return false;
        if (lower.contains(val.toLowerCase(Locale.ROOT))) return false;
        String d = val.replaceAll("\\D", "");
        if (d.length() >= 7 && (squeezed.contains(d) || (d.length() > 10 && squeezed.contains(d.substring(d.length() - 10))))) return false;
      }
    }
    if (hmacKeyHex != null) {
      if (origList.size() != tags.size()) return false;
      for (int i = 0; i < origList.size(); i++) {
        Map<String, Object> o = asObj(origList.get(i));
        Map<String, Object> t = asObj(tags.get(i));
        String val = o != null ? asStr(o.get("value")) : null;
        if (val == null) return false;
        String expected = hmacTag(hmacKeyHex, val);
        if (!expected.equals(asStr(t.get("tag"))) || !Objects.equals(asStr(o.get("type")), asStr(t.get("type")))) return false;
      }
    }
    return true;
  }

  // ==================== Phase 27: Pure-Java Fuel-Metered WebAssembly Core 1.0 VM ====================
  private record WasmResult(Integer value, String trap) {}

  private static boolean verifyWasmExec(Map<String, Object> in) throws Exception {
    Map<String, Object> cap = asObj(in.get("capsule"));
    if (cap == null || !verifyVsc1(cap) || !"wasm-core-1".equals(asStr(cap.get("runtime")))) return false;
    byte[] bytes = Base64.getDecoder().decode(asStr(cap.get("code")));
    Integer fuelLimObj = asSafeInt(in.get("fuelLimit"));
    int fuelLimit = fuelLimObj != null ? fuelLimObj : 1000;

    Map<String, Object> rev = asObj(in.get("revocation"));
    if (rev != null) {
      if (!verifyVsc1(rev) || !"vsc-revoke/1".equals(asStr(rev.get("spec")))) return false;
      if (!Objects.equals(asStr(rev.get("targetCodeSha256")), asStr(cap.get("codeSha256")))) return false;
      Map<String, Object> ce = asObj(rev.get("counterexample"));
      List<Object> ceArgs = ce != null ? asList(ce.get("input")) : null;
      Integer expected = ce != null ? asSafeInt(ce.get("expected")) : null;
      Integer observed = ce != null ? asSafeInt(ce.get("observed")) : null;
      if (ceArgs == null || expected == null || observed == null) return false;
      int[] iargs = toIntArgs(ceArgs);
      if (iargs == null) return false;
      WasmResult r = runWasmPureJava(bytes, iargs, fuelLimit);
      return r.trap() == null && Objects.equals(r.value(), observed) && !Objects.equals(r.value(), expected);
    }

    List<Object> argList = asList(in.get("args"));
    int[] iargs = argList != null ? toIntArgs(argList) : new int[0];
    if (iargs == null) return false;
    WasmResult r = runWasmPureJava(bytes, iargs, fuelLimit);
    String expectTrap = asStr(in.get("expectTrap"));
    if (expectTrap != null) return expectTrap.equals(r.trap());
    Integer expectOut = asSafeInt(in.get("expectOutput"));
    return r.trap() == null && Objects.equals(r.value(), expectOut);
  }

  private static int[] toIntArgs(List<Object> list) {
    int[] out = new int[list.size()];
    for (int i = 0; i < list.size(); i++) {
      Integer v = asSafeInt(list.get(i));
      if (v == null) return null;
      out[i] = v;
    }
    return out;
  }

  private static WasmResult runWasmPureJava(byte[] bytes, int[] args, int fuelLimit) {
    int[] p = new int[] { 0 };
    if (bytes.length < 8) return new WasmResult(null, "invalid_wasm");
    byte[] magic = new byte[] { 0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00 };
    for (int i = 0; i < 8; i++) if (bytes[p[0]++] != magic[i]) return new WasmResult(null, "invalid_wasm");

    List<Integer> typeParamCounts = new ArrayList<>();
    List<Integer> funcTypeIdxs = new ArrayList<>();
    Map<String, Integer> exports = new HashMap<>();
    List<Integer> bodyExtraLocals = new ArrayList<>();
    List<byte[]> bodyCodes = new ArrayList<>();

    try {
      while (p[0] < bytes.length) {
        int id = bytes[p[0]++] & 0xff;
        int size = readUleb(bytes, p);
        int end = p[0] + size;
        if (size < 0 || end > bytes.length) return new WasmResult(null, "invalid_wasm");
        if (id == 1) {
          int n = readUleb(bytes, p);
          for (int i = 0; i < n; i++) {
            if ((bytes[p[0]++] & 0xff) != 0x60) return new WasmResult(null, "invalid_wasm");
            int pc = readUleb(bytes, p); p[0] += pc;
            int rc = readUleb(bytes, p); p[0] += rc;
            typeParamCounts.add(pc);
          }
        } else if (id == 3) {
          int n = readUleb(bytes, p);
          for (int i = 0; i < n; i++) funcTypeIdxs.add(readUleb(bytes, p));
        } else if (id == 7) {
          int n = readUleb(bytes, p);
          for (int i = 0; i < n; i++) {
            int nl = readUleb(bytes, p);
            String name = new String(bytes, p[0], nl, StandardCharsets.UTF_8); p[0] += nl;
            int kind = bytes[p[0]++] & 0xff;
            int idx = readUleb(bytes, p);
            if (kind == 0) exports.put(name, idx);
          }
        } else if (id == 10) {
          int n = readUleb(bytes, p);
          for (int i = 0; i < n; i++) {
            int bsize = readUleb(bytes, p);
            int bend = p[0] + bsize;
            if (bsize < 0 || bend > end) return new WasmResult(null, "invalid_wasm");
            int ldecl = readUleb(bytes, p);
            int extra = 0;
            for (int j = 0; j < ldecl; j++) { extra += readUleb(bytes, p); p[0]++; }
            bodyExtraLocals.add(extra);
            bodyCodes.add(Arrays.copyOfRange(bytes, p[0], bend));
            p[0] = bend;
          }
        } else {
          p[0] = end;
        }
        if (p[0] != end) return new WasmResult(null, "invalid_wasm");
      }
    } catch (Exception e) {
      return new WasmResult(null, "invalid_wasm");
    }

    Integer fnIdx = exports.get("main");
    if (fnIdx == null || fnIdx < 0 || fnIdx >= bodyCodes.size()) return new WasmResult(null, "invalid_wasm");
    int pc = typeParamCounts.get(funcTypeIdxs.get(fnIdx));
    int extra = bodyExtraLocals.get(fnIdx);
    byte[] code = bodyCodes.get(fnIdx);
    int[] locals = new int[pc + extra];
    for (int i = 0; i < pc && i < args.length; i++) locals[i] = args[i];

    // Pre-scan control blocks (block/loop -> matching end pc)
    Map<Integer, Integer> matchEnd = new HashMap<>();
    Deque<Integer> ctrl = new ArrayDeque<>();
    for (int ip = 0; ip < code.length; ip++) {
      int op = code[ip] & 0xff;
      if (op == 0x02 || op == 0x03) { ctrl.push(ip); ip++; }
      else if (op == 0x0b) { if (!ctrl.isEmpty()) matchEnd.put(ctrl.pop(), ip); }
      else if (op == 0x0c || op == 0x0d || op == 0x20 || op == 0x21 || op == 0x22 || op == 0x41) {
        while (++ip < code.length && (code[ip] & 0x80) != 0) {}
      }
    }

    int[] stack = new int[256];
    int sp = 0;
    List<int[]> labels = new ArrayList<>(); // [isLoop(0/1), targetIp]
    int[] ipRef = new int[] { 0 };
    int fuel = fuelLimit;

    while (ipRef[0] < code.length) {
      if (--fuel < 0) return new WasmResult(null, "fuel_exhausted");
      int op = code[ipRef[0]++] & 0xff;
      switch (op) {
        case 0x00 -> { return new WasmResult(null, "unreachable"); }
        case 0x01 -> {}
        case 0x02 -> { int start = ipRef[0] - 1; ipRef[0]++; labels.add(new int[] { 0, matchEnd.get(start) + 1 }); }
        case 0x03 -> { int start = ipRef[0] - 1; ipRef[0]++; labels.add(new int[] { 1, start + 2 }); }
        case 0x0b -> {
          if (!labels.isEmpty()) labels.remove(labels.size() - 1);
          else return new WasmResult(sp > 0 ? stack[sp - 1] : 0, null);
        }
        case 0x0c -> {
          int depth = readUleb(code, ipRef);
          int idx = labels.size() - 1 - depth;
          int[] lbl = labels.get(idx);
          int keep = lbl[0] == 1 ? idx + 1 : idx;
          while (labels.size() > keep) labels.remove(labels.size() - 1);
          ipRef[0] = lbl[1];
        }
        case 0x0d -> {
          int depth = readUleb(code, ipRef);
          if (stack[--sp] != 0) {
            int idx = labels.size() - 1 - depth;
            int[] lbl = labels.get(idx);
            int keep = lbl[0] == 1 ? idx + 1 : idx;
            while (labels.size() > keep) labels.remove(labels.size() - 1);
            ipRef[0] = lbl[1];
          }
        }
        case 0x0f -> { return new WasmResult(sp > 0 ? stack[sp - 1] : 0, null); }
        case 0x20 -> stack[sp++] = locals[readUleb(code, ipRef)];
        case 0x21 -> locals[readUleb(code, ipRef)] = stack[--sp];
        case 0x22 -> locals[readUleb(code, ipRef)] = stack[sp - 1];
        case 0x41 -> stack[sp++] = readSleb(code, ipRef);
        case 0x45 -> stack[sp - 1] = stack[sp - 1] == 0 ? 1 : 0;
        case 0x46 -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = (a == b) ? 1 : 0; }
        case 0x47 -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = (a != b) ? 1 : 0; }
        case 0x48 -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = (a < b) ? 1 : 0; }
        case 0x4a -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = (a > b) ? 1 : 0; }
        case 0x4c -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = (a <= b) ? 1 : 0; }
        case 0x4e -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = (a >= b) ? 1 : 0; }
        case 0x6a -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = a + b; }
        case 0x6b -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = a - b; }
        case 0x6c -> { int b = stack[--sp], a = stack[--sp]; stack[sp++] = a * b; }
        case 0x6d -> {
          int b = stack[--sp], a = stack[--sp];
          if (b == 0 || (a == Integer.MIN_VALUE && b == -1)) return new WasmResult(null, "div_by_zero");
          stack[sp++] = a / b;
        }
        case 0x6f -> {
          int b = stack[--sp], a = stack[--sp];
          if (b == 0) return new WasmResult(null, "div_by_zero");
          stack[sp++] = a % b;
        }
        default -> { return new WasmResult(null, "unsupported_op"); }
      }
    }
    return new WasmResult(sp > 0 ? stack[sp - 1] : 0, null);
  }

  private static int readUleb(byte[] b, int[] p) {
    int res = 0, shift = 0;
    while (true) {
      int x = b[p[0]++] & 0xff;
      res |= (x & 0x7f) << shift;
      if ((x & 0x80) == 0) return res;
      shift += 7;
      if (shift > 35) throw new IllegalArgumentException("uleb overflow");
    }
  }

  private static int readSleb(byte[] b, int[] p) {
    int res = 0, shift = 0, x;
    do {
      x = b[p[0]++] & 0xff;
      res |= (x & 0x7f) << shift;
      shift += 7;
      if (shift > 35) throw new IllegalArgumentException("sleb overflow");
    } while ((x & 0x80) != 0);
    if (shift < 32 && (x & 0x40) != 0) res |= (~0 << shift);
    return res;
  }

  // ==================== Helpers & Minimal RFC 8259 JSON Parser ====================
  @SuppressWarnings("unchecked")
  private static Map<String, Object> asObj(Object o) { return (o instanceof Map<?, ?>) ? (Map<String, Object>) o : null; }
  @SuppressWarnings("unchecked")
  private static List<Object> asList(Object o) { return (o instanceof List<?>) ? (List<Object>) o : null; }
  private static String asStr(Object o) { return (o instanceof String s) ? s : null; }
  private static Long asSafeLong(Object o) {
    if (o instanceof Long l) return l;
    if (o instanceof Integer i) return i.longValue();
    if (o instanceof Double d && Double.isFinite(d) && d == Math.floor(d) && Math.abs(d) <= 9007199254740991.0) return (long) d.doubleValue();
    return null;
  }
  private static Integer asSafeInt(Object o) {
    Long l = asSafeLong(o);
    if (l == null || l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) return null;
    return l.intValue();
  }

  private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    return out;
  }

  private static String bytesToHex(byte[] bytes) {
    char[] hex = new char[bytes.length * 2];
    final char[] digits = "0123456789abcdef".toCharArray();
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xff;
      hex[i * 2] = digits[v >>> 4];
      hex[i * 2 + 1] = digits[v & 0x0f];
    }
    return new String(hex);
  }

  private static String toPrettyJson(Object obj) { return canonical(obj); }

  static final class JsonParser {
    private final String s;
    private int i;
    private JsonParser(String s) { this.s = s; }
    static Object parse(String s) {
      JsonParser p = new JsonParser(s);
      Object v = p.val();
      p.ws();
      if (p.i != p.s.length()) throw new IllegalArgumentException("Trailing JSON at " + p.i);
      return v;
    }
    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private Object val() {
      ws();
      if (i >= s.length()) throw new IllegalArgumentException("Unexpected EOF");
      char c = s.charAt(i);
      return switch (c) {
        case '{' -> obj();
        case '[' -> arr();
        case '"' -> str();
        case 't' -> { expect("true"); yield Boolean.TRUE; }
        case 'f' -> { expect("false"); yield Boolean.FALSE; }
        case 'n' -> { expect("null"); yield null; }
        default -> num();
      };
    }
    private void expect(String lit) {
      if (!s.startsWith(lit, i)) throw new IllegalArgumentException("Expected " + lit + " at " + i);
      i += lit.length();
    }
    private Map<String, Object> obj() {
      i++; // '{'
      Map<String, Object> m = new LinkedHashMap<>();
      ws();
      if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
      while (true) {
        ws();
        String k = str();
        ws();
        if (s.charAt(i++) != ':') throw new IllegalArgumentException("Expected ':' at " + i);
        m.put(k, val());
        ws();
        char next = s.charAt(i++);
        if (next == '}') return m;
        if (next != ',') throw new IllegalArgumentException("Expected ',' or '}' at " + i);
      }
    }
    private List<Object> arr() {
      i++; // '['
      List<Object> list = new ArrayList<>();
      ws();
      if (i < s.length() && s.charAt(i) == ']') { i++; return list; }
      while (true) {
        list.add(val());
        ws();
        char next = s.charAt(i++);
        if (next == ']') return list;
        if (next != ',') throw new IllegalArgumentException("Expected ',' or ']' at " + i);
      }
    }
    private String str() {
      if (s.charAt(i++) != '"') throw new IllegalArgumentException("Expected '\"' at " + i);
      StringBuilder sb = new StringBuilder();
      while (i < s.length()) {
        char c = s.charAt(i++);
        if (c == '"') return sb.toString();
        if (c == '\\') {
          char e = s.charAt(i++);
          switch (e) {
            case '"', '\\', '/' -> sb.append(e);
            case 'b' -> sb.append('\b');
            case 'f' -> sb.append('\f');
            case 'n' -> sb.append('\n');
            case 'r' -> sb.append('\r');
            case 't' -> sb.append('\t');
            case 'u' -> {
              if (i + 4 > s.length()) throw new IllegalArgumentException("Truncated \\u escape");
              String hex4 = s.substring(i, i + 4);
              for (int k = 0; k < 4; k++) if (Character.digit(hex4.charAt(k), 16) < 0) throw new IllegalArgumentException("Invalid \\u escape: " + hex4);
              sb.append((char) Integer.parseInt(hex4, 16));
              i += 4;
            }
            default -> throw new IllegalArgumentException("Bad escape \\" + e);
          }
        } else sb.append(c);
      }
      throw new IllegalArgumentException("Unterminated string");
    }
    private Object num() {
      int start = i;
      if (s.charAt(i) == '-') i++;
      while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
      boolean isFloat = false;
      if (i < s.length() && s.charAt(i) == '.') { isFloat = true; i++; while (i < s.length() && Character.isDigit(s.charAt(i))) i++; }
      if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
        isFloat = true; i++;
        if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
        while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
      }
      String tok = s.substring(start, i);
      if (isFloat || tok.equals("-0")) return Double.parseDouble(tok);
      try { return Long.parseLong(tok); } catch (NumberFormatException overflow) { return Double.parseDouble(tok); }
    }
  }
}

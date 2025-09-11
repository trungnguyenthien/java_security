package tx.secure.type;

import org.json.JSONException;
import org.json.JSONObject;

public class Result {
    private final String alg;
    private final String iv;
    private final String ct;
    private final String tag;
    private final String epub;

    public Result(String alg, String iv, String ct, String tag, String epk) {
        this.alg = alg;
        this.iv = iv;
        this.ct = ct;
        this.tag = tag;
        this.epub = epk;
    }

    public Result(JSONObject obj) throws JSONException {
        this.alg = obj.getString("alg");
        this.iv = obj.getString("iv");
        this.ct = obj.getString("ct");
        this.tag = obj.getString("tag");
        this.epub = obj.getString("epub");
    }

    public Result(String json) throws JSONException {
        this(new JSONObject(json));
    }

    // Algorithm
    public String getAlg() {
        return alg;
    }

    // Initialization vector
    public String getIv() {
        return iv;
    }

    // Ciphertext
    public String getCt() {
        return ct;
    }

    // Authentication tag
    public String getTag() {
        return tag;
    }

    // Ephemeral public key
    public String getEpub() {
        return epub;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject obj = new JSONObject();
        obj.put("alg", alg);
        obj.put("iv", iv);
        obj.put("ct", ct);
        obj.put("tag", tag);
        obj.put("epub", epub);
        return obj;
    }

    // Sample output: {"alg":"AES-GCM-256","iv":"...","ct":"...","tag":"...","epub":"..."}
    public String toJsonString() {
        try {
            return toJson().toString();
        } catch (JSONException e) {
            throw new RuntimeException("Failed to convert to JSON string", e);
        }
    }
}

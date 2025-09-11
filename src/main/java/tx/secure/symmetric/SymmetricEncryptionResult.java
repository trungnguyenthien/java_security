package tx.secure.symmetric;

import org.json.JSONException;
import org.json.JSONObject;

public class SymmetricEncryptionResult {
    private final String alg;
    private final String iv;
    private final String ct;
    private final String tag;

    public SymmetricEncryptionResult(String alg, String iv, String ct, String tag) {
        this.alg = alg;
        this.iv = iv;
        this.ct = ct;
        this.tag = tag;
    }

    public SymmetricEncryptionResult(JSONObject obj) throws JSONException {
        this.alg = obj.getString("alg");
        this.iv = obj.getString("iv");
        this.ct = obj.getString("ct");
        this.tag = obj.getString("tag");
    }

    public SymmetricEncryptionResult(String json) throws JSONException {
        this(new JSONObject(json));
    }

    public String getAlg() {
        return alg;
    }

    public String getIv() {
        return iv;
    }

    public String getCt() {
        return ct;
    }

    public String getTag() {
        return tag;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject obj = new JSONObject();
        obj.put("alg", alg);
        obj.put("iv", iv);
        obj.put("ct", ct);
        obj.put("tag", tag);
        return obj;
    }
}

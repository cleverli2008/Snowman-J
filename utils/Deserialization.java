package utils;

import java.util.StringTokenizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map.Entry;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import abe.Attribute;
import abe.Ciphertext;
import abe.Key;
import abe.Key.Type;
import abe.Policy;
import abe.SecretKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Deserialization {

	private static final Pairing pairing = PairingManager.getDefaultPairing();
	private static final ArrayList<String> g2_pattern = new ArrayList<String>(Arrays.asList("g2", "g2_x", "g2_y"));
	private static final ArrayList<String> zr_pattern = new ArrayList<String>(Arrays.asList("alpha", "x", "y", "o"));
	private static final ArrayList<String> gt_pattern = new ArrayList<String>(Arrays.asList("e_gg_alpha", "C"));

	// json to key
	public static Key toKey(String strObj) {

		JSONObject ins = JSON.parseObject(strObj, JSONObject.class);
		Key key = new Key();
		Element ele = null;

		if (ins.get("type").equals("PUBLIC"))
			key.setType(Type.PUBLIC);
		else if (ins.get("type").equals("MASTER"))
			key.setType(Type.MASTER);
		else if (ins.get("type").equals("TRANSFER"))
			key.setType(Type.TRANSFER);

		for (Entry<String, Object> entry : ins.entrySet()) {
			String strIndex = entry.getKey();
			byte[] targetBytes = ins.getBytes(strIndex);
			if (!(strIndex.equals("type"))) {
				if (g2_pattern.contains(strIndex)) {
					ele = pairing.getG2().newElementFromBytes(targetBytes).getImmutable();
					key.getComponents().put(strIndex, ele);
					continue;
				} else if (gt_pattern.contains(strIndex)) {
					ele = pairing.getGT().newElementFromBytes(targetBytes).getImmutable();
					key.getComponents().put(strIndex, ele);
					continue;
				} else if (zr_pattern.contains(strIndex)) {
					ele = pairing.getZr().newElementFromBytes(targetBytes).getImmutable();
					key.getComponents().put(strIndex, ele);
					continue;
				} else {
					ele = pairing.getG1().newElementFromBytes(targetBytes).getImmutable();
					key.getComponents().put(strIndex, ele);
				}
			}
		}
		return key;
	}

	public static SecretKey toSecretKey(String strObj) {

		JSONObject ins = JSON.parseObject(strObj, JSONObject.class);
		SecretKey secretkey = new SecretKey();
		Element ele = null;

		for (Entry<String, Object> entry : ins.entrySet()) {
			if (entry.getKey().equals("policy")) {
				Policy policy = new Policy(entry.getValue().toString());
				secretkey.setPolicy(policy);
				secretkey.setMatirx(policy.getMatrix());
				secretkey.setRho(policy.getRho());
			} else {
				String strIndex = entry.getKey();
				byte[] targetBytes = ins.getBytes(strIndex);
				if (strIndex.startsWith("K")
						&& (strIndex.endsWith("2") || strIndex.endsWith("3") || strIndex.endsWith("4")))
					ele = pairing.getG2().newElementFromBytes(targetBytes);
				else if (strIndex.startsWith("N"))
					ele = pairing.getZr().newElementFromBytes(targetBytes);
				else
					ele = pairing.getG1().newElementFromBytes(targetBytes);

				secretkey.getComponents().put(strIndex, ele);
			}
		}
		// System.out.println("---------------------------");
		// System.out.println(secretKey.toString());
		// System.out.println("---------------------------");
		return secretkey;

	}

	// json to ciphertext
	public static Ciphertext toCiphertext(String strObj) {

		JSONObject ins = JSON.parseObject(strObj, JSONObject.class);
		Ciphertext ct = new Ciphertext();
		Element ele;

		for (Entry<String, Object> entry : ins.entrySet()) {

			if (!entry.getKey().equals("attrnum")) {
				if (entry.getKey().equals("attributes")) {
					Attribute[] attributes = new Attribute[(int) ins.get("attrnum")];
					StringTokenizer st = new StringTokenizer(entry.getValue().toString(), "_");
					int k = 0;
					while (st.hasMoreTokens()) {
						String tmpAttr = st.nextToken();
						StringTokenizer stnext = new StringTokenizer(tmpAttr, ":");
						String name = stnext.nextToken().trim();
						String value = stnext.nextToken().trim();
						attributes[k] = new Attribute(name, value);
						k++;
					}
					ct.setAttributes(attributes);
				} else if (entry.getKey().equals("load")) {
					ct.setLoad(ins.getBytes(entry.getKey()));
				} else {
					String strIndex = entry.getKey();
					byte[] targetBytes = ins.getBytes(strIndex);
					if (strIndex.equals("C"))
						ele = pairing.getGT().newElementFromBytes(targetBytes);
					else if (strIndex.startsWith("C0"))
						ele = pairing.getG2().newElementFromBytes(targetBytes);
					else
						ele = pairing.getG1().newElementFromBytes(targetBytes);
					ct.getComponents().put(strIndex, ele);
				}
			}
		}
		// System.out.println("---------------------------");
		// System.out.println(ct.toString());
		// System.out.println("---------------------------");
		return ct;
	}

}

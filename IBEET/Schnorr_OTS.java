package IBEET;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import utils.Hash;

public class Schnorr_OTS {

	private Pairing pairing = PairingFactory.getPairing("scheme/a.properties");

	public List<Map<String, Object>> gen() {
		Element g = pairing.getG1().newRandomElement().getImmutable();
		Element x = pairing.getZr().newRandomElement().getImmutable();
		Element X = g.powZn(x).getImmutable();
		Element y = pairing.getZr().newRandomElement().getImmutable();
		Element Y = g.powZn(y).getImmutable();
		Element ele_K = pairing.getZr().newRandomElement().getImmutable();
		byte[] K = ele_K.toBytes();
		Hash H = new Hash("sha-1");
		Hash H_prime = new Hash("md5");

		Map<String, Object> vk = new HashMap<String, Object>();
		vk.put("g", g);
		vk.put("K", K);
		vk.put("X", X);
		vk.put("Y", Y);
		vk.put("H", H);
		vk.put("H_prime", H_prime);

		Map<String, Object> sk = new HashMap<String, Object>();
		sk.put("x", x);
		sk.put("y", y);

		List<Map<String, Object>> res = new ArrayList<Map<String, Object>>();
		res.add(0, sk);
		res.add(1, vk);
		return res;
	}

	public Element sign(Map<String, Object> ct, Map<String, Object> vk, Map<String, Object> sk) {
		Hash H = ((Hash) vk.get("H"));
		Hash H_prime = ((Hash) vk.get("H_prime"));
		Element Y = ((Element) vk.get("Y")).duplicate().getImmutable();
		byte[] K = ((byte[]) vk.get("K"));
		Element x = ((Element) sk.get("x")).duplicate().getImmutable();
		Element y = ((Element) sk.get("y")).duplicate().getImmutable();

		byte[] byte_Y = Y.toBytes();
		byte[] byte_K_Y_ct = Utils.addBytes(K, byte_Y);
		byte[] fixLength_ct = H_prime.hash(ct.toString().getBytes());
		byte_K_Y_ct = Utils.addBytes(byte_K_Y_ct, fixLength_ct);
		byte[] byte_H_K_Y_ct = H.hash(byte_K_Y_ct);
		Element elem_H_K_Y_ct = Utils.bytes2element(byte_H_K_Y_ct, "Zr").getImmutable();
		Element sigma = y.add(elem_H_K_Y_ct.mul(x)).getImmutable();
		return sigma;
	}

	public boolean verify(Map<String, Object> ct) {

		Map<String, Object> vk = (HashMap<String, Object>) ct.get("vk");
		Element sigma = ((Element) ct.get("sigma")).duplicate().getImmutable();
		ct.remove("sigma");
		ct.remove("vk");

		Element X = ((Element) vk.get("X")).duplicate().getImmutable();
		Element Y = ((Element) vk.get("Y")).duplicate().getImmutable();
		Element g = ((Element) vk.get("g")).duplicate().getImmutable();

		byte[] K = (byte[]) vk.get("K");
		Hash H = (Hash) vk.get("H");
		Hash H_prime = (Hash) vk.get("H_prime");

		byte[] byte_K_Y_ct = Utils.addBytes(K, Y.toBytes());
		byte[] fixLength_ct = H_prime.hash(ct.toString().getBytes());
		byte_K_Y_ct = Utils.addBytes(byte_K_Y_ct, fixLength_ct);
		byte[] byte_H_K_Y_ct = H.hash(byte_K_Y_ct);
		Element H_K_Y_ct = Utils.bytes2element(byte_H_K_Y_ct, "Zr").getImmutable();
		ct.put("sigma", sigma);
		ct.put("vk", vk);

		Element equ_left = g.powZn(sigma).getImmutable();
		Element equ_right = Y.mul(X.powZn(H_K_Y_ct)).getImmutable();
		if (!equ_left.equals(equ_right)) {
			System.out.print("The signature is invaild!");
			return false;
		}
		return true;
	}
}

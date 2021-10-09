package IB_CH;

import java.util.HashMap;
import java.util.Map;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @ClassName:ZSNS03_One
 * @Description:(Implementation of "ID-Based Chameleon Hashes from Bilinear
 *               Pairings" - scheme one)
 * @author:cleverli2008
 * @date:2021/9/30
 */

public class ZSNS03_One {

	// Employ the Type A pairing
	private Pairing pairing = PairingFactory.getPairing("scheme/a.properties");

	public Map<String, Object>[] setup() {

		long startTime = System.nanoTime();

		// Init the master key and public key
		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("type", "msk");

		Map<String, Object> publicKey = new HashMap<String, Object>();
		publicKey.put("type", "pk");

		// Randomly pick s
		Element s = pairing.getZr().newRandomElement().getImmutable();

		// Set the master key
		masterKey.put("s", s);

		// Randomly picks P from G_2
		Element P = pairing.getG2().newRandomElement().getImmutable();

		// Compute P_pub = P^s
		Element P_pub = P.powZn(s).getImmutable();

		// Set the public parameters
		publicKey.put("P", P);
		publicKey.put("P_pub", P_pub);

		// Set the key array
		Map<String, Object>[] res = new Map[2];
		res[0] = publicKey;
		res[1] = masterKey;

		// Record the running time, the unit is ms
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return res;
	}

	public Element keygen(Map<String, Object> pk, Map<String, Object> msk, byte[] ID) {

		long startTime = System.nanoTime();

		// obtain the master key
		Element s = ((Element) msk.get("s")).duplicate().getImmutable();

		// Compute ele_ID = H_0(ID)
		Element ele_ID = pairing.getG1().newElement().setFromHash(ID, 0, ID.length).getImmutable();

		// Compute td = ele_ID^s
		Element trapdoor = ele_ID.powZn(s).getImmutable();

		// The same function as that of the codes above
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return trapdoor;
	}

	public Element[] hash(Map<String, Object> pk, byte[] ID, byte[] m) {

		long startTime = System.nanoTime();

		// Get P_pub and P from pk
		Element P_pub = ((Element) pk.get("P_pub")).duplicate().getImmutable();
		Element P = ((Element) pk.get("P")).duplicate().getImmutable();

		// Compute ele_ID = H_0(ID)
		Element ele_ID = pairing.getG1().newElement().setFromHash(ID, 0, ID.length).getImmutable();

		// Pick R from G_1
		Element R = pairing.getG1().newRandomElement().getImmutable();

		// Compute H_1(m)
		Element ele_m = pairing.getZr().newElement().setFromHash(m, 0, m.length).getImmutable();

		// Compute the hash value h
		// h = e(R, P)e(H_1(m) H_0(ID), P_pub)
		Element h = pairing.pairing(R, P).mul(pairing.pairing(ele_ID.powZn(ele_m), P_pub));

		// Set the return array, in which h[0] = h, h[1] = R
		Element[] hash_r = new Element[2];
		hash_r[0] = h.duplicate();
		hash_r[1] = R.duplicate();

		// The same function as that of the code above
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return hash_r;
	}

	public Element col(Element td, Element[] hash_r, byte[] m, byte[] m_prime) {

		long startTime = System.nanoTime();

		// Compute H_1(m) and H_1(m')
		Element ele_m = pairing.getZr().newElement().setFromHash(m, 0, m.length).getImmutable();
		Element ele_m_prime = pairing.getZr().newElement().setFromHash(m_prime, 0, m_prime.length).getImmutable();

		// Compute temp = H1(m)-H1(m')
		Element temp = ele_m.add(ele_m_prime.negate()).getImmutable();
		Element R = hash_r[1].duplicate().getImmutable();

		// Compute R' = td^((H_1(m)-H_1(m')) R
		Element R_prime = td.powZn(temp).mul(R);

		// The same function as that of the code above
		long endTime = System.nanoTime();
		System.out.println(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return R_prime;
	}

	public Boolean verfiy(Map<String, Object> pk, Element R_prime, byte[] m_prime, byte[] ID, Element h) {

		// This algorithm is used to check whether Hash(pk,ID,m';r') = h ...(1)

		// Get P_pub and P from pk
		Element P_pub = ((Element) pk.get("P_pub")).duplicate().getImmutable();
		Element P = ((Element) pk.get("P")).duplicate().getImmutable();

		// Compute H_0(ID)
		Element ele_ID = pairing.getG1().newElement().setFromHash(ID, 0, ID.length).getImmutable();

		// Compute H_1(m')
		Element ele_m_prime = pairing.getZr().newElement().setFromHash(m_prime, 0, m_prime.length).getImmutable();

		// Compute h' = e(R', P)e(H_1(m') H_0(ID), P_pub)
		Element h_prime = pairing.pairing(R_prime, P).mul(pairing.pairing(ele_ID.powZn(ele_m_prime), P_pub));

		// If the equation (1) holds, the algorithm returns true; otherwise, it returns false
		if (h_prime.equals(h))
			return true;
		else
			return false;
	}
}

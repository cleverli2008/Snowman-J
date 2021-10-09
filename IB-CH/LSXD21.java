package IB_CH;

import java.util.HashMap;
import java.util.Map;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @ClassName:LSXD21
 * @Description:(Implementation of "Efficient identity-based chameleon hash for
 *               mobile devices")
 * @author:cleverli2008
 * @date:2021/9/30
 */

public class LSXD21 {

	// Employ the Type A pairing
	private Pairing pairing = PairingFactory.getPairing("scheme/a.properties");

	public Map<String, Object>[] setup() {

		long startTime = System.nanoTime();

		// Init the master key and public key
		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("type", "msk");

		Map<String, Object> publicKey = new HashMap<String, Object>();
		publicKey.put("type", "pk");

		// Randomly pick alpha and beta
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		Element beta = pairing.getZr().newRandomElement().getImmutable();

		// Set the master key
		masterKey.put("alpha", alpha);
		masterKey.put("beta", beta);

		// Pick g
		Element g = pairing.getG1().newRandomElement().getImmutable();

		// Compute g_1 = g^alpha, g_2 = g^beta
		Element g_1 = g.powZn(alpha).getImmutable();
		Element g_2 = g.powZn(beta).getImmutable();

		// Compute e(g,g) and e(g_2,g)
		Element e_gg = pairing.pairing(g, g).getImmutable();
		Element e_gg_2 = pairing.pairing(g_2, g).getImmutable();

		// Set the public parameters
		publicKey.put("g", g);
		publicKey.put("g_1", g_1);
		publicKey.put("g_2", g_2);
		publicKey.put("e_gg", e_gg);
		publicKey.put("e_gg_2", e_gg_2);

		// Set the key array
		Map<String, Object>[] res = new Map[2];
		res[0] = publicKey;
		res[1] = masterKey;

		// Record the running time, the unit is ms
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return res;
	}

	public Element[] keygen(Map<String, Object> pk, Map<String, Object> msk, byte[] ID) {

		long startTime = System.nanoTime();

		// Get g from pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();

		// Obtain the master key
		Element alpha = ((Element) msk.get("alpha")).duplicate().getImmutable();
		Element beta = ((Element) msk.get("beta")).duplicate().getImmutable();

		// Randomly pick t
		Element t = pairing.getZr().newRandomElement().getImmutable();

		// Hash ID to the element of Z_p
		Element ele_ID = pairing.getZr().newElement().setFromHash(ID, 0, ID.length).getImmutable();

		// Compute exp = (beta-t)/(alpha-ID)
		Element exp = (beta.add(t.negate())).div(alpha.add(ele_ID.negate())).getImmutable();

		// Set td = (td_1,td_2)
		Element[] trapdoor = new Element[2];
		// td_1 = t
		trapdoor[0] = t.duplicate();
		// td_2 = g^((beta-t)/(alpha-ID))
		trapdoor[1] = g.powZn(exp).duplicate().getImmutable();

		// The same function as that of the codes above
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return trapdoor;
	}

	public Element[] hash(Map<String, Object> pk, byte[] ID, byte[] m) {

		long startTime = System.nanoTime();

		// Get the required component from pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element e_gg = ((Element) pk.get("e_gg")).duplicate().getImmutable();
		Element e_gg_2 = ((Element) pk.get("e_gg_2")).duplicate().getImmutable();

		// Randomly pick r_1 from Z_p and r_2 from G_1
		Element r_1 = pairing.getZr().newRandomElement().getImmutable();
		Element r_2 = pairing.getG1().newRandomElement().getImmutable();

		// Hash m and ID to the elements of Z_p
		Element ele_m = pairing.getZr().newElement().setFromHash(m, 0, m.length).getImmutable();
		Element ele_ID = pairing.getZr().newElement().setFromHash(ID, 0, ID.length).getImmutable();

		// Compute the hash value h
		// h = e(g_2,g)^m e(g,g)^(r_1) e(r_2,g_1 g^(-ID))
		Element h = (e_gg_2.powZn(ele_m)).mul(e_gg.powZn(r_1))
				.mul(pairing.pairing(r_2, g_1.mul(g.powZn(ele_ID.negate())))).getImmutable();

		// Set the return array, in which h[0] = h, h[1] = r_1 and h[2] = r_2
		Element[] hash_r = new Element[3];
		hash_r[0] = h.duplicate();
		hash_r[1] = r_1.duplicate();
		hash_r[2] = r_2.duplicate();

		// The same function as that of the code above
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return hash_r;
	}

	public Element[] col(Element[] td, Element[] hash_r, byte[] m, byte[] m_prime) {

		long startTime = System.nanoTime();

		// Hash m and m' to the elements of Z_p
		Element ele_m = pairing.getZr().newElement().setFromHash(m, 0, m.length).getImmutable();
		Element ele_m_prime = pairing.getZr().newElement().setFromHash(m_prime, 0, m_prime.length).getImmutable();

		// Compute temp = m - m'
		Element temp = ele_m.add(ele_m_prime.negate()).getImmutable();

		// Compute the r'_1 and r'_2
		// r'_1 = r_1 + (m - m') td_1
		// r'_2 = r_2 td_2^(m -m')
		Element r_1_prime = hash_r[1].add(td[0].mul(temp)).getImmutable();
		Element r_2_prime = hash_r[2].mul(td[1].powZn(temp)).getImmutable();

		// Set the r'=(r'_1,r'_2)
		Element[] inside_r = new Element[2];
		inside_r[0] = r_1_prime.duplicate();
		inside_r[1] = r_2_prime.duplicate();

		// The same function as that of the code above
		long endTime = System.nanoTime();
		System.out.println(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return inside_r;
	}

	public Boolean verfiy(Map<String, Object> pk, Element[] r_new, byte[] m_prime, byte[] ID, Element h) {

		// This algorithm is used to check whether Hash(pk,ID,m';r') = h ...(1)

		// Get the required component from pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element e_gg = ((Element) pk.get("e_gg")).duplicate().getImmutable();
		Element e_gg_2 = ((Element) pk.get("e_gg_2")).duplicate().getImmutable();

		// Get r'_1 and r'_2 from r'
		Element r_1_prime = r_new[0].duplicate().getImmutable();
		Element r_2_prime = r_new[1].duplicate().getImmutable();

		// Hash m' and ID to the elements of Z_p
		Element ele_m_prime = pairing.getZr().newElement().setFromHash(m_prime, 0, m_prime.length).getImmutable();
		Element ele_ID = pairing.getZr().newElement().setFromHash(ID, 0, ID.length).getImmutable();

		// Calculate the hash value h'
		// h' = e(g_2,g)^m' e(g,g)^(r'_1) e(r'_2,g_1 g^(-ID))
		Element h_prime = e_gg_2.powZn(ele_m_prime).mul(e_gg.powZn(r_1_prime))
				.mul(pairing.pairing(r_2_prime, g_1.mul(g.powZn(ele_ID.negate())))).getImmutable();

		// If the equation (1) holds, the algorithm returns true; otherwise, it returns false
		if (h_prime.equals(h))
			return true;
		else
			return false;
	}
}

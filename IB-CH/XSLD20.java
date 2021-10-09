package IB_CH;

import java.util.HashMap;
import java.util.Map;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import utils.Hash;

/**   
 * @ClassName: XSLD20   
 * @Description:(Implementation of "Identity-Based Chameleon Hash without Random Oracles and Application in the Mobile Internet")   
 * @author:cleverli2008
 * @date:2021/9/30 
 */

public class XSLD20 {

	// Employ the Type A pairing
	private Pairing pairing = PairingFactory.getPairing("scheme/a.properties");
	
	public Map<String, Object>[] setup(int n){

		long startTime = System.nanoTime();
		
		// Init the master key and public key
		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("type", "msk");
		
		Map<String, Object> publicKey = new HashMap<String, Object>();
		publicKey.put("type", "pk");
		
		// Randomly pick alpha
		Element alpha = pairing.getZr().newRandomElement().getImmutable();	
		
		// Randomly pick g
		Element g = pairing.getG1().newRandomElement().getImmutable();		
		
		// Compute g_1 = g^alpha and randomly pick g_2 from G1
		Element g_1 = g.powZn(alpha).getImmutable();	
		Element g_2 = pairing.getG1().newRandomElement().getImmutable();
		
		// Compute g_2_alpha 
		Element g_2_alpha = g_2.powZn(alpha).getImmutable();
		
		// Set the master key
		masterKey.put("g_2_alpha", g_2_alpha);
		
		// Set the public parameters
		publicKey.put("g", g);
		publicKey.put("g_1", g_1);
		publicKey.put("g_2", g_2);
		
		for(int i = 0; i <= n; i++){
			Element u_i = pairing.getG1().newRandomElement().getImmutable();
			publicKey.put("u_"+ i, u_i);
		}
	
		// Set the key array
		Map<String, Object>[] res = new Map[2];
		res[0] = publicKey;
		res[1] = masterKey;

		// Record the running time, the unit is ms
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return res;
	}
   
	public Element[] keygen(Map<String, Object> pk, Map<String, Object> msk, int[] ID){

		long startTime = System.nanoTime();
		
		// Get g and u_0 from pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
		
		// Obtain the master secret key
		Element g_2_alpha = ((Element) msk.get("g_2_alpha")).duplicate().getImmutable();
		
		// Randomly pick t
		Element t = pairing.getZr().newRandomElement().getImmutable();
		
		
		// Compute u_0 prod_i=1^n u_i^(I_i)
		Element prod_u_i = u_0.duplicate().getImmutable();
		
		for(int i = 0; i < ID.length; i++) {
			if(ID[i] != 0) {
				Element u_i = ((Element) pk.get("u_"+ i)).duplicate().getImmutable();
				prod_u_i = prod_u_i.mul(u_i);
			}
		}
		
		Element[] trapdoor = new Element[2];
		
		// Compute td_1 = g_2^alpha (u_0 prod_i=1^n u_i^(I_i))^t
		trapdoor[0] = g_2_alpha.mul(prod_u_i.powZn(t)).duplicate();
		// Compute td_2 = g^t
		trapdoor[1] = g.powZn(t).duplicate();

		// The same function as that of the codes above
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return trapdoor;
	}

	public Element[] hash(Map<String, Object> pk, int[] ID, byte[] m){

		long startTime = System.nanoTime();
	
		// Get g,g_1,g_2,u_0 from pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
			
		// Randomly pick r_1, r_2
		Element r_1 = pairing.getG1().newRandomElement().getImmutable();
		Element r_2 = pairing.getG1().newRandomElement().getImmutable();
		
		// Hash m to the element of Z_p
		Element ele_m = pairing.getZr().newElement().setFromHash(m, 0, m.length).getImmutable();

		// Compute u_0 prod_i=1^n u_i^(I_i)
		Element prod_u_i = u_0.duplicate().getImmutable();
		
		for(int i = 0; i < ID.length; i++) {
			if(ID[i] != 0) {
				Element u_i = ((Element) pk.get("u_"+ i)).duplicate().getImmutable();
				prod_u_i = prod_u_i.mul(u_i);
			}
		}
		
		// Compute the hash value h
		// h=e(g_1,g_2)^m (e(r_1,g)/e(r_2,u_0 prod_i=1^n u_i^(I_i)))
		Element h = pairing.pairing(g_1, g_2).powZn(ele_m).mul(pairing.pairing(r_1, g).div(pairing.pairing(r_2, prod_u_i))).getImmutable();
		
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

	public Element[] col(Element[] td, Element[] hash_r, byte[] m, byte[] m_prime){

		long startTime = System.nanoTime();
		
		// Hash m and m' to the elements of Z_p
		Element ele_m = pairing.getZr().newElement().setFromHash(m, 0, m.length).getImmutable();
		Element ele_m_prime = pairing.getZr().newElement().setFromHash(m_prime, 0, m_prime.length).getImmutable();
		
		// Compute temp = m - m'
		Element temp = ele_m.add(ele_m_prime.negate()).getImmutable();
		
		// Compute the r'_1 and r'_2
		// r'_1 = r_1 td_1^(m- m')
		// r'_2 = r_2 td_2^(m -m')
		Element r_1_prime = hash_r[1].mul(td[0].powZn(temp)).getImmutable();
		Element r_2_prime =  hash_r[2].mul(td[1].powZn(temp)).getImmutable();
		
		// Set the r'=(r'_1,r'_2)
		Element[] inside_r = new Element[2];
		inside_r[0] = r_1_prime.duplicate();
		inside_r[1] = r_2_prime.duplicate();
			
		// The same function as that of the code above
		long endTime = System.nanoTime();
		System.out.println(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return inside_r;
	}
	
	public Boolean verfiy(Map<String, Object> pk, Element[] r_new, byte[] m_prime, int[] ID, Element h){
		
		// This algorithm is used to check whether Hash(pk,ID,m';r') = h ...(1)
		
		// Get the required component from pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
		
		// Get r'_1 and r'_2 from r
		Element r_1_prime = r_new[0].duplicate().getImmutable();
		Element r_2_prime = r_new[1].duplicate().getImmutable();
		
		// Hash m' the element of Z_p
		Element ele_m_prime = pairing.getZr().newElement().setFromHash(m_prime, 0, m_prime.length).getImmutable();
		
		// Compute u_0 prod_i=1^n u_i^(I_i)
		Element prod_u_i = u_0.duplicate().getImmutable();
		
		for(int i = 0; i < ID.length; i++) {
			if(ID[i] != 0) {
				Element u_i = ((Element) pk.get("u_"+ i)).duplicate().getImmutable();
				prod_u_i = prod_u_i.mul(u_i);
			}
		}
		
		// Calculate the hash value h'
		Element h_prime = pairing.pairing(g_1, g_2).powZn(ele_m_prime).mul(pairing.pairing(r_1_prime, g).div(pairing.pairing(r_2_prime, prod_u_i))).getImmutable();
		
		// If the equation (1) holds, the algorithm returns true; otherwise, it returns false
		if(h_prime.equals(h))
		 return true;
		else 
		 return false;
	}
	
	public static int[] getBit(byte[] by){
		
		//Transform the byte array to the bit array
		
		int[] bits = new int[256];
		int offset = 8;
		for(int i = 0; i < by.length; i++) {
		   for(int j = 0; j < 8; j++) {
				bits[i*offset+j] = (by[i]>>(7-j))&0x1;		
		   }
		}
		return bits;
	}
	
}

package IB_CH;

import java.util.Map;
import java.util.Scanner;

import it.unisa.dia.gas.jpbc.Element;
import utils.Hash;	

public class Test_IBCH {
	
	public boolean testZSNS03_One(byte[] ID, byte[] m, byte[] m_prime) {
		
		ZSNS03_One scheme = new ZSNS03_One();
		
		// Run the setup algorithm
		Map<String, Object>[] keys = scheme.setup();
		
		// Run the trapdoor algorithm
		Element td = scheme.keygen(keys[0], keys[1], ID);
		
		// Run the hash algorithm
		Element[] h_r = scheme.hash(keys[0], ID, m);
		
		// Run the col algorithm
		Element inside_r = scheme.col(td, h_r, m, m_prime);
		
		// Verfiy
		boolean flag = scheme.verfiy(keys[0], inside_r, m_prime, ID, h_r[0]);
	
		return flag;
	}

	public boolean testZSNS03_Two(byte[] ID, byte[] m, byte[] m_prime) {
		
		ZSNS03_Two scheme = new ZSNS03_Two();
		
		// Run the setup algorithm
		Map<String, Object>[] keys = scheme.setup();
		
		// Run the trapdoor algorithm
		Element td = scheme.keygen(keys[0], keys[1], ID);
		
		// Run the hash algorithm
		Element[] h_r = scheme.hash(keys[0], ID, m);
		
		// Run the col algorithm
		Element inside_r = scheme.col(td, h_r, m, m_prime);
		
		// Verfiy
		boolean flag = scheme.verfiy(keys[0], inside_r, m_prime, ID, h_r[0]);
	
		return flag;
	}

	public boolean testXSLD20(byte[] byte_ID, byte[] m, byte[] m_prime) {
		
		XSLD20 scheme = new XSLD20();
		
		// Set the length of ID
		int n = 256;
		
		// Run the setup algorithm
		Map<String, Object>[] keys = scheme.setup(n);
	
		// Convert the form of ID from the byte arrary to the bit arrary
		int [] ID = Test_IBCH.getBit(byte_ID);
		
		// Run the trapdoor algorithm
		Element[] td = scheme.keygen(keys[0], keys[1], ID);
		
		// Run the hash algorithm
		Element[] h_r = scheme.hash(keys[0], ID, m);
		
		// Run the col algorithm
		Element[] inside_r = scheme.col(td, h_r, m, m_prime);
		
		// Verfiy
		boolean flag = scheme.verfiy(keys[0], inside_r, m_prime, ID, h_r[0]);
		
		return flag;
	}
	
	public boolean testLSXD21(byte[] ID, byte[] m, byte[] m_prime) {
		
		LSXD21 scheme = new LSXD21();
		
		// Run the setup algorithm
		Map<String, Object>[] keys = scheme.setup();
		
		// Run the trapdoor algorithm
		Element[] td = scheme.keygen(keys[0], keys[1], ID);
		
		// Run the hash algorithm
		Element[] h_r = scheme.hash(keys[0], ID, m);
		
		// Run the col algorithm
		Element[] inside_r = scheme.col(td, h_r, m, m_prime);
		
		// Verfiy
		boolean flag = scheme.verfiy(keys[0], inside_r, m_prime, ID, h_r[0]);
		
		return flag;
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
	
	public static void main(String[] args) throws Exception {
		
		
		System.out.println("Please input the name of IB-CH scheme:");
		Scanner sc= new Scanner(System.in);
		String schemeName = sc.next();
		Test_IBCH test = new Test_IBCH();
		
		//Init ID, m and m'
		
		//Employ the SHA-256 hash function to fix the length of ID to be 256 bits 
		String ID = "1701116666";
		Hash H = new Hash("SHA-256");
		byte[] fixdlength_ID = H.hash(ID.getBytes());
		
		//Employ the SHA-512 hash function to fix the length of message to be 512 bits 
		Hash H_1 = new Hash("SHA-512");
		String m = "This is a test!";
		byte[] fixdlength_m = H_1.hash(m.getBytes());
		
		String m_prime = "This is not a test!";
		byte[] fixdlength_m_prime = H_1.hash(m_prime.getBytes());
		
		
		if (schemeName.equals("ZSNS03_One"))
			test.testZSNS03_One(fixdlength_ID, fixdlength_m, fixdlength_m_prime);
		else if (schemeName.equals("ZSNS03_Two"))
			test.testZSNS03_Two(fixdlength_ID, fixdlength_m, fixdlength_m_prime);
		else if (schemeName.equals("XSLD20"))
			test.testXSLD20(fixdlength_ID, fixdlength_m, fixdlength_m_prime);
		else if (schemeName.equals("LSXD21"))
			test.testLSXD21(fixdlength_ID, fixdlength_m, fixdlength_m_prime);
		else
			System.out.print("Valid Scheme!");
		
	  }	
}

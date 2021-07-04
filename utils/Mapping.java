package utils;

import java.util.StringTokenizer;

import abe.Attribute;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Mapping {

	private static Pairing pairing = PairingManager.getDefaultPairing();

	public static Element bytesToElement(byte[] targetBytes) {

		Element ele = pairing.getGT().newElementFromHash(targetBytes, 0, targetBytes.length);
		return ele;
	}

	public static Attribute[] strsToAttrs(String[] attributes) {

		Attribute[] attrs = new Attribute[attributes.length];

		for (int i = 0; i < attributes.length; i++) {
			StringTokenizer st = new StringTokenizer(attributes[i], ":");
			String name = st.nextToken().trim();
			String value = st.nextToken().trim();
			attrs[i] = new Attribute(name, value);
		}
		return attrs;
	}
}

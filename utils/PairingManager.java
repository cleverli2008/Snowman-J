package utils;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @ClassName: PairingManager
 * @Description: Create or obtain the pairing
 * @author:cleverli2008
 * @update:2021/11/26
 * @version: v1.0
 */

public class PairingManager {

	public static Pairing getDefaultPairing() {

//		Pairing pairing = PairingFactory.getPairing("curves/a.properties");
		Pairing pairing = PairingFactory.getPairing("curves/d224.properties");

		if (pairing != null) {
			return pairing;
		} else {
			System.out.println("pairing initialization error!");
			return null;
		}
	}
}

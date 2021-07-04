package abe;

public class Threshold{
	
		private Attribute[] setS;
		private int t;
		
		public Threshold(Attribute[] setS, int t) {
			this.setS = setS;
			this.t = t;
		}
		
		public Attribute[] getsetS() {
			return setS;
		}
		
		public int getTValue() {
			return t;
		}
		
}

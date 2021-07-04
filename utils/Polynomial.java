package utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Polynomial {
	
	private Pairing pairing = PairingFactory.getPairing("schemes/a.properties");
	
	private Element[] coefficient;
	private Element[] values;
	private int order;
	private int tlevel = 0;
	private Element tcoefficient = pairing.getZr().newOneElement().getImmutable();
	private int t_x = 0;     
	
	
	public Element[] computeCoefficient_opt(Element[] values){
		
//		long startTime = System.nanoTime();
		int order = values.length;
		Element[] coefficient = new Element[order+1];
		Element[] temp_coefficient = new Element[order];
		for(int i=0; i < order; i++) {
			coefficient[i] = pairing.getZr().newZeroElement().getImmutable();
			temp_coefficient[i] = coefficient[i].duplicate().getImmutable();
		}
		coefficient[order] = pairing.getZr().newZeroElement().getImmutable();
		
		coefficient[0] = values[0].duplicate().getImmutable(); 
		coefficient[1] = pairing.getZr().newOneElement().getImmutable();	
		for(int i = 1; i < order; i ++) {
			for(int j = i; j >= 0; j --) {
				coefficient[j+1] = coefficient[j].duplicate().getImmutable();
				temp_coefficient[j] = coefficient[j].mul(values[i]).getImmutable();			
			}
			coefficient[0] = pairing.getZr().newZeroElement().getImmutable();
			
			for(int j=0; j <= i; j++) {
				coefficient[j] = coefficient[j].add(temp_coefficient[j]).getImmutable();
				temp_coefficient[j] = pairing.getZr().newZeroElement().getImmutable();
			}			
		}
//		long endTime = System.nanoTime();
//		System.out.println(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");	
		return coefficient;
	}
	
	public Element[] computeCoefficient(Element[] values){
		
//		long startTime = System.nanoTime();
		this.values = values;
		this.order = values.length;
		this.coefficient = new Element[order+1];
		 for (int i = 0; i< order+1; i++) {
			 coefficient[i] = pairing.getZr().newZeroElement().getImmutable();
		  }
		this.recursion(true);
		this.recursion(false);
//		long endTime = System.nanoTime();
//		System.out.println(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");	
		return this.coefficient;
	}
		
	private void recursion(boolean flag) {
		
		 if(tlevel == this.order-1){
	            if (flag == true){
	            	coefficient[t_x+1] = coefficient[t_x+1].add(tcoefficient).getImmutable();
	            }else {
	            	coefficient[t_x] = coefficient[t_x].add(tcoefficient.mul(values[tlevel])).getImmutable();
	            }
	            return;
	        }	 
		 	tlevel++;
		 	
	        if(flag == true){
	        	t_x++;
	        	recursion(true);
	        	recursion(false);
	        	t_x--;
	        }else{
	        	tcoefficient = tcoefficient.mul(values[tlevel-1]).getImmutable();
	            recursion(true);
	            recursion(false);
	            tcoefficient = tcoefficient.div(values[tlevel-1]).getImmutable();
	        }
	        tlevel--;
	    }
	
	public Element Product(Element value, Element[] computeCoefficient) {
//		long startTime = System.nanoTime();
		int coeffs_length = computeCoefficient.length;
		Element sum = pairing.getZr().newZeroElement().getImmutable();
			for (int j = 0; j < coeffs_length; j++) {
				if(j != 0) {
					Element order = pairing.getZr().newElement(j).getImmutable();
					sum = sum.add(value.powZn(order).mul(computeCoefficient[j])).getImmutable();
				}
				else {
					sum = computeCoefficient[j].duplicate().getImmutable();
				}
			}
//		long endTime = System.nanoTime();
//		System.out.println(String.format("Product: "+"%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");	
	return sum;
}
	
	public boolean verify(Element[] values, Element[] computeCoefficient) {
			
		int order = values.length;
		Element sum = pairing.getZr().newZeroElement().getImmutable();
		for(int i = 0; i < order; i++) {
			for (int j = 0; j < order+1; j++) {
				if(j != 0) {
					Element temp = pairing.getZr().newElement(j).getImmutable();
					sum = sum.add(values[i].negate().powZn(temp).mul(computeCoefficient[j])).getImmutable();
				}
				else {
					sum = computeCoefficient[j].duplicate();
				}
			}
			if(!sum.isZero()) {
				return false;
			}
			else {
				System.out.println(i+"-th values is correct!");
			}
		}
		     return true;
	    }
		
	  public static void main(String[] args) {
		  Polynomial poly = new Polynomial();
		  Element[] values = new Element[500];
		  for (int i = 0; i< values.length; i++) {
			  values[i] = poly.pairing.getZr().newRandomElement().negate().getImmutable();
		  }
		  Element[] coeff = poly.computeCoefficient_opt(values);
		  for (Element a:
			  values) {
	            System.out.println(a);
	        }
	        int i=0;
	        for (Element a:coeff
	             ) {
	            System.out.println("The coefficient of X (order "+(i++)+") is :"+a);
	        }
	    	System.out.println(poly.verify(values, coeff));
	    	
	    	System.out.println(poly.Product(values[0], coeff));
	  }
}

package abe;

/*
 * author: licong
 */

public class Attribute {
	private String name;
	private String value;
	
	public Attribute(String name, String value){
		this.name = name;
		this.value = value;
	}
	
	public boolean equals(Object o){
		if(o == null){
			return false;
		}
		else if(!(o instanceof Attribute)){
			return false;
		}

		Attribute attr = (Attribute) o;
		return this.name.equals(attr.name) && this.value.equals(attr.value);
	}
	
	public int hashCode(){  
	     return (this.name +this.value).hashCode();  
	}  
	
	public String toString(){
		return this.name + ":" + this.value;
	}
 
    public String getAttrValue(){ 
    	return this.value;
    }

    public String getAttrName(){
    	return this.name;	
    	
    }

}

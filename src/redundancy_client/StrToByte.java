package redundancy_client;
/**
 * ��һ���ַ���(0��9,a��f)ת��byte��ʽ,���ڷ���.����������,���緢��"68040B000000"����wireshark�￴�����ľ���68040B000000
 * @author Z0034DCK
 *
 */
public class StrToByte {
	 public static byte[] strToByte(String s) {
		   String str = s;
		   str = str.toUpperCase();
		   int arr_len = (str.length()%2==0)?str.length()/2:str.length()/2 + 1;
		   char[] c = str.toCharArray();
		   byte[] b = new byte[arr_len];
		   if(str.length()%2==0){
			   for (int i = 0; i<str.length(); i+=2){
				   int pos = i/2;
				   b[pos] = (byte)(charToByte(c[i])<<4 | charToByte(c[i+1]));
			//	   System.out.println(b[pos]);
			   }
		   }
		   else{
			   for (int i = 0; i<str.length()-1; i+=2){
				   int pos = i/2;
				   b[pos] = (byte)(charToByte(c[i])<<4 | charToByte(c[i+1]));
			//	   System.out.println(b[pos]);
			   }
			   b[arr_len-1] = (byte)charToByte(c[str.length()-1]);
			//  System.out.println(b[arr_len-1]);
		   }
		  return b;		 
	   }
	    
	   private static byte charToByte(char c) {  
		   c = Character.toUpperCase(c);
	        return (byte) ("0123456789ABCDEF".indexOf(c));  
	    } 

}

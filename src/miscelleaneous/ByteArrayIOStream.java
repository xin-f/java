package miscelleaneous;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ByteArrayIOStream {
	public static void main(String args[]) throws IOException {
	      ByteArrayOutputStream bOutput = new ByteArrayOutputStream(12);
	      //д����,�Ӽ��������ַ�,д������. ��������ַ������ȵ�5ʱ,���ٽ����µ�����.
	      while( bOutput.size()!= 5 ) {
	         bOutput.write(System.in.read()); //�ѴӼ������������д��bOutput.
	      }
	      byte b [] = bOutput.toByteArray();//����������ݸ����ֽ�����.
	      for(int x= 0 ; x < b.length; x++) {
	         System.out.print((char)b[x]  + " "); 
	      }
	      System.out.print("\n" );
	      int c;
	      //һ��������,�Ѵ��ֽ�����b������ݶ����������
	      ByteArrayInputStream bInput = new ByteArrayInputStream(b);
	      for(int y = 0 ; y < 1; y++ ) {
	         while(( c= bInput.read())!= -1) {
	            System.out.print(Character.toUpperCase((char)c));
	         }
	         bInput.reset(); 
	      }
	   }

}

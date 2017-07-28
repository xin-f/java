package T104TimeSync;


public class TelegramClassify {
	
	public static boolean isU = false;
	public static boolean isI = false;
	public static boolean isS = false;
	public enum Type{isU,isI,isS};
	
	/**
	 * ���ֱ�����I,U ����S��ʽ��.
	 * @param args
	 */
	public static void distgUIS(String args) {
		Type type = null;
		type = distg(args);
		if (type == Type.isU){
			isU = true;
	//		System.out.println("isU");
			}
		if (type == Type.isI){
			isI = true;
	//		System.out.println("isI");
			}
		if (type == Type.isS){
			isS = true;
	//		System.out.println("isS");
			}
	}
	
	public static Type distg(String arg){
		Type type = null;
		int len = Integer.parseInt(arg.substring(2,4),16);
		int lns = Integer.parseInt(arg.substring(4,6),16);
		int mns = Integer.parseInt(arg.substring(6,8),16);
		int lnr = Integer.parseInt(arg.substring(8,10),16);
		int mnr = Integer.parseInt(arg.substring(10,12),16);
		if((len>4)&&(0 == (lns & 1))&&(0 == (lnr & 1))){
			type = Type.isI;
		}
		if((len == 4)&&(mns == 0)&&(3==(lns & 3))&&(mnr == 0)&&(0 == (lnr & 1))){
			type = Type.isU;
		}
		if((len == 4)&&(1==(lns & 3))&&(mns == 0)&&(0 == (lnr & 1))){
			type = Type.isS;
		}
		return type;
	}

}

class SplitTele{
	/**
	 * �ͻ���һ������,װ�ÿ��ܻظ�һ��������. ���,Ȼ��֡ �ŵ��ŷ�������.
	 * @param args
	 * @return
	 */
	public  static String[] splitTele(String args) { 
//	public static void main(String[] arg){
//		 String args = "68fa00000000251003000100ca0000000000000f4e00a104030100cb0000000000000f4e00a104030100cc0000000000000f4e00a104030100cd0000000000000f4e00a104030100c8000000000000104e00a204030100c9000000000000104e00a204030100ca000000000000104e00a204030100cb000000000000104e00a204030100cc000000000000104e00a204030100cd000000000000104e00a204030100c8000000000000114e00a304030100c9000000000000114e00a304030100ca000000000000114e00a304030100cb000000000000114e00a304030100cc000000000000114f00a304030100cd000000000000114f00a304030100686402000000250603000100c8000000000000124f00a404030100c9000000000000124f00a404030100ca000000000000124f00a404030100cb000000000000124f00a404030100cc000000000000125000a404030100cd000000000000125000a404030100681404000000670140000100000000a1e7a70323010068fa06000000251003000100c8000000000000134e00a504030100c9000000000000134e00a504030100ca000000000000134e00a504030100cb000000000000134e00a504030100cc000000000000134e00a504030100cd000000000000134e00a504030100c8000000000000144e00a604030100c9000000000000144e00a604030100ca000000000000144e00a604030100cb000000000000144e00a604030100cc000000000000144e00a604030100cd000000000000144e00a604030100c8000000000000154e00a704030100c9000000000000154e00a704030100ca000000000000154e00a704030100cb000000000000154e00a704030100688208000000250803000100cc000000000000154e00a704030100cd000000000000154e00a704030100c8000000000000164e00a804030100c9000000000000164e00a804030100ca000000000000164e00a804030100cb000000000000164e00a804030100cc000000000000164e00a804030100cd000000000000164e00a80403010068140a000000670140000100000000506cb10323010068140c000000670140000100000000e07db11623010068190e0000002401030001001300000100e44100dc4ca31703010068fa10000000251003000100ca000000000000064f00a417030100cb000000000000064f00a417030100cc000000000000064f00a417030100cd000000000000064f00a417030100c8000000000000074e00a517030100c9000000000000074e00a517030100ca000000000000074e00a517030100cb000000000000074e00a517030100cc000000000000074e00a517030100cd000000000000074e00a517030100c8000000000000084e00a617030100c9000000000000084e00a617030100ca000000000000084e00a617030100cb000000000000084e00a617030100cc000000000000084e00a617030100cd000000000000084e00a61703010068fa12000000251003000100c8000000000000094e00a717030100c9000000000000094e00a717030100ca000000000000094e00a717030100cb000000000000094e00a717030100cc000000000000094e00a717030100cd000000000000094e00a717030100c80000000000000a4e00a817030100c90000000000000a4e00a817030100ca0000000000000a4e00a817030100cb0000000000000a4e00a817030100cc0000000000000a4e00a817030100cd0000000000000a4e00a817030100c80000000000000b4e00a917030100c90000000000000b4e00a917030100ca0000000000000b4e00a917030100cb0000000000000b4e00a9170301006814140000006701400001000000009a8a9c00440100".toUpperCase();  
		 String str = args;
		 int len = 0;
		 int len_current = 0;
		//11���ַ�������. 11 �Ǽ���ֵ,��ʵֵҪ������while()��Ĵ�������ж�(n ��ֵ).������ʵֵ,Ҫ��while()֮���ٽ���һ��str. 
		 String[] bi = new String[11];
		 for (int i = 0; i<11;i++){bi[i] = null;}
		 int n = 0;	//����֡��
		 while((len = str.length())>=12){
			 String tmp = str.substring(2, 4);
			 len_current = Integer.parseInt(tmp, 16)*2+4;
			 if(! str.substring(0, 2).equals("68")){break;}
			 else if(   //  str.substring(0, 2).equals("68") 	&& 			//��68��ͷ. Ϊ��ֹ������������68,�������渨������.
					 //��������1,ֻ��һ֡,Ϊtrue,����һ֡(������һ֡),�������к�(LSB)���.
					 //����һ���㹻�������[2048]���ձ���,�����ı���ֻ��һ֡ʱ,����������ֵ����0,Ҫ�ٴ��ж�.					 
					 ((len == len_current)?(true):(str.substring(len_current+6,len_current+8).equals("00")?(true):str.substring(6, 8).equals(str.substring(len_current+6,len_current+8))))/*(str.substring(6, 8).equals(str.substring(len_current+6,len_current+8)))*/
					 //��������2,ֻ��һ֡,Ϊtrue,����һ֡(������һ֡),�������к�(LSB)��2.
					 &&( (len == len_current)?(true):(str.substring(len_current+6,len_current+8).equals("00")?(true):(Integer.parseInt(str.substring(4, 6),16) == Integer.parseInt(str.substring(len_current+4, len_current+6),16) - 2)))/*(Integer.parseInt(str.substring(4, 6),16) == Integer.parseInt(str.substring(len_current+4, len_current+6),16) - 2) */
					 ){
			 bi[n] = str.substring(0,len_current);
			 str = str.substring(len_current, len); //�޵��ʼ��һ֡.
		//	 System.out.println("bi["+n+"] "+bi[n]);
			 n++;
			 }
		/*	 else {
				 break;	//���鶨����㹻��ʱ,����Ķ���0, ������if()�������,str�����ü�,��ѭ��.
			 }		*/  
		 }
		 return bi;
	   }    

}

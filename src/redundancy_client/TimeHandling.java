package redundancy_client;
//һ���ļ��������һ��public��(����һ����û��), ���Ҵ�public��������ļ�����ͬ.û��public ��ʱ,�ļ�������һ����ͬ��.
//�κ�һ����������main������������һ��main�����е�������һ�����main��������main������class����һ������class.�����������Ὣclass�ֿ�

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

//68 14 �����ֽ�1 �����ֽ�2 �����ֽ�3 �����ֽ�4  67��ASDU�� 1����Ϣ�������06 00������ԭ�� addl addh 00 00 00����Ϣ���ַ��msl msh min hour day month year
 class TimeHandling {
	public static int year, month, day, hour, minute,second,msl,msh,ms;
	public static long millionsecond;
	public static String CUR_TIME;
	
	public static String getTime()  {
		String str,strh,strl = null;
		Calendar c = Calendar.getInstance();
		year = c.get(Calendar.YEAR)-2000;
		month = c.get(Calendar.MONTH)+1;
		day = c.get(Calendar.DATE);
		hour = c.get(Calendar.HOUR_OF_DAY);
		minute = c.get(Calendar.MINUTE);
		second = c.get(Calendar.SECOND);
		millionsecond = c.getTimeInMillis();
		str = Long.toString(millionsecond);
	//	System.out.println(c.getTime());
	//	System.out.println(hour);
		str=str.substring(str.length()-3, str.length());
	//	System.out.println(str);
		ms = Integer.parseInt(str)+second*1000;
		str = Integer.toHexString(ms);
		if(ms < 16){
			str = "000"+str;
		}else if(ms < 256){
			str = "00"+str;
		}
		else if(ms < 4096){
			str = "0"+str;
		}
	//	System.out.println(str);
		strl = str.substring(2, 4);
		strh = str.substring(0, 2);
		msl = Integer.parseInt(strl,16);
		msh = Integer.parseInt(strh,16);
	//	System.out.println("msh: "+msh);System.out.println("msl: "+msl);
	//	System.out.println(c.get(Calendar.ZONE_OFFSET));
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		CUR_TIME = df.format(c.getTime());
	return(CUR_TIME);
	}

}

//68 14 Ns1 Ns2 Nr3 Nr4  67��ASDU�� 1��no.��06 00��COT�� addl addh 00 00 00��IOA��msl msh min hour day month year
//��ʱ����ĵ�min �ֽ�,���λΪ0��Valid,�ڶ�λΪ0��Genuine time,��������Ϊ����; hour �ֽ����λΪ0�� SU ΪStandard time; day�ֽڸ���λΪdayOfWeek,�ɲ���.
//��ʱȷ�ϱ��ĵ�dayOfWeek�ᱻ��λ.
 class TimeFraming {
	
	public static int commadd;
	public static String comadd = "0100"; //������ַ�̶�Ϊ1
	
		public static String framing(){
		String str = null;
		TimeHandling.getTime();
		/*if(VisibleFrame.chkbx_SetTime == false){	//��ѡ��ûѡ��,��ϵͳʱ���ʱ
			str = "68140000000067010600"+getComaddr(VisibleFrame.comaddr)+"000000"+align(TimeHandling.msl)+align(TimeHandling.msh)
				+align(TimeHandling.minute)+align(TimeHandling.hour)+align(TimeHandling.day)+align(TimeHandling.month)+align(TimeHandling.year);
		}*/
//		else{			//�ֶ�����ʱ������ʱ.
			Date d = null;
			Calendar c = null;
			String timeModified = null;
			String timeInMs = null;
			String strl = null;
			String strh = null;
			String ms_str = null;
			int msl,msh;
			int ms = 0;
			int len_time = 0;
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			/*timeModified = TimeHandling.getTime();
			len_time = timeModified.length();
			try{
				d = sdf.parse(timeModified);
			}catch(ParseException pe){}*/
//			timeInMs = Long.toString(d.getTime());
			timeInMs = Long.toString(c.getInstance().getTimeInMillis());
			ms = Integer.parseInt(timeInMs.substring(timeInMs.length()-3, timeInMs.length())); //�����λ,С��1��Ĳ���,��������
			ms += (Integer.parseInt(timeInMs.substring(timeInMs.length()-5, timeInMs.length()-3)))*1000;//�����������Ĳ���,Ȼ���ú�������ʾ.
			ms_str = Integer.toHexString(ms);
			if(ms < 16){
				ms_str = "000"+ms_str;
			}else if(ms < 256){
				ms_str = "00"+ms_str;
			}
			else if(ms < 4096){
				ms_str = "0"+ms_str;
			}
			strl = ms_str.substring(2, 4);
			strh = ms_str.substring(0, 2);
			msl = Integer.parseInt(strl,16);
			msh = Integer.parseInt(strh,16);
			//timeModified "yyyy-MM-dd HH:mm:ss"
			timeModified = TimeHandling.getTime();
//			System.out.println(timeModified);
			len_time = timeModified.length();
			str = "68140000000067010600"+comadd+"000000"+align(msl)+align(msh)+align(Integer.parseInt(timeModified.substring(len_time-5, len_time-3)))
			+align(Integer.parseInt(timeModified.substring(len_time-8, len_time-6)))+align(Integer.parseInt(timeModified.substring(8, 10)))
			+align(Integer.parseInt(timeModified.substring(5, 7)))+align(Integer.parseInt(timeModified.substring(0, 4))-2000);
//		}
		return str;
	}
		
		public static String align(int i){
			String str = "";
			str = Integer.toHexString(i);
			if (i<16){
				str = "0"+str;
			//	System.out.println("������ʱ�ֺ��뵥�ֽ�ǰ��0");
			}
			return str;
		}
		
		public static String getComaddr(int arg){
		//	arg = VisibleFrame.comaddr;
			String str = Integer.toString(arg, 16);
			if (arg < 16) str = "000"+str;
			else if (arg < 256) str = "00"+str;
			else if (arg < 4096) str = "0"+str;
			return (str.substring(2, 4)+str.substring(0, 2));
			
		}

}
 
 
//681400000000670107000100000000D6D9B20C310411
//681400000000670107000100000000 D6D9 B2(1b of validity, 1b of Genuine time) 0C(1b of SU) 31(3b day of week) 04 11
//4/17/2017 12:51:10:072 Wed [Activation/Confirmation, Invalid, Genuine time, Standard time]
//VisibleFrame.updateTextArea("4/17/2017 12:51:10:072 [Activation, Invalid, Genuine time, Standard time]\n");
 class TimeParsing {
	/**
	 * ֻ��������ʱ�ӱ���. 
	 * @param arg
	 * @return
	 */
	public static String parsing(String arg){
//	public static void main(String[] args){
		String str = null;
		String Date = null;
		String Day = null;
		String dayOfWeek = null;
		String Time = null;
		String Year = null;
		String Month = null;
		String Second = null;
		String MillionSecond = null;
		String Hour = null;
		String Minute = null;
		String Cos = null;
		boolean invalid=false;boolean genuine=false;boolean summer = false;
		int dayofweek = 0;
		int day = 0; int hour = 0; int minute = 0; int ms = 0;
//		String arg = "681400000000670107000100000000D6D9F20CF70A11";
		int len = arg.length();
		Day= arg.substring(len - 6, len -4);
		dayofweek=Integer.parseInt(Day,16);
		dayofweek = dayofweek>>5;
		switch(dayofweek){
		case 0:
			dayOfWeek = "";break;
		case 1:
			dayOfWeek = "Mon";break;
		case 2:
			dayOfWeek = "Tue";break;
		case 3:
			dayOfWeek = "Wed";break;
		case 4:
			dayOfWeek = "Thu";break;
		case 5:
			dayOfWeek = "Fri";break;
		case 6:
			dayOfWeek = "Sat";break;
		case 7:
			dayOfWeek = "Sun";break;
		}
		Year = Integer.toString(Integer.parseInt(arg.substring(len-2, len), 16)+2000);	
		Month = Integer.toString(Integer.parseInt(arg.substring(len-4, len-2), 16));
		day = Integer.parseInt(Day, 16) & 31; //�����3λ,������5λ.
		Day = Integer.toString(day);
		str = "( "+ Month+"/"+Day+"/"+Year+" ";
		hour = Integer.parseInt(arg.substring(len-8, len-6), 16);		
		if((hour>>7)==1){
			summer = true;   //��һλ,0��ʾstandard time, 1 �ǲ��Ǳ�ʾsummer time??
		}
		hour &= 127;
		Hour = Integer.toString(hour);
		minute = Integer.parseInt(arg.substring(len-10, len-8), 16);
		if (0 != (minute & 128)){	//���λ,Ϊfalse��ʾ  valid
			invalid = true;
		}
		if (0 != (minute & 64)){	//�θ�λ,Ϊfalse��ʾ Genuine time
			genuine = true;
		}
		minute &= 63;				//�������λ.
		Minute = Integer.toString(minute);
		if(Minute.length()==1) Minute = "0"+Minute;
		MillionSecond = arg.substring(len-12, len-10) + arg.substring(len-14, len-12); 	//��Ӻ���һ��.
		ms = Integer.parseInt(MillionSecond, 16);
		Second = Integer.toString(ms/1000);
		if(Second.length()==1) Second = "0"+Second;
		MillionSecond = Integer.toString(ms%1000);		//ֻ�Ǻ���
		if(MillionSecond.length()==1) MillionSecond = "00"+MillionSecond;
		if(MillionSecond.length()==2) MillionSecond = "0"+MillionSecond;
		str = str + Hour + ":" + Minute +":" + Second + ":" + MillionSecond + " " + dayOfWeek;
		str += " [";
		//arg.substring(16, 18)�ĵ�6λ��ʾ����ԭ��,���λΪ1��ʾtest,�θ�λΪ1��ʾnegative. <10>������ֹ; <44>δ֪�����ͱ�ʶ;<45>δ֪�Ĵ���ԭ��;<46>δ֪��Ӧ�÷������ݵ�Ԫ������ַ;	<47>δ֪IOA

/*		if(arg.substring(16, 18).equals("06")){	
			str += "ACT,";
		}
		else if (arg.substring(16, 18).equals("07")){
			str += "CON,";
		}else if(arg.substring(16, 18).equals("10")){
			str += "ACT Termnt,";
		}else if(arg.substring(16, 18).equals("44")){
			str += "ACT Termnt,";
		}*/
		int cot = Integer.parseInt(arg.substring(16, 18), 16);
		if((cot & 128) == 128){
			str += "TEST,";
		}else if ((cot & 64) == 64){
			str += "NEG,";
		}else if (cot == 7){
			str += "CON,";
		}else if (cot == 6){
			str += "ACT,";
		}
		
		if(invalid){
			str += " Invalid,";
		}else{
			str += " Valid,";			
		}
		if(genuine){
			str += " None Gen time,";
		}else{
			str += " Genuine time,";
		}
		if(summer){
			str += " SU])";
		}else{
			str += " Standard time] )";
		}
		return (str);
		//VisibleFrame.updateTextArea("4/17/2017 12:51:10:072 [Activation, Invalid, Genuine time, Standard time]\n");
		//	return str;
	}

}

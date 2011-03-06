import jpcap.*;
import jpcap.packet.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
    
class Sniffer implements PacketReceiver {
    static int protocol; // chikka = 0, meebo = 1
    static JpcapCaptor jpcap;  
    FileWriter fw;
    

    public void receivePacket(Packet packet) {
        
        String data = new String(packet.data);
        String pack = new String(packet.toString());
        String B;
        
        Pattern pattern = null;
		Matcher matcher = null;
		
        if (protocol == 0){
           		if(data.indexOf("message")!=-1){
           		    System.out.println("-----------------------START------------------------");
           		    System.out.println(pack);
                    System.out.println(data);
           		    System.out.println("-----------------------END------------------------");
           		}
           		try {
					fw = new FileWriter("chikka/");
                    /*fw.append(this.getDateTime());
					fw.append(" SENDER: " + from + ": ");
					//fw.append("RECEIVER: " + r + "\n");
					fw.append(message + "\n");*/
				} catch (IOException e) {}   
       	}//end chikka
       	
       	else if(protocol ==1){

           	    if((data.indexOf("sender=")!=-1) ||
           	       ((data.indexOf("clientId=")!=-1) && (data.indexOf("GET")==-1))){
           	        System.out.println("-----------------------START------------------------");
               		System.out.println("SENT!!!"); 
               	    System.out.println(pack);
               	    System.out.println(data);
           	        System.out.println("-----------------------END--------------------------");  
           	    }
           	    if (data.startsWith("HTTP/1.1 200")&& (data.indexOf("sender")!=-1)){
               		System.out.println("-----------------------START------------------------");
               		System.out.println("RECEIVED!!!");
               	    System.out.println(data);
               	    
                    System.out.println("-----------------------END--------------------------");
                }
           		try {
					fw = new FileWriter("meebo/");
                    /*fw.append(this.getDateTime());
					fw.append(" SENDER: " + from + ": ");
					//fw.append("RECEIVER: " + r + "\n");
					fw.append(message + "\n");*/
				} catch (IOException e) {}   
       	}//end meebo
       	
       	else if(protocol ==2){
       	    if((data.indexOf("{\"msg\":{")!=-1)&&(data.indexOf("\"msgID\"")!=-1)&&(data.indexOf("\"from_name\"")!=-1)){
               	pattern = Pattern.compile("msgevents.+");
				matcher = pattern.matcher(data);
               		System.out.println("-----------------------START------------------------");
               	    //System.out.println(data);
               	    
               	    // from name
               	    int start = data.indexOf("\"from_name\"") + 13;
               	    int end = data.indexOf(",\"from_first_name\"") - 1;
               	    String from = data.substring(start, end);
                    // from id
               	    start = data.indexOf("\"from\":") + 7;
               	    end = data.indexOf(",\"to\":");
               	    String from_id = data.substring(start, end);

               	    //to name
               	    start = data.indexOf("to_name") + 10;
               	    end = data.indexOf("\",\"to_first_name");
               	    String to = data.substring(start, end);
               	    
               	    //to id
               	    start = data.indexOf(",\"to\":") + 6;
               	    end =  data.indexOf("\"from_name\"")-1;
               	    String to_id = data.substring(start, end);

                    //"session"
                    start = data.indexOf("(;;);{\"t\":\"msg\",\"c\":\"p_") + 23;
               	    end =  data.indexOf("\",\"s\":");
               	    String session = data.substring(start, end);
                    
               	    //message
               	    start = data.indexOf("{\"msg\":{\"text\":\"") +16;
               	    end = data.indexOf("\",\"time\"");
               	    String message = data.substring(start, end);
               	    
               	    System.out.println("Time: " + this.getDateTime());
               	    System.out.println("From: "+ from);
               	    System.out.println("To: "+to);
               	    System.out.println("Message: "+ message); 
               	    if (session.equals(from_id)){
               	        B = to_id;
               	    }
               	    else{
               	        B = from_id;
               	    }
               	        try {
					        fw = new FileWriter("facebook/" + session + "-" + B + ".txt", true);
                            fw.append(this.getDateTime());
					        fw.append(" " + from + ": ");
					        //fw.append("RECEIVER: " + r + "\n");
					        fw.append(message + "\n");
				        } 
        			    catch (IOException e) {} 
	                    try {
        	                fw.close();
	                    } catch (IOException e) {}  
                    System.out.println("-----------------------END--------------------------"); 
                    
           	          	  
       	    }
       	} //end facebook
       	
        
    }
    
    private String getDateTime() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();
        return dateFormat.format(date);
    }
    
    public static void main(String[] args) throws Exception {
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		if (args.length<2) {
			System.out.println("usage: sudo java Sniffer <select a number of desired device> <chikka or meebo>");
			for (int i = 0; i < devices.length; i++) {
				System.out.println(i + " :" + devices[i].name + "(" + devices[i].description + ")");
				System.out.println("    data link:" + devices[i].datalink_name + "(" + devices[i].datalink_description + ")");
				System.out.print("    MAC address:");
				for (byte b : devices[i].mac_address) {
					System.out.print(Integer.toHexString(b&0xff) + ":");
				}
				System.out.println();
				for (NetworkInterfaceAddress a : devices[i].addresses) {
					System.out.println("    address:"+a.address + " " + a.subnet + " " + a.broadcast);
				}
			}
		}
		else {
			jpcap = JpcapCaptor.openDevice(devices[Integer.parseInt(args[0])], 2000, true, 20);
			if (args[1].equals("chikka")) {
				jpcap.setFilter("host chikka.com", true);
				protocol = 0;
				//jpcap.setFilter("port 80", true);
				//File f = new File("meebo");
				//f.mkdir();
			}
			else if (args[1].equals("meebo")) {
   				protocol = 1;
				jpcap.setFilter("host meebo.com", true);   				
				//jpcap.setFilter("port 5050", true);
				//jpcap.setFilter("port 20", true);
				//File f = new File("ym");
				//f.mkdir();
			}
			else if(args[1].equals("fb")){
			    protocol = 2;
			    File f = new File("facebook");
				f.mkdir();
				//jpcap.setFilter("host facebook.com", true);   							    
			}
			/*
			else {
				System.err.println("Choose between meebo or ym.");
				System.exit(1);
			}*/
			jpcap.loopPacket(-1, new Sniffer());
		}
	}
}

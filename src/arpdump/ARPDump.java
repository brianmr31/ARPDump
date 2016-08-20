package arpdump;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
public class ARPDump {
    private static InputStream in = null;
    private static int status ;
    private static Pcap pcap ;
    private static String ofile = null; 
    private static PcapDumper dumper ;
    private static ByteBufferHandler<Pcap> data ;
    private static byte[] tmp ;
    private static List<PcapIf> alldevs = new ArrayList<PcapIf>();
    private static int r  ;
    private static int deviceid = -1;
    private static PcapIf device ;
    private static StringBuilder errbuf = new StringBuilder();
    private static File hadoop = null;
    private static FileWriter writeTxt = null;
    private static String Nm_Rpcap = null ;
    private static String Nm_Wpcap = null ;
    private static File setting = null ;
    private static Scanner input ;
    private static String Nm_Write ;
    private static String[] settings = new String[5];
    private static FileWriter fw= null;
    private static String Info = null ;
    private static String Protocol = null ;
    private static String ArpIpSrc = null ;
    private static String ArpIpDst = null ;
    private static String ArpMacSrc = null ;
    private static String ArpMacDst = null ;
    private static String MacSrc = null ;
    private static String MacDst = null ;
    private static int length = 0 ;
    private static int typeip[] = new int[2] ;
    private static InetAddress IPAddress ;   
    private static DatagramSocket clientSocket;  
    private static DatagramPacket sendPacket ;
    private static byte[] sendData  ;
    private static String sentence ;
    private static PcapBpfProgram program ;
    private static int snaplen = 64 * 2024;           
    private static int flags = Pcap.MODE_PROMISCUOUS; 
    private static int timeout = 1 * 10;   
    private static String date ;
    private static Date datereal;
    private static DateFormat dateFormat;
    static {
        try {
            System.load("/home/brian/NetBeansProjects/0_libJar/jnetpcap/libjnetpcap.so");
            System.load("//home/brian/NetBeansProjects/0_libJar/jnetpcap/libjnetpcap-pcap100.so");
        } catch (UnsatisfiedLinkError e) {
          System.err.println("Native code library failed to load.\n" + e);
          System.exit(1);
        }
    }
    public static String hex(byte n ) {
        return String.format("%.2s", Integer.toHexString(n & 0xFF));
    }
    public static void help(){
        System.out.println("========================= Help ======================");
        System.out.println("+ Syntax : ");
        System.out.println("+ java -jar DumpTA [option] ");
        System.out.println("+ [option] ");
        System.out.println("+ -h help ");
        System.out.println("+ -v jalankan dengan view log traffic ");
        System.out.println("+ -c check setting ");
        System.out.println("+ -b jalankan tanpa view log traffic ");
        System.out.println("+ -u ubah setting  ");
        System.out.println("+ [Example] ");
        System.out.println("+ java -jar DumpTA -b ");
        System.out.println("======================================================");
    }
    public ARPDump(){
        setting = new File("setting.txt") ;
    }
    public static boolean checkSetting(){
         setting = new File("setting.txt") ;
         if(setting.exists()){
             return true ;
         }else{
             return false ;
         }
    }
    public static void loadSetting(){
        setting = new File("setting.txt") ;
        if(setting.exists()){
            try (BufferedReader br = new BufferedReader(new FileReader(setting))) {
                int i = 0 ;
                String sCurrentLine;
                while ((sCurrentLine = br.readLine()) != null) {
                    settings[i] = sCurrentLine;
                    if(i==1){
                        deviceid = Integer.parseInt(settings[1]);
                    }else if(i==2){
                        ofile = settings[2];
                    }
                    i++;
                }
            } catch (IOException e) {
                    e.printStackTrace();
            } 
        }
        try {
            fw = new FileWriter(setting);
            fw.write(""+(Integer.parseInt(settings[0])+1)+"\n");
            fw.flush();
        } catch (IOException ex) {
            Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public static void rdSetting(){
        if(setting.exists()){
            try (BufferedReader br = new BufferedReader(new FileReader(setting))) {
                int i = 0 ;
                String sCurrentLine;
                while ((sCurrentLine = br.readLine()) != null) {
                    settings[i] = sCurrentLine;
                    if(i==1){
                        deviceid = Integer.parseInt(settings[1]);
                    }else if(i==2){
                        ofile = settings[2];
                    }
                    i++;
                }
            } catch (IOException e) {
                    e.printStackTrace();
            } 
        }else{
            try {
                setting.createNewFile();
                fw = new FileWriter(setting);
                fw.write("0"+"\n");
                fw.flush();
            } catch (IOException ex) {
                Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    public static void readSetting(){
        if(setting.exists()){
            try (BufferedReader br = new BufferedReader(new FileReader(setting))) {
                int i = 0 ;
                String sCurrentLine;
                System.out.println("--> Membaca Data Setting.txt");
                while ((sCurrentLine = br.readLine()) != null) {
                    settings[i] = sCurrentLine;
                    if(i == 0 ){
                        System.out.print("Jumlah file Dump : ");
                    }else if(i==1){
                        deviceid = Integer.parseInt(settings[1]);
                        System.out.print("Index interface  : ");
                    }else if(i==2){
                        ofile = settings[2];
                        System.out.print("Nama file Dump   : ");
                    }else if(i==3){
                        System.out.print("Ip Server        : ");
                    }else if(i==4){
                        System.out.print("Port Server      : ");
                    }
                    System.out.print(settings[i]+"\n");
                    i++;
                }
            } catch (IOException e) {
                    e.printStackTrace();
            } 
        }else{
            try {
                setting.createNewFile();
                fw = new FileWriter(setting);
                fw.write("0"+"\n");
                fw.flush();
                System.out.println("--> Membuat Data Setting.txt");
            } catch (IOException ex) {
                Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    public static void changesSetting(){
        loadSetting();
        r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
        System.out.println("Network devices found:");  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
                System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }  
        System.out.print("Enter a device in number: ");
        input = new Scanner(System.in);
        deviceid = input.nextInt();
        device = alldevs.get(deviceid);
        System.out.printf("\nChoosing '%s' on your behalf:\n",  
            (device.getDescription() != null) ? device.getDescription()  
                : device.getName());  
        System.out.print("Input Txt Write : ");
        input = new Scanner(System.in);
        ofile = input.nextLine();
        System.out.print("Input IP Address : ");
        input = new Scanner(System.in);
        settings[3] = input.nextLine();
        System.out.print("Input PORT Address : ");
        input = new Scanner(System.in);
        settings[4] = input.nextLine();
        try {
            fw.write(""+deviceid+"\n");
            fw.write(ofile+"\n");
            fw.write(settings[3]+"\n");
            fw.write(settings[4]+"\n");
            fw.flush();
        } catch (IOException ex) {
            Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public static void inputSettingDevices(){
        if(checkSetting()==false){
            readSetting();
        }else{
            loadSetting();
        }
        r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
        if(deviceid== -1){
            System.out.println("Network devices found:");  
        }
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            if(deviceid == -1){
                System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
            }
        }  
        if(deviceid == -1){
            System.out.print("Enter a device in number: ");
            input = new Scanner(System.in);
            deviceid = input.nextInt();
        }
        device = alldevs.get(deviceid); 
        if(deviceid == -1){
            System.out.printf("\nChoosing '%s' on your behalf:\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());  
        }
        if(ofile == null){
            System.out.print("Input Txt Write : ");
            input = new Scanner(System.in);
            ofile = input.nextLine();
        }
        if(settings[3] == null){
            System.out.print("Input IP Address : ");
            input = new Scanner(System.in);
            settings[3] = input.nextLine();
        }
        if(settings[4] == null){
            System.out.print("Input PORT Address : ");
            input = new Scanner(System.in);
            settings[4] = input.nextLine();
        }
        try {
            fw.write(""+deviceid+"\n");
            fw.write(ofile+"\n");
            fw.write(settings[3]+"\n");
            fw.write(settings[4]+"\n");
            fw.flush();
        } catch (IOException ex) {
            Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public static void OpenData(String fname){
        rdSetting();
        
        String ofile = "tmp-capture-file.cap";  
        PcapBpfProgram filter = new PcapBpfProgram();
        StringBuilder errbuf = new StringBuilder(); 
        Pcap pcap = Pcap.openOffline(fname, errbuf);  
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }
        try {
            IPAddress = InetAddress.getByName(settings[3]);
        } catch (UnknownHostException ex) {
            Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            clientSocket = new DatagramSocket() ;
        } catch (SocketException ex) {
            Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
        }
        pcap.compile(filter, "arp", 0, 0xFFFFFF00);
        pcap.setFilter(filter);
        dumper = pcap.dumpOpen(ofile);
        ByteBufferHandler<Pcap> d;
        d = new ByteBufferHandler<Pcap>() {
            
            @Override
            public void nextPacket(PcapHeader ph, ByteBuffer bb, Pcap t) {
                dumper.dump(ph, bb);
                byte[] b = new byte[bb.remaining()];
                bb.get(b,0,b.length);
                MacDst = hex(b[0])+":"+hex(b[1])+":"+hex(b[2])+":"+hex(b[3])+":"+hex(b[4])+":"+hex(b[5]);
                MacSrc = hex(b[6])+":"+hex(b[7])+":"+hex(b[8])+":"+hex(b[9])+":"+hex(b[10])+":"+hex(b[11]);
                length = b.length ;
                if(!hex(b[12]).equals("dd") && !hex(b[13]).equals("dd") ){
                    typeip[0] = Integer.parseInt(hex(b[12]));
                    typeip[1] = Integer.parseInt(hex(b[13])) ;
                    if(typeip[0] == 8 && typeip[1] == 6){
                        //System.out.println("ARP");
                        Protocol = "ARP" ;
                        if(hex(b[20]).equals("0") && hex(b[21]).equals("1")){
                            Info = "Request" ;
                            //System.out.println("Request");
                        }else if(hex(b[20]).equals("0") && hex(b[21]).equals("2")){
                            Info = "Reply" ;
                            //System.out.println("Reply");
                        }else {
                            Info = "Unknow" ;
                            //System.out.println("Unknow");
                        }
                        ArpMacSrc = hex(b[22])+":"+hex(b[23])+":"+hex(b[24])+":"+hex(b[25])+":"+hex(b[26])+":"+hex(b[27]) ;
                        ArpIpSrc  = Integer.parseInt(hex(b[28]), 16)+"."+Integer.parseInt(hex(b[29]), 16)+"."+Integer.parseInt(hex(b[30]), 16)+"."+Integer.parseInt(hex(b[31]), 16);
                        ArpMacDst = hex(b[32])+":"+hex(b[33])+":"+hex(b[34])+":"+hex(b[35])+":"+hex(b[36])+":"+hex(b[37]) ;
                        ArpIpDst  = Integer.parseInt(hex(b[38]), 16)+"."+Integer.parseInt(hex(b[39]), 16)+"."+Integer.parseInt(hex(b[40]), 16)+"."+Integer.parseInt(hex(b[41]), 16) ;
                    }
                }
                dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH:mm");
                datereal = new Date();
                date = dateFormat.format(datereal);
                sentence = date+";"+MacSrc+";"+MacDst+";"+String.valueOf(length)+";"+
                            ArpMacSrc+";"+ArpIpSrc+";"+ArpMacDst+";"+
                            ArpIpDst+";"+Protocol+";"+Info+";";
                sendData = sentence.getBytes();
                System.out.println(sentence);
                
                sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, Integer.parseInt(settings[4]));  
                try {  
                    clientSocket.send(sendPacket);
                } catch (IOException ex) {
                    Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        };
        pcap.loop(-1, d, pcap);
        clientSocket.close();
    }
    public static void DumpdataPcapOn(){
        if(checkSetting()==false){
            readSetting();
        }
                
        pcap =  
            Pcap.openLive(ARPDump.device.getName(), snaplen, flags, timeout, errbuf); 
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  
        program = new PcapBpfProgram();
        pcap.compile(program, "arp", 0, 0xFFFFFF00);
        pcap.setFilter(program);
        dumper = pcap.dumpOpen(ofile+settings[0]+".pcap");
        try {
            IPAddress = InetAddress.getByName(settings[3]);
        } catch (UnknownHostException ex) {
            Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            clientSocket = new DatagramSocket() ;
        } catch (SocketException ex) {
            Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
        }
        data = new ByteBufferHandler<Pcap>() {
            @Override
            public void nextPacket(PcapHeader ph, ByteBuffer bb, Pcap t) {
                dumper.dump(ph, bb);
                byte[] b = new byte[bb.remaining()];
                bb.get(b,0,b.length);
                MacDst = hex(b[0])+":"+hex(b[1])+":"+hex(b[2])+":"+hex(b[3])+":"+hex(b[4])+":"+hex(b[5]);
                MacSrc = hex(b[6])+":"+hex(b[7])+":"+hex(b[8])+":"+hex(b[9])+":"+hex(b[10])+":"+hex(b[11]);
                length = b.length ;
                if(!hex(b[12]).equals("dd") && !hex(b[13]).equals("dd") ){
                    typeip[0] = Integer.parseInt(hex(b[12]),16);
                    typeip[1] = Integer.parseInt(hex(b[13]),16);
                    if(typeip[0] == 8 && typeip[1] == 6){
                        Protocol = "ARP" ;
                        if(hex(b[20]).equals("0") && hex(b[21]).equals("1")){
                            Info = "Request" ;
                        }else if(hex(b[20]).equals("0") && hex(b[21]).equals("2")){
                            Info = "Reply" ;
                        }else {
                            Info = "Unknow" ;
                        }
                        ArpMacSrc = hex(b[22])+":"+hex(b[23])+":"+hex(b[24])+":"+hex(b[25])+":"+hex(b[26])+":"+hex(b[27]) ;
                        ArpIpSrc  = Integer.parseInt(hex(b[28]), 16)+"."+Integer.parseInt(hex(b[29]), 16)+"."+Integer.parseInt(hex(b[30]), 16)+"."+Integer.parseInt(hex(b[31]), 16);
                        ArpMacDst = hex(b[32])+":"+hex(b[33])+":"+hex(b[34])+":"+hex(b[35])+":"+hex(b[36])+":"+hex(b[37]) ;
                        ArpIpDst  = Integer.parseInt(hex(b[38]), 16)+"."+Integer.parseInt(hex(b[39]), 16)+"."+Integer.parseInt(hex(b[40]), 16)+"."+Integer.parseInt(hex(b[41]), 16) ;
                   }
                } 
                dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH:mm");
                datereal = new Date();
                date = dateFormat.format(datereal);
                sentence = date+";"+MacSrc+";"+MacDst+";"+String.valueOf(length)+";"+
                            ArpMacSrc+";"+ArpIpSrc+";"+ArpMacDst+";"+
                            ArpIpDst+";"+Protocol+";"+Info;
                sendData = sentence.getBytes();
                if(status == 1){
                    System.out.println(sentence+" "+sendData.length);
                }
                sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, Integer.parseInt(settings[4]));  
                try {  
                    clientSocket.send(sendPacket);
                } catch (IOException ex) {
                    Logger.getLogger(ARPDump.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        };
        pcap.loop(-1, data, pcap);  
        clientSocket.close();
    }
    public static void main(String[] args) {
        setting = new File("setting.txt") ;
        if(args[0].equals("-v")){
            inputSettingDevices();
            status = 1 ;
            System.out.println("--> Jalankan dengan view log traffic");
            DumpdataPcapOn();
        }else if(args[0].equals("-h")){
            help();
            System.exit(0);
        }else if(args[0].equals("-c")){
            System.out.println("--> Check Setting ");
            status = -1;
            readSetting();
            System.exit(0);
        }else if(args[0].equals("-b")){
            inputSettingDevices();
            status = 0 ;
            System.out.println("--> Jalankan tanpa view log traffic");
            DumpdataPcapOn();
        }else if(args[0].equals("-u")){
            System.out.println("--> Ubah Setting");
            changesSetting();
        }else if(args[0].equals("-o")){
            System.out.println("--> Buka File Dump");
            OpenData(args[1]);
            System.exit(0);
        }else{
            System.out.println("--> ERROR SYSNTAX");
            help();
            System.exit(0);
        }
        
    }
    
}

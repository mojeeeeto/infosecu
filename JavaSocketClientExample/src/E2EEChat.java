import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.util.Arrays;
import java.util.Base64;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class E2EEChat
{
    private Socket clientSocket = null;

    public Socket getSocketContext() {
        return clientSocket;
    }

    // 접속 정보, 필요시 수정
    private final String hostname = "homework.islab.work";
    private final int port = 8080;

    public E2EEChat() throws IOException {
       clientSocket = new Socket();
       clientSocket.connect(new InetSocketAddress(hostname, port));
       InputStream stream = clientSocket.getInputStream();
       Thread senderThread = new Thread(new MessageSender(this));
       senderThread.start();
       while (true) {
           try {
               if (clientSocket.isClosed() || !senderThread.isAlive()) {
                   break;
               }

               byte[] recvBytes = new byte[2048];
               int recvSize = stream.read(recvBytes);

               if (recvSize == 0) {
                   continue;
               }

               String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);
               
               parseReceiveData(recv);
           } catch (IOException ex) {
               System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
               break;
           }
       }

       try {
           System.out.println("입력 스레드가 종료될때까지 대기중...");
           senderThread.join();

           if (clientSocket.isConnected()) {
               clientSocket.close();
           }
       } catch (InterruptedException ex) {
           System.out.println("종료되었습니다.");
       }
    }

    public void parseReceiveData(String recvData) {
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.
        System.out.println(recvData + "\n==== recv ====\n");
    }
   
    // 필요한 경우 추가로 메서드를 정의하여 사용합니다.

    
    public static void main(String[] args)
    {
    	
        try {
            new E2EEChat();
        } catch (UnknownHostException ex) {
            System.out.println("연결 실패, 호스트 정보를 확인하세요.");
        } catch (IOException ex) {
            System.out.println("소켓 통신 중 문제가 발생하였습니다.");
        }
    }
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class MessageSender implements Runnable {
    E2EEChat clientContext;
    OutputStream socketOutputStream;
    static String key ="";
    static String iv ="";
    public MessageSender(E2EEChat context) throws IOException {
        clientContext = context;

        Socket clientSocket = clientContext.getSocketContext();
        socketOutputStream = clientSocket.getOutputStream();
    }

    @Override
    public void run() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            try {            
                System.out.println("Select: CONNECT, DISCONNECT, KEYXCHG, KEYCHGRST, MSGSEND");
                System.out.println("key: "+key);
                
                
                String input1 = scanner.nextLine().trim();
                input1 = input1.toLowerCase();
                String credential,from,to,nonce,message,text = "";
                switch (input1) {
                case "connect":
                	System.out.print("Credential: ");
                	credential = scanner.nextLine().trim();
                	message = "3EPROTO CONNECT\n Credential: "+credential;
                	break;
                case "disconnect":
                	System.out.print("Credential: ");
                	credential = scanner.nextLine().trim();
                	message = "3EPROTO DISCONNECT\n Credential: "+credential;
                	break;
                case "keyxchg":
                	System.out.print("from: ");
                	from = scanner.nextLine().trim();
                	System.out.print("To: ");
                	to = scanner.nextLine().trim();
                	System.out.print("key: ");
                	key = scanner.nextLine().trim();
                	System.out.print("iv: ");
                	iv = scanner.nextLine().trim();
                	message = "3EPROTO KEYXCHG\nAlgo: AES-256-CBC\n From: "+from+"\nTo: "+to+"\n"+key+"\n"+iv;
                	break;
                case "keychgrst":
                	System.out.print("from: ");
                	from = scanner.nextLine().trim();
                	System.out.print("To: ");
                	to = scanner.nextLine().trim();
                	System.out.print("key: ");
                	key = createrandomstring(256);
                	System.out.print("iv: ");
                	iv = createrandomstring(128);
                	message = "3EPROTO KEYXCHG\nAlgo: AES-256-CBC\n From: "+from+"\nTo: "+to+"\n"+key+"\n"+iv;
                	break;
                case "msgsend":
                	System.out.print("from: ");
                	from = scanner.nextLine().trim();
                	System.out.print("To: ");
                	to = scanner.nextLine().trim();
                	nonce = createrandomstring(30);
                	System.out.print("text: ");
                	text = scanner.nextLine().trim();
                	text = AES_Encode(text);
                	message = "3EPROTO MSGSEND\nFrom: "+from+"\nTo: "+to+"\nnonce: "+nonce+"\ntext: "+text;
                	break;
                default:
                	message="";
                	break;
                }
                
                byte[] payload = message.getBytes(StandardCharsets.UTF_8);
                
                socketOutputStream.write(payload, 0, payload.length);  
            } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
                break;
            }
        }
       
        System.out.println("MessageSender runnable end");
    }
    public static String AES_Encode(String str) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        byte[] keyData = key.getBytes();
        SecretKey secureKey = new SecretKeySpec(keyData, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, secureKey, new IvParameterSpec(iv.getBytes()));
        byte[] encrypted = c.doFinal(str.getBytes("UTF-8"));
        String enStr = Base64.getEncoder().encodeToString(encrypted);
        return enStr;
    }
  
	private String createrandomstring(int length) {
    	final byte[] arr = new byte[length];
    	new SecureRandom().nextBytes(arr);
    	final String nonce = new String(java.util.Base64.getUrlEncoder().withoutPadding().encode(arr), StandardCharsets.UTF_8);
    	Arrays.fill(arr, (byte)0);
    	return nonce;
	}
}
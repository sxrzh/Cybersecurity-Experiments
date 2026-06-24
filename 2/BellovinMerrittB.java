// 服务端进程 B

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class BellovinMerrittB {
	private static String shortPassword = "passwordqwerty";		// 事先共享的口令 pw

	public static void main(String[] args) throws Exception {
		System.out.println("Server B started.");
		try(ServerSocket serverSocket = new ServerSocket(1234)) {		// 通过 sokcet 与 A 通信
			try(Socket clientSocket = serverSocket.accept()) {
				BufferedReader in = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream(), "UTF-8"));
                PrintWriter out = new PrintWriter(
                    new OutputStreamWriter(clientSocket.getOutputStream(), "UTF-8"), true);
				
				// 根据 pw 生成 AES 密钥
				SecretKey aesKey = CryptoUtils.generateAesKeyFromPassword(shortPassword, 256 / 8);

				// 接收 A, E0(pw, pkA)
				String username = in.readLine();	
				System.out.println("Username: " + username);
				byte[] aesNonce = Base64.getDecoder().decode(in.readLine());

				// 解密 pkA
				byte[] pkAbytes = CryptoUtils.decryptBytes(Base64.getDecoder().decode(in.readLine()), aesKey, aesNonce, CryptoUtils.AlgorithmAES);
				PublicKey pkA = CryptoUtils.bytesToPublicKey(pkAbytes);

				// 随机生成 Ks
				KeyGenerator desKeyGen = KeyGenerator.getInstance("DES");
				desKeyGen.init(56);
				SecretKey desKey = desKeyGen.generateKey();		// Ks
				byte[] desKeyRSAEncrypted = CryptoUtils.encryptRSA(desKey.getEncoded(), pkA);

				// 传输 E0(pw, E(pkA, Ks))
				aesNonce = CryptoUtils.generateIv(12);	// 必须重新生成 aesNonce
				out.println(Base64.getEncoder().encodeToString(aesNonce));
				out.println(Base64.getEncoder().encodeToString(CryptoUtils.encryptBytes(desKeyRSAEncrypted, aesKey, aesNonce, CryptoUtils.AlgorithmAES)));
			
				SecureRandom secureRandom = new SecureRandom();

				// 接收 E1(Ks, NA)
				byte[] desIv = Base64.getDecoder().decode(in.readLine());
				byte[] NaEncrypted = Base64.getDecoder().decode(in.readLine());
				BigInteger NA = new BigInteger(1, CryptoUtils.decryptBytes(NaEncrypted, desKey, desIv, CryptoUtils.AlgorithmDES));	// 解密 NA

				// 随机生成 NB 并拼接 NA||NB
				BigInteger NB = new BigInteger(2048, secureRandom);
				BigInteger NAB = BigInteger.ONE.shiftLeft(2048).multiply(NA).add(NB);
				
				// 传输 E1(Ks, NA||NB)
				desIv = CryptoUtils.generateIv(8);
				out.println(Base64.getEncoder().encodeToString(desIv));
				out.println(Base64.getEncoder().encodeToString(CryptoUtils.encryptBytes(NAB.toByteArray(), desKey, desIv, CryptoUtils.AlgorithmDES)));
				
				// 接收 E1(Ks, NB)
				desIv = Base64.getDecoder().decode(in.readLine());
				BigInteger receivedNB = new BigInteger(1, CryptoUtils.decryptBytes(Base64.getDecoder().decode(in.readLine()), desKey, desIv, CryptoUtils.AlgorithmDES));
				if(receivedNB.equals(NB)) {		// 验证解密出的 NB
					// 判断对方确实是 A，得到共享对称式密钥 Ks
					System.out.println("NB matches. A is verified!");
					System.out.println("Ks = " + Base64.getEncoder().encodeToString(desKey.getEncoded()));
				}
				else {
					System.err.println("Error: NB does not match!");
				}
			}
			catch (Exception e) {
				// 等待随机时间，防止侧信道攻击
				Thread.sleep(50 + new SecureRandom().nextInt(200));
				System.err.println("Server B: Wrong password or tampering detected");
			}
		}
		catch (IOException e) {
			System.err.println("Server B: Port Error");
			e.printStackTrace();
		}
	}
}
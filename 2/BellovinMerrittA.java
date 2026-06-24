// 客户端进程 A

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import java.util.Base64;
import java.util.Scanner;

public class BellovinMerrittA {
	private static String username = "ClientA";
	private static String shortPassword;
	
	public static void main(String[] args) throws Exception {
		System.out.println("Client A started.");
		try(Socket socket = new Socket("localhost", 1234)) {	// 通过 socket 与 B 通信
			PrintWriter out = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);
			BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), "UTF-8"));

			// 输入短口令 pw，此处为了演示方便会显示输入的密码
			// 实际应用中应该使用 readPassword 输入
			System.out.print("Password: ");
			Scanner scanner = new Scanner(System.in);
			shortPassword = scanner.nextLine();
			scanner.close();

			// 生成密钥对 (pkA, skA)
			KeyPair rsaKey = CryptoUtils.generateKeyPair(2048);
			
			// 根据 pw 生成 AES 密钥
			SecretKey aesKey = CryptoUtils.generateAesKeyFromPassword(shortPassword, 256 / 8);
			byte[] pkA = rsaKey.getPublic().getEncoded();
			
			// 传输 A, E0(pw, pkA)
			byte[] aesNonce = CryptoUtils.generateIv(12);
			out.println(username);
			out.println(Base64.getEncoder().encodeToString(aesNonce));
			out.println(Base64.getEncoder().encodeToString(CryptoUtils.encryptBytes(pkA, aesKey, aesNonce, CryptoUtils.AlgorithmAES)));

			// 接收 E0(pw, E(pkA, Ks))
			aesNonce = Base64.getDecoder().decode(in.readLine());
			byte[] desKeyEncryptedAES = Base64.getDecoder().decode(in.readLine());
			byte[] desKeyEncryptedRSA = CryptoUtils.decryptBytes(desKeyEncryptedAES, aesKey, aesNonce, CryptoUtils.AlgorithmAES);
			byte[] desKeyBytes = CryptoUtils.decryptRSA(desKeyEncryptedRSA, rsaKey.getPrivate());	// 解密得到 Ks
			SecretKey desKey = new SecretKeySpec(desKeyBytes, "DES");		// Ks
			
			// 随机生成 NA
			SecureRandom secureRandom = new SecureRandom();
			byte[] desIv = CryptoUtils.generateIv(8);
			BigInteger NA = new BigInteger(2048, secureRandom);
			// 传输 E1(Ks, NA)
			out.println(Base64.getEncoder().encodeToString(desIv));
			out.println(Base64.getEncoder().encodeToString(CryptoUtils.encryptBytes(NA.toByteArray(), desKey, desIv, CryptoUtils.AlgorithmDES)));

			// 接收 E1(Ks, NA||NB)
			desIv = Base64.getDecoder().decode(in.readLine());
			byte[] NabEncrypted = Base64.getDecoder().decode(in.readLine());
			BigInteger NAB = new BigInteger(1, CryptoUtils.decryptBytes(NabEncrypted, desKey, desIv, CryptoUtils.AlgorithmDES));
			BigInteger[] nums = NAB.divideAndRemainder(BigInteger.ONE.shiftLeft(2048));
			// 解密得到 NB
			BigInteger NB = nums[1];
			BigInteger receivedNA = nums[0];

			if(receivedNA.equals(NA)) {		// 验证解密出的 NA
				System.out.println("NA matches. B is verified!");
				// 传输 E1(Ks, NB)
				desIv = CryptoUtils.generateIv(8);
				out.println(Base64.getEncoder().encodeToString(desIv));
				out.println(Base64.getEncoder().encodeToString(CryptoUtils.encryptBytes(NB.toByteArray(), desKey, desIv, CryptoUtils.AlgorithmDES)));
				// 判断对方确实是 B，得到共享对称式密钥 Ks
				System.out.println("Ks = " + Base64.getEncoder().encodeToString(desKey.getEncoded()));
			}
			else {
				System.err.println("Error: NA does not match!");
			}
		}
		catch (IOException e) {
			System.err.println("Client A: Port connection failed!");
		}
	}
}

// 密码学相关函数

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import java.util.Base64;
import java.util.Scanner;

public class CryptoUtils {
	public static final String AlgorithmAES = "AES/GCM/NoPadding";	// AES，使用 GCM 可以进行完整性校验，防止 Padding Oracle 攻击
	public static final String AlgorithmDES = "DES/CBC/PKCS5Padding";	// DES 不支持 GCM
	public static final String AlgorithmRSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(keySize);
		return kpGen.generateKeyPair();
	}

	public static SecretKey generateAesKeyFromPassword(String password, int keyLengthBytes)
            throws NoSuchAlgorithmException {
		// 根据短口令生成 AES 密钥
		String base64 = java.util.Base64.getEncoder().encodeToString(password.getBytes());
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(base64.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] keyBytes = new byte[keyLengthBytes];
		System.arraycopy(hash, 0, keyBytes, 0, keyLengthBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

	public static PublicKey bytesToPublicKey(byte[] keyBytes) 
            throws Exception {
		// X509 格式的 byte[] 转换为 RSA 公钥
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

	public static byte[] generateIv(int sizeIv) {
		// 生成 GCM、CBC 需要的 IV
        byte[] iv = new byte[sizeIv];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

	public static byte[] encryptBytes(byte[] plainBytes, SecretKey key, byte[] iv, String Algorithm) throws Exception {
		// AES/DES 加密
        Cipher cipher = Cipher.getInstance(Algorithm);
        if (Algorithm == AlgorithmAES) {
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        }
        return cipher.doFinal(plainBytes);
    }

    public static byte[] decryptBytes(byte[] cipherBytes, SecretKey key, byte[] iv, String Algorithm) throws Exception {
		// AES/DES 解密
        Cipher cipher = Cipher.getInstance(Algorithm);
        if (Algorithm == AlgorithmAES) {
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        }
        return cipher.doFinal(cipherBytes);
    }
	
	public static byte[] encryptRSA(byte[] plainBytes, PublicKey publicKey) throws Exception {
		// RSA 加密
        Cipher cipher = Cipher.getInstance(AlgorithmRSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainBytes);
    }
	
    public static byte[] decryptRSA(byte[] encryptedBytes, PrivateKey privateKey) throws Exception {
		// RSA 解密
        Cipher cipher = Cipher.getInstance(AlgorithmRSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedBytes);
    }
}
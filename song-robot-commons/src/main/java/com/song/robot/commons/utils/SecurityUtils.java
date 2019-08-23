package com.song.robot.commons.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;

/**
 * 加密工具类
 */
public class SecurityUtils {

    /**
     * MD5
     */
    public static final String MD5 = "MD5";
    /**
     * SHA1
     */
    public static final String SHA1 = "SHA-1";
    /**
     * SHA256
     */
    public static final String SHA256 = "SHA-256";
    /**
     * DES
     */
    public static final String DES = "DES";
    /**
     * 3重DES
     */
    public static final String DESEDE = "DESEde";
    /**
     * AES
     */
    public static final String AES = "AES";
    /**
     * PBE
     */
    public static final String PBE = "PBEWITHMD5andDES";

    /**
     * 十六进制
     */
    private static final char[] HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


    /**
     * base64加密算法
     */


    /**
     * md5、sha、sha256摘要算法
     */
    public static String encrypt(String algorithm, byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(bytes);
        return bytesToHex(messageDigest.digest());
    }

    /**
     * md5、sha、sha256摘要算法
     */
    public static String encrypt(String algorithm, File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        try (FileInputStream fileInputStream = new FileInputStream(file); DigestInputStream digestInputStream = new DigestInputStream(fileInputStream, messageDigest)) {
            byte[] buffer = new byte[Integer.valueOf(131072)];//TODO 硬编码
            while (true) {
                if (digestInputStream.read(buffer) <= 0) {
                    break;
                }
            }
            return bytesToHex(digestInputStream.getMessageDigest().digest());
        }
    }

    public static String encry(String securityStr,String keyStr,String encryptType) throws Exception {
        return enorde(securityStr,keyStr,encryptType,Cipher.ENCRYPT_MODE);
    }

    public static String decode(String securityStr,String keyStr,String encryptType) throws Exception {
        return enorde(securityStr,keyStr,encryptType,Cipher.ENCRYPT_MODE);
    }

    /**
     * DES、3重DES、AES和PBE对称加密 (对称加密指加密和解密使用相同密钥的加密算法。)
     */
    public static String enorde(String securityStr,String keyStr,String encryptType,int mode)throws Exception{
        SecureRandom random = new SecureRandom();
        DESKeySpec desKey = new DESKeySpec(keyStr.getBytes());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptType);
        SecretKey securekey = keyFactory.generateSecret(desKey);
        Cipher cipher = Cipher.getInstance(encryptType);
        cipher.init(mode, securekey, random);
        return new String(cipher.doFinal(securityStr.getBytes()));
    }





//    public static void DES(String secutiryStr) throws Exception{
//        //1.生成KEY
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");//Key的生成器
////        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");//Key的生成器
//        keyGenerator.init(56);
//        SecretKey secretKey = keyGenerator.generateKey();
//        byte[] bytesKey = secretKey.getEncoded();
//
//        //2.KEY转换
//        DESKeySpec desKeySpec = new DESKeySpec(bytesKey);//实例化DESKey秘钥的相关内容
//        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");//实例一个秘钥工厂，指定加密方式
//        Key convertSecretKey = factory.generateSecret(desKeySpec);
//
//        //3.加密    DES/ECB/PKCS5Padding--->算法/工作方式/填充方式
//        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");//通过Cipher这个类进行加解密相关操作
//        cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
//        byte[] result = cipher.doFinal(secutiryStr.getBytes());//输入要加密的内容
//
//        //4.解密
//        cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
//        result = cipher.doFinal(result);
//
//    }
//
//    public static void jdkThreeDES() {
//        try {
//            //1.生成KEY
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESEde");
////			keyGenerator.init(168);
//            keyGenerator.init(new SecureRandom());
//            SecretKey secretKey = keyGenerator.generateKey();
//            byte[] bytesKey = secretKey.getEncoded();
//
//            //2.转换KEY
//            DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(bytesKey);
//            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESEde");
//            Key convertKey = factory.generateSecret(deSedeKeySpec);
//
//            //3.加密
//            Cipher cipher = Cipher.getInstance("DESEde/ECB/PKCS5Padding");
//            cipher.init(Cipher.ENCRYPT_MODE, convertKey);
//            byte[] result = cipher.doFinal(password.getBytes());
//            System.out.println("加密后：" + Hex.encodeHexString(result));
//
//            //4.解密
//            cipher.init(Cipher.DECRYPT_MODE, convertKey);
//            result = cipher.doFinal(result);
//            System.out.println("解密后：" + new String(result));
//        } catch (Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//    }
//
//    public static void jdkAES() {
//        try {
//            //1.生成KEY
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//            keyGenerator.init(new SecureRandom());
//            SecretKey secretKey = keyGenerator.generateKey();
//            byte[] byteKey = secretKey.getEncoded();
//
//            //2.转换KEY
//            Key key = new SecretKeySpec(byteKey,"AES");
//
//            //3.加密
//            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
//            cipher.init(Cipher.ENCRYPT_MODE, key);
//            byte[] result = cipher.doFinal(password.getBytes());
//            System.out.println("加密后：" + Hex.encodeHexString(result));
//
//            //4.解密
//            cipher.init(Cipher.DECRYPT_MODE, key);
//            result = cipher.doFinal(result);
//            System.out.println("解密后：" + new String(result));
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//
//    public static void jdkPBE() {
//        try {
//            //1. 初始化盐
//            SecureRandom secureRandom = new SecureRandom();
//            byte[] salt = secureRandom.generateSeed(8);
//
//
//            //2. 口令与秘钥
//            //2.1 定义密码
//            String password = "NELSON";//这个是加密用的口令
//            //2.2 把密码转换成秘钥
//            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
//            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
//            Key key = factory.generateSecret(pbeKeySpec);
//
//            //3. 加密
//            PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, 100);//100是你选择迭代的次数
//            Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
//            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
//            byte[] result = cipher.doFinal(src.getBytes());
//            System.out.println("加密后：" + Hex.encodeHexString(result));
//
//            //4.解密
//            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
//            result = cipher.doFinal(result);
//            System.out.println("解密后：" + new String(result));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//    }
//
//
//
//

    /**
     * 将字节数组转换成16进制字符串
     */
    public static String bytesToHex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            chars[i << 1] = HEX[b >>> 4 & 0xf];
            chars[(i << 1) + 1] = HEX[b & 0xf];
        }
        return new String(chars);
    }
}

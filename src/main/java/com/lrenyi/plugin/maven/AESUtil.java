package com.lrenyi.plugin.maven;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
    private static final String ALG_AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
    
    public byte[] encryption(byte[] aesKey, byte[] aesIv, byte[] classData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALG_AES_CBC_PKCS5);
        SecretKeySpec skeySpec = new SecretKeySpec(aesKey, ALG_AES_CBC_PKCS5.split("/")[0]);
        IvParameterSpec iv = new IvParameterSpec(aesIv);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        return cipher.doFinal(classData);
    }
    
    public byte[] decrypt(byte[] aesKey, byte[] aesIv, byte[] classData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALG_AES_CBC_PKCS5);
        // step 2 初始化密码器，指定是加密还是解密(Cipher.DECRYPT_MODE 解密; Cipher.ENCRYPT_MODE 加密)
        // 加密时使用的盐来够造秘钥对象
        SecretKeySpec skeySpec = new SecretKeySpec(aesKey, ALG_AES_CBC_PKCS5.split("/")[0]);
        // 加密时使用的向量，16位字符串
        IvParameterSpec iv = new IvParameterSpec(aesIv);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        // 解密后的报文数组
        return cipher.doFinal(classData);
    }
}

package org.yueweb3j.crypto.sm;


import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.yueweb3j.crypto.Hash;

import java.io.*;
import java.security.Security;

public class SM3Util {

    private volatile static SM3Util sm3Util;

    private SM3Util() {
    }

    public static SM3Util getInstance() {
        if (sm3Util == null) {
            synchronized (SM3Util.class) {
                if (sm3Util == null) {
                    sm3Util = new SM3Util();
                }
            }
        }
        return sm3Util;
    }

    /**
     * 指定key杂凑
     *
     * @param key key 十六进制编码
     * @param msg 待加密的数据
     * @return 十六进制编码
     */
    public static String SM3Hash(String key, String msg) throws DecoderException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] dataByte = msg.getBytes();
        byte[] keyByte = Hex.decode(key);
        KeyParameter keyParameter = new KeyParameter(keyByte);
        SM3Digest sm3Digest = new SM3Digest();
        HMac hMac = new HMac(sm3Digest);
        hMac.init(keyParameter);
        hMac.update(dataByte, 0, dataByte.length);
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result, 0);
        return Hex.toHexString(result);
    }

    /**
     * 不指定key杂凑
     *
     * @param msg 待加密的数据
     * @return 十六进制编码
     */
    public static String SM3Hash(String msg) {
        Security.addProvider(new BouncyCastleProvider());
        byte[] dataByte = msg.getBytes();
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(dataByte, 0, dataByte.length);
        byte[] result = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(result, 0);
        return Hex.toHexString(result);
    }

    /**
     * 文件摘要
     *
     * @param filepath
     * @return
     */
    public static String SM3HashFile(String filepath) {
        FileUtils fileUtil = FileUtils.getInstance();
        byte[] dataByte = fileUtil.FileToByte(new File(filepath));
        if (dataByte == null) {
            // 文件读取失败
            return null;
        }
        Security.addProvider(new BouncyCastleProvider());
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(dataByte, 0, dataByte.length);
        byte[] result = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(result, 0);
        return Hex.toHexString(result);
    }


    public static void main(String[] args) throws DecoderException {
        System.out.println(Hex.toHexString("123456".getBytes()));
        System.out.println(SM3Hash("1234567812345678", "abc"));
        System.out.println(SM3Hash("1234"));
    }

}
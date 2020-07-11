package org.yueweb3j.crypto.sm;


import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.yueweb3j.crypto.Credentials;
import org.yueweb3j.crypto.Hash;
import org.yueweb3j.crypto.Sign;
import org.yueweb3j.crypto.sm.interfaces.Sm2PrivateKey;
import org.yueweb3j.crypto.sm.interfaces.impl.Sm2PrivateKeyImpl;
import org.yueweb3j.crypto.sm.util.Sm2Util;
import org.yueweb3j.utils.Numeric;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

/**
 * need jars:
 * bcpkix-jdk15on-160.jar
 * bcprov-jdk15on-160.jar
 * <p>
 * ref:
 * https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 * http://gmssl.org/docs/oid.html
 * http://www.jonllen.com/jonllen/work/164.aspx
 * <p>
 * 用BC的注意点：
 * 这个版本的BC对SM3withSM2的结果为asn1格式的r和s，如果需要直接拼接的r||s需要自己转换。下面rsAsn1ToPlainByteArray、rsPlainByteArrayToAsn1就在干这事。
 * 这个版本的BC对SM2的结果为C1||C2||C3，据说为旧标准，新标准为C1||C3||C2，用新标准的需要自己转换。下面changeC1C2C3ToC1C3C2、changeC1C3C2ToC1C2C3就在干这事。
 */
public class GmUtil {

    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static ECDomainParameters ecDomainParameters =
            new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
    private static ECParameterSpec ecParameterSpec =
            new ECParameterSpec(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }
    public static byte[] defaultUserId = "1234567812345678".getBytes();

    /**
     * @param msg
     * @param userId
     * @param privateKey
     * @return r||s，直接拼接byte数组的rs
     */
    public static byte[] signSm3WithSm2(byte[] msg, byte[] userId, PrivateKey privateKey) {
        return rsAsn1ToPlainByteArray(signSm3WithSm2Asn1Rs(msg, userId, privateKey));
    }

    /**
     * @param msg
     * @param userId
     * @param privateKey
     * @return rs in <b>asn1 format</b>
     */
    public static byte[] signSm3WithSm2Asn1Rs(byte[] msg, byte[] userId, PrivateKey privateKey) {
        try {
            SM2ParameterSpec parameterSpec = new SM2ParameterSpec(userId);
            Signature signer = Signature.getInstance("SM3withSM2", "BC");
            signer.setParameter(parameterSpec);
            signer.initSign(privateKey, new SecureRandom());
            signer.update(msg, 0, msg.length);
            byte[] sig = signer.sign();
            return sig;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @param msg
     * @param userId
     * @param rs        r||s，直接拼接byte数组的rs
     * @param publicKey
     * @return
     */
    public static boolean verifySm3WithSm2(byte[] msg, byte[] userId, byte[] rs, PublicKey publicKey) {
        return verifySm3WithSm2Asn1Rs(msg, userId, rsPlainByteArrayToAsn1(rs), publicKey);
    }

    /**
     * @param msg
     * @param userId
     * @param rs        in <b>asn1 format</b>
     * @param publicKey
     * @return
     */
    public static boolean verifySm3WithSm2Asn1Rs(byte[] msg, byte[] userId, byte[] rs, PublicKey publicKey) {
        try {
            SM2ParameterSpec parameterSpec = new SM2ParameterSpec(userId);
            Signature verifier = Signature.getInstance("SM3withSM2", "BC");
            verifier.setParameter(parameterSpec);
            verifier.initVerify(publicKey);
            verifier.update(msg, 0, msg.length);
            return verifier.verify(rs);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * bc加解密使用旧标c1||c2||c3，此方法在加密后调用，将结果转化为c1||c3||c2
     *
     * @param c1c2c3
     * @return
     */
    private static byte[] changeC1C2C3ToC1C3C2(byte[] c1c2c3) {
        //sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        //new SM3Digest().getDigestSize();
        final int c3Len = 32;
        byte[] result = new byte[c1c2c3.length];
        //c1
        System.arraycopy(c1c2c3, 0, result, 0, c1Len);
        //c3
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, result, c1Len, c3Len);
        //c2
        System.arraycopy(c1c2c3, c1Len, result, c1Len + c3Len, c1c2c3.length - c1Len - c3Len);
        return result;
    }


    /**
     * bc加解密使用旧标c1||c3||c2，此方法在解密前调用，将密文转化为c1||c2||c3再去解密
     *
     * @param c1c3c2
     * @return
     */
    private static byte[] changeC1C3C2ToC1C2C3(byte[] c1c3c2) {
        //sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        //new SM3Digest().getDigestSize();
        final int c3Len = 32;
        byte[] result = new byte[c1c3c2.length];
        //c1: 0->65
        System.arraycopy(c1c3c2, 0, result, 0, c1Len);
        //c2
        System.arraycopy(c1c3c2, c1Len + c3Len, result, c1Len, c1c3c2.length - c1Len - c3Len);
        //c3
        System.arraycopy(c1c3c2, c1Len, result, c1c3c2.length - c3Len, c3Len);
        return result;
    }

    /**
     * c1||c3||c2
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] sm2Decrypt(byte[] data, PrivateKey key) {
        return sm2DecryptOld(changeC1C3C2ToC1C2C3(data), key);
    }

    /**
     * c1||c3||c2
     *
     * @param data
     * @param key
     * @return
     */

    public static byte[] sm2Encrypt(byte[] data, PublicKey key) {
        return changeC1C2C3ToC1C3C2(sm2EncryptOld(data, key));
    }

    /**
     * c1||c2||c3
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] sm2EncryptOld(byte[] data, PublicKey key) {
        BCECPublicKey localECPublicKey = (BCECPublicKey) key;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * c1||c2||c3
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] sm2DecryptOld(byte[] data, PrivateKey key) {
        BCECPrivateKey localECPrivateKey = (BCECPrivateKey) key;
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(localECPrivateKey.getD(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);
        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sm4Encrypt(byte[] keyBytes, byte[] plain) {
        if (keyBytes.length != 16) {
            throw new RuntimeException("err key length");
        }
        if (plain.length % 16 != 0) {
            throw new RuntimeException("err data length");
        }

        try {
            Key key = new SecretKeySpec(keyBytes, "SM4");
            Cipher out = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
            out.init(Cipher.ENCRYPT_MODE, key);
            return out.doFinal(plain);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sm4Decrypt(byte[] keyBytes, byte[] cipher) {
        if (keyBytes.length != 16) {
            throw new RuntimeException("err key length");
        }
        if (cipher.length % 16 != 0) {
            throw new RuntimeException("err data length");
        }

        try {
            Key key = new SecretKeySpec(keyBytes, "SM4");
            Cipher in = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
            in.init(Cipher.DECRYPT_MODE, key);
            return in.doFinal(cipher);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * @param bytes
     * @return
     */
    public static byte[] sm3(byte[] bytes) {
        SM3Digest sm3 = new SM3Digest();
        sm3.update(bytes, 0, bytes.length);
        byte[] result = new byte[sm3.getDigestSize()];
        sm3.doFinal(result, 0);
        return result;
    }

    public static String sm3(String hash){
        Security.addProvider(new BouncyCastleProvider());
        byte[] dataByte = hash.getBytes();
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(dataByte, 0, dataByte.length);
        byte[] result = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(result, 0);
        return Hex.toHexString(result);
    }

    private final static int RS_LEN = 32;

    public static byte[] bigIntToFixexLengthBytes(BigInteger rOrS) {
        // for sm2p256v1, n is 00fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
        // r and s are the result of mod n, so they should be less than n and have length<=32
        byte[] rs = rOrS.toByteArray();
        if (rs.length == RS_LEN) {
            return rs;
        } else if (rs.length == RS_LEN + 1 && rs[0] == 0) {
            return Arrays.copyOfRange(rs, 1, RS_LEN + 1);
        } else if (rs.length < RS_LEN) {
            byte[] result = new byte[RS_LEN];
            Arrays.fill(result, (byte) 0);
            System.arraycopy(rs, 0, result, RS_LEN - rs.length, rs.length);
            return result;
        } else {
            throw new RuntimeException("err rs: " + Hex.toHexString(rs));
        }
    }

    /**
     * BC的SM3withSM2签名得到的结果的rs是asn1格式的，这个方法转化成直接拼接r||s
     *
     * @param rsDer rs in asn1 format
     * @return sign result in plain byte array
     */
    public static byte[] rsAsn1ToPlainByteArray(byte[] rsDer) {
        ASN1Sequence seq = ASN1Sequence.getInstance(rsDer);
        byte[] r = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        byte[] s = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        byte[] result = new byte[RS_LEN * 2];
        System.arraycopy(r, 0, result, 0, r.length);
        System.arraycopy(s, 0, result, RS_LEN, s.length);
        return result;
    }

    /**
     * BC的SM3withSM2验签需要的rs是asn1格式的，这个方法将直接拼接r||s的字节数组转化成asn1格式
     *
     * @param sign in plain byte array
     * @return rs result in asn1 format
     */
    private static byte[] rsPlainByteArrayToAsn1(byte[] sign) {
        if (sign.length != RS_LEN * 2) {
            throw new RuntimeException("err rs. ");
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded("DER");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
            kpGen.initialize(ecParameterSpec, new SecureRandom());
            KeyPair kp = kpGen.generateKeyPair();
            return kp;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static BCECPrivateKey getPrivatekeyFromD(BigInteger d) {
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
        return new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static BCECPublicKey getPublickeyFromXY(BigInteger x, BigInteger y) {
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(x9ECParameters.getCurve().createPoint(x, y), ecParameterSpec);
        return new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static PublicKey getPublickeyFromX509File(File file) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            FileInputStream in = new FileInputStream(file);
            X509Certificate x509 = (X509Certificate) cf.generateCertificate(in);
            return x509.getPublicKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null){
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }



    public static byte[] toByteArray(String hexString) {
        hexString = hexString.toLowerCase();
        final byte[] byteArray = new byte[hexString.length() / 2];
        int k = 0;
        for (int i = 0; i < byteArray.length; i++) {// 因为是16进制，最多只会占用4位，转换成字节需要两个16进制的字符，高位在先
            byte high = (byte) (Character.digit(hexString.charAt(k), 16) & 0xff);
            byte low = (byte) (Character.digit(hexString.charAt(k + 1), 16) & 0xff);
            byteArray[i] = (byte) (high << 4 | low);
            k += 2;
        }
        return byteArray;
    }








    public static void main(String[] args) throws Exception {


        final BouncyCastleProvider bc = new BouncyCastleProvider();

        BigInteger privD = Numeric.toBigInt("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");
        byte[] userID = "1234567812345678".getBytes();
        byte[] enByte = sm3("1234".getBytes());
        System.out.println(Numeric.toHexStringNoPrefix(enByte));

        BCECPrivateKey privateKey = getPrivatekeyFromD(Numeric.toBigInt("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"));



        Credentials credentials = Credentials.create("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");


        byte[] signabc = signSm3WithSm2Asn1Rs(enByte, userID, privateKey);
        System.out.println(Numeric.toHexStringNoPrefix(rsAsn1ToPlainByteArray(signabc)));

        byte [] sig = rsAsn1ToPlainByteArray(signabc);

        //04
        // bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b6954931
        // 3dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd

        BigInteger x = new BigInteger("bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b6954931",16);
        BigInteger y = new BigInteger("3dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd",16);

        String rs = "5b48861bb8b83e3afd8986c5df0f7034f08db2e921209d77774702b59b16155669b38c490bd4f849a766a35003b7bc21a8b505090b2ae0bb7acbd0c261753611";

//        sig = toByteArray(rs);
        PublicKey pk =getPublickeyFromXY(x,y);

//        enByte = "9487aa1e391b2003ea39e9c5e9e73b62e22adc2c25d1cad691597e8da0f785d3".getBytes();
        boolean bbb = verifySm3WithSm2(enByte, userID, sig, pk);
        System.out.println(bbb);
        Date date = new Date();
        Long c = date.getTime();
        System.out.println(c);
        for (int i = 0;i< 1000;i++){
            verifySm3WithSm2(enByte, userID, sig,pk);
        }
        date = new Date();
        System.out.println(date.getTime() -c);
        System.out.println(((float)(date.getTime()-c))/1000.0);



        byte[] signabc2 = signSm3WithSm2(enByte, userID, privateKey);
        System.out.println(Numeric.toHexStringNoPrefix(signabc2));

        sig =(signabc2);
        bbb = verifySm3WithSm2(enByte, userID, sig, getPublickeyFromXY(x,y));
        System.out.println(bbb);

        byte[] signabc3 = Sm2Util.sign(new ECPrivateKeyParameters(privD, ecDomainParameters),
                userID, enByte);
        System.out.println(Numeric.toHexStringNoPrefix(rsAsn1ToPlainByteArray(signabc3)));

        Sm2PrivateKey sm2PrivateKey = new Sm2PrivateKeyImpl(privateKey);
        sm2PrivateKey.setWithId(userID);

        sig =rsAsn1ToPlainByteArray(signabc3);
        bbb = verifySm3WithSm2(enByte, userID, sig, getPublickeyFromXY(x,y));
        System.out.println(bbb);


        byte[] signabc4 = Sm2Util.sign(sm2PrivateKey, enByte);
        System.out.println(Numeric.toHexStringNoPrefix(rsAsn1ToPlainByteArray(signabc4)));

        sig =rsAsn1ToPlainByteArray(signabc4);
        bbb = verifySm3WithSm2(enByte, userID, sig, getPublickeyFromXY(x,y));
        System.out.println(bbb);



//        byte[] encPub = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESic24soUECzuSh2aYH0e+hQYh+/I01NmfjOnm5mwyUEYQvNCPTzn3BlNyufgMV+DWLUKV+2h0+PVel9jYTfG8Q==");
//        byte[] encPriv = Base64.getDecoder().decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg0dYU+I6IdiSe8bvWlsHuWfsjSn3XFZqOGWO3K1814O6gCgYIKoEcz1UBgi2hRANCAARKJzbiyhQQLO5KHZpgfR76FBiH78jTU2Z+M6ebmbDJQRhC80I9POfcGU3K5+AxX4NYtQpX7aHT49V6X2NhN8bx");
//        byte[] plainText = "你好".getBytes(StandardCharsets.UTF_8);
//
//        KeyFactory keyFact = KeyFactory.getInstance("EC", bc);
//        // 根据采用的编码结构反序列化公私钥
//        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
//        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
//
//
//        Signature signature = Signature.getInstance("SM3withSm2", bc);
//        signature.initVerify(pub);
//        signature.update(plainText);
//        // 验证签名值
//        boolean res = signature.verify(Hex.decode("3045022100ff9a872f21e47d4fba8f37b48a62cc2e6fdde843a40cbc96242536afc10a395e02203bbab982d1bb6a7ee5f5f6b34cd887c255ae4dcc14dd87ecae2e0392611b7a8c"));
//        System.out.println(">> 验证结果:" + res);


//        // 随便看看 ---------------------
//        System.out.println("GMNamedCurves: ");
//        for(Enumeration e = GMNamedCurves.getNames(); e.hasMoreElements();) {
//            System.out.println(e.nextElement());
//        }
//        System.out.println("sm2p256v1 n:"+x9ECParameters.getN());
//        System.out.println("sm2p256v1 nHex:"+Hex.toHexString(x9ECParameters.getN().toByteArray()));


//        // 生成公私钥对 ---------------------
//        KeyPair kp = generateKeyPair();
//
//        System.out.println(Hex.toHexString(kp.getPrivate().getEncoded()));
//        System.out.println(Hex.toHexString(kp.getPublic().getEncoded()));
//
//        System.out.println(kp.getPrivate().getAlgorithm());
//        System.out.println(kp.getPublic().getAlgorithm());
//
//        System.out.println(kp.getPrivate().getFormat());
//        System.out.println(kp.getPublic().getFormat());
//
//        System.out.println("private key d: " + ((BCECPrivateKey) kp.getPrivate()).getD());
//        System.out.println("public key q:" + ((BCECPublicKey) kp.getPublic()).getQ()); //{x, y, zs...}
//
//        byte[] msg = "message digest".getBytes();
//        byte[] userId = "12345678".getBytes();
//        byte[] sig = signSm3WithSm2(msg, userId, kp.getPrivate());
//        System.out.println(Hex.toHexString(sig));
//        System.out.println(verifySm3WithSm2(msg, userId, sig, kp.getPublic()));


//        // 由d生成私钥 ---------------------
//        BigInteger d = new BigInteger("097b5230ef27c7df0fa768289d13ad4e8a96266f0fcb8de40d5942af4293a54a", 16);
//        BCECPrivateKey bcecPrivateKey = getPrivatekeyFromD(d);
////        System.out.println(bcecPrivateKey.getParameters());
////        System.out.println(Hex.toHexString(bcecPrivateKey.getEncoded()));
////        System.out.println(bcecPrivateKey.getAlgorithm());
////        System.out.println(bcecPrivateKey.getFormat());
////        System.out.println(bcecPrivateKey.getD());
////        System.out.println(bcecPrivateKey instanceof java.security.interfaces.ECPrivateKey);
////        System.out.println(bcecPrivateKey instanceof ECPrivateKey);
////        System.out.println(bcecPrivateKey.getParameters());
////

////        公钥X坐标PublicKeyXHex: 59cf9940ea0809a97b1cbffbb3e9d96d0fe842c1335418280bfc51dd4e08a5d4
////        公钥Y坐标PublicKeyYHex: 9a7f77c578644050e09a9adc4245d1e6eba97554bc8ffd4fe15a78f37f891ff8
//        PublicKey publicKey = getPublickeyFromX509File(new File("/Users/xxx/Downloads/xxxxx.cer"));
//        System.out.println(publicKey);
////        PublicKey publicKey1 = getPublickeyFromXY(new BigInteger("59cf9940ea0809a97b1cbffbb3e9d96d0fe842c1335418280bfc51dd4e08a5d4", 16), new BigInteger("9a7f77c578644050e09a9adc4245d1e6eba97554bc8ffd4fe15a78f37f891ff8", 16));
////        System.out.println(publicKey1);
////        System.out.println(publicKey.equals(publicKey1));
////        System.out.println(publicKey.getEncoded().equals(publicKey1.getEncoded()));
//


//        // sm2 encrypt and decrypt test ---------------------
//        KeyPair kp = generateKeyPair();
//        PublicKey publicKey2 = kp.getPublic();
//        PrivateKey privateKey2 = kp.getPrivate();
//        byte[]bs = sm2Encrypt("s".getBytes(), publicKey2);
//        System.out.println(Hex.toHexString(bs));
//        bs = sm2Decrypt(bs, privateKey2);
//        System.out.println(new String(bs));


//        // sm4 encrypt and decrypt test ---------------------
//        //0123456789abcdeffedcba9876543210 + 0123456789abcdeffedcba9876543210 -> 681edf34d206965e86b3e94f536e4246
//        byte[] plain = Hex.decode("0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
//        byte[] key = Hex.decode("0123456789abcdeffedcba9876543210");
//        byte[] cipher = Hex.decode("595298c7c6fd271f0402f804c33d3f66");
//        byte[] bs = sm4Encrypt(key, plain);
//        System.out.println(Hex.toHexString(bs));;
//        bs = sm4Decrypt(key, bs);
//        System.out.println(Hex.toHexString(bs));
    }
}
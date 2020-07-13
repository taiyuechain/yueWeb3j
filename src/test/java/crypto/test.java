package crypto;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.yueweb3j.crypto.Credentials;
import org.yueweb3j.crypto.ECDSASignature;
import org.yueweb3j.crypto.Hash;
import org.yueweb3j.crypto.Sign;
import org.yueweb3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;

import static org.yueweb3j.crypto.TransactionEncoder.createEip155SignatureData;
import static org.yueweb3j.crypto.sm.GmUtil.*;


public class test {
    public static void signMessage(Credentials credentials) {
        byte[] encodedTransaction = Hash.sha3("1234".getBytes());
        System.out.println(Hex.toHexString(encodedTransaction));
        Sign.SignatureData signatureData =
                Sign.signMessage(encodedTransaction, credentials.getEcKeyPair());
        Sign.SignatureData eip155SignatureData = createEip155SignatureData(signatureData, 20515);
        System.out.println(Hex.toHexString(signatureData.getR()) +
                Hex.toHexString(signatureData.getS()) + Hex.toHexString(signatureData.getV()));
    }


    private static PrivateKey getPrivateKey(String key) {
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        org.bouncycastle.jce.spec.ECPrivateKeySpec privateKeySpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(
                new BigInteger(key, 16), ecSpec);
        return new BCECPrivateKey("EC", privateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    private static PublicKey getPublicKey(String key) {
        String x = key.substring(0, 64);
        String y = key.substring(64, 128);
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        org.bouncycastle.math.ec.ECPoint ecPoint = ecSpec.getCurve().createPoint(new BigInteger(x, 16),
                new BigInteger(y, 16));
        org.bouncycastle.jce.spec.ECPublicKeySpec publicKeySpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(ecPoint,
                ecSpec);
        return new BCECPublicKey("EC", publicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        Credentials credentials = Credentials.create("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");

        System.out.println(credentials.getEcKeyPair().getPublicKey().toString(16));
        credentials.getAddress();
        System.out.println(credentials.getEcKeyPair().getCompressPublicKey());
//        signMessage(credentials);
//
//        String a =SM2Util.getInstance().SM2Sign( Hash.sha3("1234"),"7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");
//        System.out.println(a);


        String priv = "7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75";
        String pub = "bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd";


        // 获取SM2 椭圆曲线推荐参数
        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造EC 算法参数
        ECNamedCurveParameterSpec sm2Spec = new ECNamedCurveParameterSpec(
                // 设置SM2 算法的 OID
                GMObjectIdentifiers.sm2p256v1.toString()
                // 设置曲线方程
                , ecParameters.getCurve()
                // 椭圆曲线G点
                , ecParameters.getG()
                // 大整数N
                , ecParameters.getN());
        // 创建 密钥对生成器
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

        // 使用SM2的算法区域初始化密钥生成器
        gen.initialize(sm2Spec, new SecureRandom());
        // 获取密钥对
        KeyPair keyPair = gen.generateKeyPair();



                /*
        获取公私钥
         */
        PublicKey publicKey = getPublicKey(pub);//keyPair.getPublic();
        PrivateKey privateKey = getPrivateKey(priv);//keyPair.getPrivate();


        // 生成SM2sign with sm3 签名验签算法实例
        Signature signature = Signature.getInstance(
                GMObjectIdentifiers.sm2sign_with_sm3.toString()
                , new BouncyCastleProvider());

        /*
        签名
         */
        // 签名需要使用私钥，使用私钥 初始化签名实例
        signature.initSign(privateKey);
        // 签名原文
        byte[] plainText = "Hello world".getBytes(StandardCharsets.UTF_8);
        // 写入签名原文到算法中
        signature.update(plainText);
        // 计算签名值
        byte[] signatureValue = signature.sign();
        System.out.println("signature: \n" + Hex.toHexString(signatureValue));

        /*
        验签
         */
        // 签名需要使用公钥，使用公钥 初始化签名实例
        signature.initVerify(publicKey);
        // 写入待验签的签名原文到算法中
        signature.update(plainText);
        // 验签
        System.out.println("Signature verify result: " + signature.verify(signatureValue));


    }

    public static final String PERSONAL_MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";

    @Test
    public void testRecoverAddressFromSignature() {
        //CHECKSTYLE:OFF
        String signature = "0x2c6401216c9031b9a6fb8cbfccab4fcec6c951cdf40e2320108d1856eb532250576865fbcd452bcdc4c57321b619ed7a9cfd38bd973c3e1e0243ac2777fe9d5b1b";
        //CHECKSTYLE:ON
        String address = "0x31b26e43651e9371c88af3d36c14cfd938baf4fd";
        String message = "v0G9u7huK4mJb2K1";

        String prefix = PERSONAL_MESSAGE_PREFIX + message.length();
        byte[] msgHash = Hash.sha3((prefix + message).getBytes());

        byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
        byte v = signatureBytes[64];
        if (v < 27) {
            v += 27;
        }

        Sign.SignatureData sd = new Sign.SignatureData(
                v,
                (byte[]) Arrays.copyOfRange(signatureBytes, 0, 32),
                (byte[]) Arrays.copyOfRange(signatureBytes, 32, 64));

        String addressRecovered = null;
        boolean match = false;

        // Iterate for each possible key to recover

        Date date = new Date();
        Long c = date.getTime();
        System.out.println(c);

        for (int j = 0; j < 1000; j++) {
            for (int i = 0; i < 4; i++) {
                BigInteger publicKey = Sign.recoverFromSignature(
                        (byte) i,
                        new ECDSASignature(new BigInteger(1, sd.getR()), new BigInteger(1, sd.getS())),
                        msgHash);

                if (publicKey != null) {
                    break;
                }
            }
        }

        date = new Date();
        System.out.println(date.getTime() - c);
        System.out.println(((float) (date.getTime() - c)) / 1000.0);

    }

    @Test
    public void testRecoverAddressFromSignature2() {
        final BouncyCastleProvider bc = new BouncyCastleProvider();

        BigInteger privD = Numeric.toBigInt("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");
        byte[] userID = "1234567812345678".getBytes();
        byte[] enByte = sm3("1234".getBytes());
        System.out.println(Numeric.toHexStringNoPrefix(enByte));

        BCECPrivateKey privateKey = getPrivatekeyFromD(Numeric.toBigInt("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"));


        Credentials credentials = Credentials.create("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");


        byte[] signabc = signSm3WithSm2Asn1Rs(enByte, userID, privateKey);
        System.out.println(Numeric.toHexStringNoPrefix(rsAsn1ToPlainByteArray(signabc)));

        byte[] sig = rsAsn1ToPlainByteArray(signabc);

        //04
        // bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b6954931
        // 3dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd

        BigInteger x = new BigInteger("bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b6954931", 16);
        BigInteger y = new BigInteger("3dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd", 16);

        String rs = "5b48861bb8b83e3afd8986c5df0f7034f08db2e921209d77774702b59b16155669b38c490bd4f849a766a35003b7bc21a8b505090b2ae0bb7acbd0c261753611";

        //        sig = toByteArray(rs);
        PublicKey pk = getPublickeyFromXY(x, y);

        //        enByte = "9487aa1e391b2003ea39e9c5e9e73b62e22adc2c25d1cad691597e8da0f785d3".getBytes();
        boolean bbb = verifySm3WithSm2(enByte, userID, sig, pk);
        System.out.println(bbb);
        Date date = new Date();
        Long c = date.getTime();
        System.out.println(c);
        for (int i = 0; i < 1000; i++) {
            verifySm3WithSm2(enByte, userID, sig, pk);
        }
        date = new Date();
        System.out.println(date.getTime() - c);
        System.out.println(((float) (date.getTime() - c)) / 1000.0);
    }


}

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

/**
 * AES加密解密，修复在Win系统可以加解密，在Linux系统只能加密不能解密问题
 */
@Component
public class AESUtils {

    /**
     * 私有化SecurityUtils
     */
    private AESUtils() {
    }

    /**
     * 编码格式
     */
    private static final String ENCODING = "UTF-8";
    /**
     * 加密算法
     */
    private static final String KEY_ALGORITHM = "AES";
    /**
     * 签名算法
     */
    private static final String SIGN_ALGORITHMS = "SHA1PRNG";
    /**
     * 加密位数为128位
     */
    private static final int ENCRYPT_SIZE = 128;

    /**
     * HEX_16
     */
    private static final int HEX_16 = 0xFF;

    /**
     * 16
     */
    private static final int NUMBER_16 = 16;

    /**
     * 加密文本
     *
     * @param content
     *            待加密内容
     * @param key
     *            加密的密钥
     * @return 加密结果
     */
    public static String encrypt(String content, String key) {

        if (StringUtils.isBlank(content)) {
            return content;
        }

        try {
            // 构造密钥生成器，指定为AES算法,不区分大小写
            KeyGenerator kgen = KeyGenerator.getInstance(KEY_ALGORITHM);

            // 签名
            SecureRandom random = SecureRandom.getInstance(SIGN_ALGORITHMS);

            // 设置种子
            random.setSeed(key.getBytes(ENCODING));

            // 初始化
            kgen.init(ENCRYPT_SIZE, random);

            // 密钥构造
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();

            // 生成密钥
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, KEY_ALGORITHM);

            Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
            byte[] byteContent = content.getBytes(ENCODING);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] byteRresult = cipher.doFinal(byteContent);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < byteRresult.length; i++) {
                String hex = Integer.toHexString(byteRresult[i] & HEX_16);
                if (hex.length() == 1) {
                    hex = '0' + hex;
                }
                sb.append(hex.toUpperCase());
            }
            return sb.toString();
        } catch (Exception e) {

        }
        return content;
    }

    /**
     * 解密文本
     *
     * @param content
     *            待解密内容
     * @param key
     *            解密的密钥
     * @return 解密结果
     */
    public static String decrypt(String content, String key) {

        if (StringUtils.isBlank(content)) {
            return content;
        }

        byte[] byteRresult = new byte[content.length() / 2];

        // 还原base64处理后的字符传（一串乱码）
        for (int i = 0; i < content.length() / 2; i++) {
            int high = Integer.parseInt(content.substring(i * 2, i * 2 + 1), NUMBER_16);
            int low = Integer.parseInt(content.substring(i * 2 + 1, i * 2 + 2), NUMBER_16);
            byteRresult[i] = (byte) (high * NUMBER_16 + low);
        }
        // 执行解密
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(KEY_ALGORITHM);
            SecureRandom random = SecureRandom.getInstance(SIGN_ALGORITHMS);

            random.setSeed(key.getBytes(ENCODING));
            kgen.init(ENCRYPT_SIZE, random);

            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();

            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] result = cipher.doFinal(byteRresult);
            return new String(result, ENCODING);
        } catch (Exception e) {

        }
        return content;
    }
}


public class AESEncryptUtil {
     //private static final transient Logger log = LoggerFactory.getLogger(AESEncryptUtil.class);

     public AESEncryptUtil() {
     }

     public static byte[] encrypt(byte[] bytes, String password) {
         try {
             KeyGenerator e = KeyGenerator.getInstance("AES");
             SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
             secureRandom.setSeed(password.getBytes("utf-8"));
             e.init(128, secureRandom);
             SecretKey secretKey = e.generateKey();
             byte[] enCodeFormat = secretKey.getEncoded();
             SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
             Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
             cipher.init(1, key, getSpec(cipher, secureRandom));
             return cipher.doFinal(bytes);
         } catch (Exception var8) {
             //log.error(var8.getMessage(), var8);
             var8.printStackTrace();
             System.out.println("AESEncryptUtil exception:" + var8.getMessage());
             return null;
         }
     }

     public static byte[] decrypt(byte[] content, String password) {
         try {
             KeyGenerator e = KeyGenerator.getInstance("AES");
             SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
             secureRandom.setSeed(password.getBytes("utf-8"));
             e.init(128, secureRandom);
             SecretKey secretKey = e.generateKey();
             byte[] enCodeFormat = secretKey.getEncoded();
             SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
             Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
             cipher.init(2, key, getSpec(cipher, secureRandom));
             return cipher.doFinal(content);
         } catch (Exception var8) {
             //log.error(var8.getMessage(), var8);
             var8.printStackTrace();
             System.out.println("AESEncryptUtil exception:" + var8.getMessage());
             return null;
         }
     }

     private static AlgorithmParameterSpec getSpec(Cipher cipher, SecureRandom secureRandom) {
         byte[] iv = new byte[cipher.getBlockSize()];
         secureRandom.nextBytes(iv);
         IvParameterSpec ivspec = new IvParameterSpec(iv);
         return ivspec;
     }
 }

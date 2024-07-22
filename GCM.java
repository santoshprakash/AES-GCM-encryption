import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class GCM {

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String FACTORY_INSTANCE = "PBKDF2WithHmacSHA512";
    private static final int TAG_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 32;
    private static final int ITERATIONS = 65535;

    public static void main(String[] args) throws Exception {
        System.out.println("AES GCMC 256 String decryption with PBKDF2 derived key");

        String masterKey = "your_secure_key";
        String encryptedData = encrypt(masterKey, "Your_plain_text");
        System.out.println("Encrypted: " + encryptedData);
        String decryptedText = decrypt(encryptedData, masterKey);
        System.out.println("Decrypted: " + decryptedText);
    }

    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH * 8);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    public static String decrypt(String cipherContent, String password) throws Exception {
        byte[] decode = Base64.getDecoder().decode(cipherContent.getBytes(UTF_8));
        ByteBuffer byteBuffer = ByteBuffer.wrap(decode);

        byte[] salt = new byte[SALT_LENGTH];
        byteBuffer.get(salt);

        byte[] iv = new byte[IV_LENGTH];
        byteBuffer.get(iv);

        byte[] content = new byte[byteBuffer.remaining()];
        byteBuffer.get(content);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH * 8, iv));
        byte[] plainText = cipher.doFinal(content);
        return new String(plainText, UTF_8);
    }

    public static String encrypt(String password, String plainMessage) throws Exception {
        byte[] salt = getRandomNonce(SALT_LENGTH);
        SecretKey secretKey = getSecretKey(password, salt);

        byte[] iv = getRandomNonce(IV_LENGTH);

        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedMessageByte = cipher.doFinal(plainMessage.getBytes(UTF_8));

        byte[] cipherByte = ByteBuffer.allocate(salt.length + iv.length + encryptedMessageByte.length)
                .put(salt)
                .put(iv)
                .put(encryptedMessageByte)
                .array();
        return Base64.getEncoder().encodeToString(cipherByte);
    }

    public static byte[] getRandomNonce(int length) {
        byte[] nonce = new byte[length];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static SecretKey getSecretKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH * 8);

        SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_INSTANCE);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private static Cipher initCipher(int mode, SecretKey secretKey, byte[] iv) throws InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(mode, secretKey, new GCMParameterSpec(TAG_LENGTH * 8, iv));
        return cipher;
    }

}

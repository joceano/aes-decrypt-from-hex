package br.com.example.aesdecryptfromhex.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Algoritmo de encriptação/decriptação AES compatível com C# .Net.
 */
public final class AesCipher {

    private final SecretKeySpec key;
    private final IvParameterSpec iv;
    private final Cipher aesAlgorithm;

    public AesCipher(String password, String salt) {
        this(password, salt.getBytes());
    }

    public AesCipher(String password, byte[] salt) {
        try {
            aesAlgorithm = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(password, salt);
            key = new SecretKeySpec(deriveBytes.getBytes(256 / 8), "AES");
            iv = new IvParameterSpec(deriveBytes.getBytes(128 / 8));
        } catch (Exception e) {
            throw new RuntimeException(e.getLocalizedMessage(), e);
        }
    }

    public String encrypt(String toEncrypt) {
        try {
            aesAlgorithm.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] decrypted = toEncrypt.getBytes();
            byte[] encrypted = aesAlgorithm.doFinal(decrypted);
            return byteArrayToHexString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e.getLocalizedMessage(), e);
        }
    }

    public String decrypt(String toDecrypt) {
        try {
            aesAlgorithm.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] encoded = hexStringToByteArray(toDecrypt);
            byte[] decrypted = aesAlgorithm.doFinal(encoded);
            return new String(decrypted);
        } catch (Exception e) {
            throw new RuntimeException(e.getLocalizedMessage(), e);
        }
    }

    private byte[] hexStringToByteArray(String encryptText) throws IllegalArgumentException {
        int len = encryptText.length();
        if (len % 2 == 1) {
            throw new IllegalArgumentException("Hex string must have even number of characters");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(encryptText.charAt(i), 16) << 4) +
                    Character.digit(encryptText.charAt(i + 1), 16));
        }
        return data;
    }

    private String byteArrayToHexString(byte[] bytes) {
        final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
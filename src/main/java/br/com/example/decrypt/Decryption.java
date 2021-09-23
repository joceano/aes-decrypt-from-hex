package br.com.example.decrypt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryption {

    private static final String KEY = "nifInformation";
    private static final int ITERATIONS = 1000;
    private static final int SIZE = 256;
    private static final byte[] SALT = { 1, 2, 3, 4, 5, 6, 7, 8 };
    private static final String ALGORITHM = "AES";

    public String decrypt(String encryptText) {
        try {
            //Configura a key
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(KEY.toCharArray(), SALT, ITERATIONS, SIZE);
            SecretKey secretKey = factory.generateSecret(spec);
            SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret);

            //Converte o hexadecimal em um array de byte
            byte[] encryptArray = hexStringToByteArray(encryptText);

            //Realiza a descriptografia
            byte[] decrypt = cipher.doFinal(encryptArray);

            return new String(decrypt);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
        return null;
    }

    private byte[] hexStringToByteArray(String encryptText) throws IllegalArgumentException {
        int len = encryptText.length();
        if (len % 2 == 1) {
            throw new IllegalArgumentException("Hex string must have even number of characters");
        }
        byte[] data = new byte[len / 2]; // Allocate 1 byte per 2 hex characters
        for (int i = 0; i < len; i += 2) {
            // Convert each character into a integer (base-16), then bit-shift into place
            data[i / 2] = (byte) ((Character.digit(encryptText.charAt(i), 16) << 4) +
                    Character.digit(encryptText.charAt(i + 1), 16));
        }
        return data;
    }

    private String byteArrayToHexString(byte[] bytes) {
        final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
            hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
            hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
        }
        return new String(hexChars);
    }
}

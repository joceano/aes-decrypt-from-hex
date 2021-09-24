package br.com.example.aesdecryptfromhex.aes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public final class Rfc2898DeriveBytes {

    private final Mac hmacSha1;
    private final byte[] salt;
    private final int iterationCount;
    private byte[] buffer = new byte[20];
    private int bufferStartIndex = 0;
    private int bufferEndIndex = 0;
    private int block = 1;

    public Rfc2898DeriveBytes(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException {
        this(password, salt, 1000);
    }

    public Rfc2898DeriveBytes(String password, byte[] salt, int iterations) throws InvalidKeyException, NoSuchAlgorithmException {
        this(password.getBytes(StandardCharsets.UTF_8), salt, iterations);
    }

    public Rfc2898DeriveBytes(byte[] password, byte[] salt, int iterations) throws NoSuchAlgorithmException, InvalidKeyException {
        if ((salt == null) || (salt.length < 8)) {
            throw new InvalidKeyException("Salt must be 8 bytes or more.");
        }
        if (password == null) {
            throw new InvalidKeyException("Password cannot be null.");
        }
        this.salt = salt;
        this.iterationCount = iterations;
        this.hmacSha1 = Mac.getInstance("HmacSHA1");
        this.hmacSha1.init(new SecretKeySpec(password, "HmacSHA1"));
    }

    private byte[] intToBytes(int value) {
        return new byte[] { (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) (value >>> 0) };
    }

    public byte[] getBytes(int count) {
        byte[] result = new byte[count];
        int resultOffset = 0;
        int bufferCount = this.bufferEndIndex - this.bufferStartIndex;

        if (bufferCount > 0) {
            if (count < bufferCount) {
                System.arraycopy(this.buffer, this.bufferStartIndex, result, 0, count);
                this.bufferStartIndex += count;
                return result;
            }
            System.arraycopy(this.buffer, this.bufferStartIndex, result, 0, bufferCount);
            this.bufferStartIndex = this.bufferEndIndex = 0;
            resultOffset += bufferCount;
        }

        while (resultOffset < count) {
            int needCount = count - resultOffset;
            this.buffer = this.func();
            if (needCount > 20) {
                System.arraycopy(this.buffer, 0, result, resultOffset, 20);
                resultOffset += 20;
            } else {
                System.arraycopy(this.buffer, 0, result, resultOffset, needCount);
                this.bufferStartIndex = needCount;
                this.bufferEndIndex = 20;
                return result;
            }
        }
        return result;
    }

    private byte[] func() {
        this.hmacSha1.update(this.salt, 0, this.salt.length);
        byte[] tempHash = this.hmacSha1.doFinal(intToBytes(this.block));

        this.hmacSha1.reset();
        byte[] finalHash = tempHash;
        for (int i = 2; i <= this.iterationCount; i++) {
            tempHash = this.hmacSha1.doFinal(tempHash);
            for (int j = 0; j < 20; j++) {
                finalHash[j] = (byte) (finalHash[j] ^ tempHash[j]);
            }
        }
        if (this.block == 2147483647) {
            this.block = -2147483648;
        } else {
            this.block += 1;
        }
        return finalHash;
    }
}

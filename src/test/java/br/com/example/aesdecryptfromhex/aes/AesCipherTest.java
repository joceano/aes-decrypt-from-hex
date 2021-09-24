package br.com.example.aesdecryptfromhex.aes;

import br.com.example.aesdecryptfromhex.aes.given.AesCipherGiven;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AesCipherTest {

    private final AesCipherGiven given = new AesCipherGiven();
    private final AesCipher aes = new AesCipher(new String(given.getPassword()), given.getSalt());

    @Test
    void decryptValidations() {
        given.getValidations().forEach((original, encrypted) -> {
            String result = this.aes.decrypt(encrypted);
            assertEquals(original, result);
        });
    }

    @Test
    void encryptValidations() {
        given.getValidations().forEach((original, encrypted) -> {
            String result = this.aes.encrypt(original);
            assertEquals(encrypted, result);
        });
    }
}

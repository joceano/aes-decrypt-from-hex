package br.com.example.aesdecryptfromhex.aes.given;

import java.util.Base64;
import java.util.Map;

public class AesCipherGiven {

    private final byte[] password = Base64.getDecoder().decode("bmlmSW5mb3JtYXRpb24=");
    private final byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
    private final Map<String, String> validations = Map.of(
            "25883838073", "D3D489BFDB21CB3E383C2B4716DEFDA1",
            "56900616038", "EA9C93CC5E22B22F456DC6E42B97BB86",
            "24876330000103","D3647BF35941A84B9BDA556518D8C936",
            "51365441000128", "077907F550791FE752D26A5AE1A12937",
            "", "04E1A92D6E08CD467D5D4E9476BB2974"
    );

    public byte[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public Map<String, String> getValidations() {
        return validations;
    }
}

package br.com.example;

import br.com.example.decrypt.Decryption;

public class Main {

    private static final String CPF = "35972299801";
    private static final String CPF_ENCRYPT = "35A809659ABB4751B83616D4AF85CDA1";

    public static void main(String[] args) {

        System.out.println("Original: " + CPF);
        System.out.println("Encrypted: " + CPF_ENCRYPT);

        Decryption decryption = new Decryption();
        String decrypt = decryption.decrypt(CPF_ENCRYPT);

        System.out.println("Decrypted: " + decrypt);
    }
}

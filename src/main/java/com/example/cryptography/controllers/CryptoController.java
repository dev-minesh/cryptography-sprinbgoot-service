package com.example.cryptography.controllers;

import com.example.cryptography.Models.LoginRequestInput;
import com.example.cryptography.Models.SignupResponse;
import jakarta.annotation.PostConstruct;
import org.springframework.web.bind.annotation.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

@RestController
public class CryptoController {
    private static final String PKBDF2_ALGO = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 10000;
    private static final int HASHBYTES = 256;
    private static final int SALT_BYTES = 24;
    private static final int CSPRNG_BYTES = 24;
    private Cipher cipher = null;
    private SecretKeyFactory factory = null;

    public static byte[] generateSecureRandom(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getEncoder().encode(bytes);
    }

    @PostConstruct
    public void initializeCipher() {
        System.out.println("Initialize Cipher Init");
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            factory = SecretKeyFactory.getInstance(PKBDF2_ALGO);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("...", e);
        }
        System.out.println("Initialize Cipher Completed");
    }

    @GetMapping("/signup")
    public SignupResponse signup(@RequestParam String password, @RequestParam String dataToEncrypt) throws Exception {


        //step:1 generate a bunch of Base64 encodedCSPRNG of certain length
        byte[] dek = generateSecureRandom(CSPRNG_BYTES);
        byte[] kekSalt = generateSecureRandom(SALT_BYTES);
        byte[] kekIv = generateSecureIV();
        byte[] dekIv = generateSecureIV();


        /*
         * step:2 we will make use of PBKDF2 algorithm to generate a KEK (Key Encryption Key)
         * using the User's password and saltForKek and call it kekBasedOnUserPassword
         */
        SecretKey kekBasedOnUserPassword = generateEncryptionKey(password, kekSalt);


        /*
         * step:3
         * Now that we have a KEK SecretKey we will make use of AES encryption
         *  algorithm to encrypt the dek using KEK SecretKey & ivForKek.
         *  encryptedDek will be used for encryption and decryption
         */
        String encryptedDek = encrypt(kekBasedOnUserPassword, kekIv, new String(dek));

        /*
         * step:4
         * To decrypt the encryptedDek then feed the decryptedDek with saltForDek to PBKDF2
         * in order to obtain DEK SecretKey
         */
        String decryptedDek = decrypt(kekBasedOnUserPassword, kekIv, encryptedDek);


        /*
         * step:5
         * Obtain secretKey for DEK using PBKDF2 algorithm
         */
        SecretKey dekSecretKey = generateEncryptionKey(decryptedDek, kekSalt);


        /*
         * step:6
         * Now that we have a DEK SecretKey we will make use of AES encryption
         * algorithm to encrypt the dataToEncrypt using DEK SecretKey & ivForDek.
         */
        String encryptedText = encrypt(dekSecretKey, dekIv, dataToEncrypt);
        return new SignupResponse(encryptedDek, kekSalt, encryptedText, kekIv, dekIv);
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequestInput requestInput) throws InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        /*
         * step1:
         * Use the user’s password with kekSalt to generate a kekBasedOnUserPassword (Similar to #2 of Registration phase)
         * usingPBKDF2 algorithm and store it
         */
        SecretKey kekSecretKey = generateEncryptionKey(requestInput.getPassword(), requestInput.getKekSalt());


        /*
         * step2:
         * Use the kekBasedOnUserPassword to decrypt the encryptedDek (Similar to #3 of Registration phase)
         * and store it
         */
        String decryptedDek = decrypt(kekSecretKey, requestInput.getKekIv(), requestInput.getEncryptedDek());

        /*
         * step3:
         * Use the decryptedDek with kekSalt to generate a dekSecretKey (Similar to #4 of Registration phase)
         * using PBKDF2 algorithm and store it
         */
        SecretKey dekSecretKey = generateEncryptionKey(decryptedDek, requestInput.getKekSalt());

        /*
         * step4:
         * Use the dekSecretKey to decrypt the encryptedText (Similar to #6 of Registration phase)
         * and store it
         */
        String decryptedText = decrypt(dekSecretKey, requestInput.getDekIv(), requestInput.getDataToDecrypt());
        return decryptedText;
    }


    public byte[] generateSecureIV() throws NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encode(iv);
    }

    /*
     * Encrypt given toBeEncrypted with passed SecretKey and IV.
     */
    public String encrypt(SecretKey secret, byte[] encodedIV,
                          String toBeEncryped) {
        byte[] iv = Base64.getDecoder().decode(encodedIV);
        AlgorithmParameterSpec ivspec = new IvParameterSpec(iv);
        byte[] encrypedValue = null;

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
            byte[] ciphertext = cipher.doFinal(
                    toBeEncryped.getBytes("UTF-8"));
            encrypedValue = Base64.getEncoder().encode(ciphertext);
        } catch (InvalidKeyException |
                 InvalidAlgorithmParameterException |
                 IllegalBlockSizeException |
                 BadPaddingException |
                 UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException("...", e);
        }
        return new String(encrypedValue);
    }

    /*
     * Decrypt toBeDecrypted using the secret and passed iv.
     */
    public String decrypt(SecretKey secret, byte[] encodedIV,
                          String toBeDecrypted) throws NoSuchPaddingException, NoSuchAlgorithmException {

        byte[] iv = Base64.getDecoder().decode(encodedIV);
        AlgorithmParameterSpec ivspec = new IvParameterSpec(iv);
        byte[] decryptedValue = null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
            byte[] decodedValue = Base64.getDecoder()
                    .decode(toBeDecrypted.getBytes());
            decryptedValue = cipher.doFinal(decodedValue);
        } catch (InvalidKeyException |
                 InvalidAlgorithmParameterException |
                 IllegalBlockSizeException |
                 BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("...", e);
        }
        return new String(decryptedValue);
    }

    /*
     * Generate an encryption key using PBKDF2 with given
     * salt, iterations and hash bytes.
     */
    public SecretKey generateEncryptionKey(String str, byte[] salt) throws InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException {
        char[] strChars = str.toCharArray();
        KeySpec spec = new PBEKeySpec(strChars, salt,
                ITERATIONS, HASHBYTES);
        SecretKey key;
        try {
            key = factory.generateSecret(spec);
            return new SecretKeySpec(key.getEncoded(), "AES");
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new InternalError("...", e);
        }
    }


}

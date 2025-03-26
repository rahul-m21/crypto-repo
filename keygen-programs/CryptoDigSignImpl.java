import java.security.*;
import java.security.spec.*;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.pqc.jcajce.interfaces.*;
import org.bouncycastle.pqc.jcajce.spec.*;
import org.bouncycastle.util.encoders.Hex;

public class BouncyCastleCrypto {
    static {
        
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Bouncy Castle Cryptographic Operations");
        
        rsaEncryptionDecryption();

        ecdsaSigningVerification();
    }

    public static void rsaEncryptionDecryption() throws Exception {
        System.out.println("\n--- RSA Encryption and Decryption ---");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BCFIPS");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA", "BCFIPS");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] plaintext = "Hello, RSA!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);
        System.out.println("Ciphertext: " + Hex.toHexString(ciphertext));

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(ciphertext);
        System.out.println("Decrypted Text: " + new String(decrypted));
    }

    public static void ecdsaSigningVerification() throws Exception {
        System.out.println("\n--- ECDSA Signing and Verification ---");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BCFIPS");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Signature signature = Signature.getInstance("SHA256withECDSA", "BCFIPS");
        signature.initSign(keyPair.getPrivate());
        byte[] message = "Hello, ECDSA!".getBytes();
        signature.update(message);
        byte[] sigBytes = signature.sign();
        System.out.println("Signature: " + Hex.toHexString(sigBytes));

        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        boolean isValid = signature.verify(sigBytes);
        System.out.println("Signature Valid: " + isValid);
    }


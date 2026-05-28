package bih.iths.sedina.mfasecurity.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Service
public class TwoFactorService {

    @Value("${app.encryption.secret-key}")
    private String secretKey;

    public String generateSecret() {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        return gAuth.createCredentials().getKey();
    }

    public boolean verifyCode(String secret, int code) {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        return gAuth.authorize(secret, code);
    }

    public String getQRUrl(String username, String secret) {
        return String.format("otpauth://totp/%s?secret=%s&issuer=MyMFA",
                username, secret);
    }

    public String encryptSecret(String secret) {

        try {
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");

            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = cipher.doFinal(secret.getBytes());

            return Base64.getEncoder().encodeToString(encrypted);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decryptSecret(String encryptedSecret) {

        try {
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");

            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] decoded = Base64.getDecoder().decode(encryptedSecret);

            return new String(cipher.doFinal(decoded));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
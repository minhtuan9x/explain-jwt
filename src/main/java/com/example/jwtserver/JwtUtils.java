package com.example.jwtserver;

import io.jsonwebtoken.*;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

@Slf4j
public class JwtUtils {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static final int JWT_EXPIRATION_MS = 86400000;

    static {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ClassPathResource("/static/mycert.pfx").getInputStream(), "".toCharArray());
            ks.aliases();
            X509Certificate x509Certificate = (X509Certificate) ks.getCertificate("1");
            // Retrieving the private key.
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("1", new KeyStore.PasswordProtection("".toCharArray()));
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = x509Certificate.getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @SneakyThrows
    public static String generateToken() {
        String token = Jwts.builder()
                .setSubject("tuan")
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + JWT_EXPIRATION_MS))
                .setIssuer("tuando99")
                .claim("test1", Arrays.asList("tuan1", "tuan2"))
                .claim("test2", Arrays.asList("tuan3", "tuan4"))
                .signWith(SignatureAlgorithm.RS256, privateKey).compact();
        log.info(token);
        return token;
    }

    //Print structure of JWT
    public static String printStructure(String token) {
        Jws<Claims> parseClaimsJws = Jwts.parser().setSigningKey(publicKey)
                .parseClaimsJws(token);
        StringBuilder result = new StringBuilder();
        result.append("Header     : ").append(parseClaimsJws.getHeader()).append("\n")
                .append("Body       : ").append(parseClaimsJws.getBody()).append("\n")
                .append("Signature  : ").append(parseClaimsJws.getSignature()).append("\n");
        return result.toString();
    }

    // Add BEGIN and END comments
    public static String convertToPublicKey() {
        String encodedPublicKey = Base64.getUrlEncoder().encodeToString(publicKey.getEncoded());
        StringBuilder result = new StringBuilder();
        result.append("-----BEGIN PUBLIC KEY-----\n");
        result.append(encodedPublicKey);
        result.append("\n-----END PUBLIC KEY-----");
        return result.toString();
    }

    // Add BEGIN and END comments
    public static String convertToPrivateKey() {
        String encodedPublicKey = Base64.getUrlEncoder().encodeToString(privateKey.getEncoded());
        StringBuilder result = new StringBuilder();
        result.append("-----BEGIN PRIVATE KEY-----\n");
        result.append(encodedPublicKey);
        result.append("\n-----END PRIVATE KEY-----");
        return result.toString();
    }

    @RestController
    @RequestMapping("/api")
    public static class Controller123 {

        @GetMapping
        public String generateToken() {
            return JwtUtils.generateToken();
        }

        @GetMapping("/{token}")
        public String verifyToken(@PathVariable String token) {
            return JwtUtils.printStructure(token);
        }

        @GetMapping("/private")
        public String privateKey() {
            return JwtUtils.convertToPrivateKey();
        }

        @GetMapping("/public")
        public String publicKey() {
            return JwtUtils.convertToPublicKey();
        }

    }
}

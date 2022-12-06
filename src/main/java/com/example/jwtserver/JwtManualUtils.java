package com.example.jwtserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Slf4j
public class JwtManualUtils {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static Signature sign;
    private static final int JWT_EXPIRATION_MS = 86400000;
    private static final ObjectMapper objectMapper = new ObjectMapper();


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

            sign = Signature.getInstance("SHA256withRSA");


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @SneakyThrows
    public static String generateToken() {
        String header = "";
        String payload = "";
        String signature = "";

        //building header
        Map<String, Object> mapHeader = new HashMap<>();
        mapHeader.put("alg", "RS256");
        mapHeader.put("kid", JwkUtils.kid);
        header = Base64.getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(mapHeader));

        //building payload
        Map<String, Object> mapPayload = new HashMap<>();
        mapPayload.put("sub", "sample");
        mapPayload.put("iat", new Date().getTime());
        mapPayload.put("exp", new Date(new Date().getTime() + JWT_EXPIRATION_MS));
        mapPayload.put("iss", "tuandovippro");
        payload = Base64.getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(mapPayload));

        //signing
        sign.initSign(privateKey);
        sign.update((header + "." + payload).getBytes(StandardCharsets.UTF_8));
        signature = Base64.getUrlEncoder().encodeToString(sign.sign());

        return header + "." + payload + "." + signature;
    }

    //Print structure of JWT
    @SneakyThrows
    public static boolean validateToken(String token) {
        sign.initVerify(publicKey);

        String header = token.split("\\.")[0];
        String payload = token.split("\\.")[1];
        String signature = token.split("\\.")[2];
        sign.update((header + "." + payload).getBytes(StandardCharsets.UTF_8));

        return sign.verify(Base64.getUrlDecoder().decode(signature));
    }

    @SneakyThrows
    public static boolean validateTokenWithJwk(String token) {
        JwkUtils.Jwks jwks = new RestTemplate().getForObject("http://localhost:8080/jwk", JwkUtils.Jwks.class);
        PublicKey publicKeyNew = getKey(jwks.getN());
        sign.initVerify(publicKeyNew);

        String header = token.split("\\.")[0];

        String kid = new JSONObject(new String(Base64.getUrlDecoder().decode(header.getBytes(StandardCharsets.UTF_8)))).getString("kid");
        if (!kid.equals(jwks.getKid()))
            return false;

        String payload = token.split("\\.")[1];
        String signature = token.split("\\.")[2];
        sign.update((header + "." + payload).getBytes(StandardCharsets.UTF_8));

        return sign.verify(Base64.getUrlDecoder().decode(signature));
    }

    public static PublicKey getKey(String key) {
        key = key.replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("\n-----END PUBLIC KEY-----", "");
        try {
            byte[] byteKey = Base64.getUrlDecoder().decode(key.getBytes());
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePublic(X509publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    @RestController
    @RequestMapping("/api2")
    public static class Controller123 {

        @GetMapping
        public String generateToken() {
            return JwtManualUtils.generateToken();
        }

        @GetMapping("/verify")
        public Boolean verifyToken(@RequestParam String token) {
            return JwtManualUtils.validateToken(token);
        }

        @GetMapping("/verify2")
        public Boolean verifyTokenWithJwk(@RequestParam String token) {
            return JwtManualUtils.validateTokenWithJwk(token);
        }


    }


}

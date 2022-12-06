package com.example.jwtserver;

import lombok.Data;
import lombok.SneakyThrows;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

public class JwkUtils {
    public static final String kid = UUID.randomUUID().toString();

    @SneakyThrows
    public static Jwks getJwks() {
        Jwks jwks = new Jwks();
        jwks.setKid(kid);
        jwks.setAlg("RS256");
        jwks.setKty("RSA");
        jwks.setN(JwtUtils.convertToPublicKey());
        return jwks;
    }

    @Data
    public static class Jwks {
        private String kty;
        private String alg;
        private String kid;
        private String n;
    }

    @RestController
    @RequestMapping("/jwk")
    public static class Controller123 {

        @GetMapping
        public Jwks getJwks() {
            return JwkUtils.getJwks();
        }

    }

}

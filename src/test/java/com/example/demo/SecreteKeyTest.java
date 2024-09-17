package com.example.demo;

import io.jsonwebtoken.Jwts;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

public class SecreteKeyTest {
    @Test
    public void generateKey(){
       SecretKey key=Jwts.SIG.HS256.key().build();
       String encodedKey= DatatypeConverter.printHexBinary(key.getEncoded());
       System.out.printf("\nKey = [%s]\n",encodedKey);
    }
}

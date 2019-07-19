package io.mickeckemi21;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Test;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

public class DeutscheBankJwtTest {

    @Test
    public void useJwtk() throws ParseException, JOSEException {

        String originalPublicKey = "{\n" +
                "  \"keys\": [\n" +
                "    {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"d\": \"Y5tmu8G6bSAaM88YovD-7dURL3v89pnzuqDc7BAJCQE\",\n" +
                "      \"use\": \"sig\",\n" +
                "      \"crv\": \"P-256\",\n" +
                "      \"kid\": \"public-key\",\n" +
                "      \"x\": \"6zDuZkzS_SzQdYBoYaWgW3ObMd6zfka3cmdOYhnVa48\",\n" +
                "      \"y\": \"ctg5NUiRzYU15esh7YQOfrZwMa6WZY6OwOLN_P7tXg4\",\n" +
                "      \"alg\": \"SHA256\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        JWKSet jwkSet = JWKSet.parse(originalPublicKey);

        List<JWK> jwkList = jwkSet.getKeys();

        for (JWK jwk : jwkList) {

            String keyId = jwk.getKeyID();
            ECKey ecKey = (ECKey) jwkSet.getKeyByKeyId(keyId);
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            ECPrivateKey ecPrivateKey = ecKey.toECPrivateKey();

            // Create the EC signer
            JWSSigner signer = new ECDSASigner(ecPrivateKey);

            // Prepare JWT with claims set
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    // for client_credentials the subject
                    // and the issuer must be the client_id
                    .subject("366e91ce-0cef-4553-adc3-f95b25e257e7")
                    .issuer("366e91ce-0cef-4553-adc3-f95b25e257e7")
                    .audience("https://simulator-api.db.com/gw/oidc/token")
                    .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.ES256),
                    claimsSet
            );

            // compute the EC signature
            signedJWT.sign(signer);

            // serialize the JWS to compact form
            String serializedJWT = signedJWT.serialize();

            // on the consumer side, parse the JWS and verify its EC signature
            signedJWT = SignedJWT.parse(serializedJWT);

            JWSVerifier verifier = new ECDSAVerifier(ecPublicKey);
            String clientAssertion = signedJWT.serialize();

            System.out.println(clientAssertion);

        }

    }

}

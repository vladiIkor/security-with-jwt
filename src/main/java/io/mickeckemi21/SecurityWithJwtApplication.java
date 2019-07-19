package io.mickeckemi21;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

@SpringBootApplication
public class SecurityWithJwtApplication {

	public static void main(String[] args) throws ParseException, JOSEException {
//		SpringApplication.run(SecurityWithJwtApplication.class, args);

		String originalPublicKey = args[0];
		String clientId = args[1];

//		String clientId = "366e91ce-0cef-4553-adc3-f95b25e257e7";
//		String originalPublicKey = "{\"keys\": [{\"kty\": \"EC\",\"d\": \"Y5tmu8G6bSAaM88YovD-7dURL3v89pnzuqDc7BAJCQE\",\"use\": \"sig\",\"crv\": \"P-256\",\"kid\": \"public-key\",\"x\": \"6zDuZkzS_SzQdYBoYaWgW3ObMd6zfka3cmdOYhnVa48\",\"y\": \"ctg5NUiRzYU15esh7YQOfrZwMa6WZY6OwOLN_P7tXg4\",\"alg\": \"SHA256\"}]}";

		System.out.println("JWKSet: \n" + originalPublicKey);
		System.out.print("\n");
		System.out.println("Client ID: \n" + clientId);
		System.out.print("\n");

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
					.subject(clientId)
					.issuer(clientId)
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

			System.out.println("Client assertion: \n" + clientAssertion);

		}
	}

}

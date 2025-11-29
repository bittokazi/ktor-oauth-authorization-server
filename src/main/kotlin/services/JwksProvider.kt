package com.bittokazi.ktor.auth.services

import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.server.plugins.di.annotations.Property
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.UUID

interface JwtTokenCustomizer {
    fun customize(user: String? = null, client: OAuthClientDTO?, claims: JWTClaimsSet.Builder): Map<String, Any>
}

class JwksProvider(
    @Property("jwk.private-key-path") val privateKeyPath: String? = null,
    @Property("jwk.public-key-path") val publicKeyPath: String? = null,
    @Property("jwk.key-id") val keyId: String?,
    val jwtTokenCustomizer: JwtTokenCustomizer? = null
) {

    val rsaJwk: RSAKey

    init {
        var rsaPrivateKey: RSAPrivateKey? = null
        var rsaPublicKey: RSAPublicKey? = null
        var tmpKeyId = UUID.randomUUID().toString()

        if (keyId != null) {
            tmpKeyId = keyId
        }

        if (privateKeyPath != null || publicKeyPath != null) {
            rsaPrivateKey = PemUtils.loadPrivateKey(privateKeyPath)
            rsaPublicKey = PemUtils.loadPublicKey(publicKeyPath)

            rsaJwk = RSAKey.Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .keyID(tmpKeyId)
                .build()
        } else {
            val keyPair = generateRsaKey()
            rsaJwk = RSAKey.Builder(keyPair.public as RSAPublicKey)
                .privateKey(keyPair.private)
                .keyID(tmpKeyId)
                .build()
        }
    }

    private fun generateRsaKey(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)
        return keyGen.generateKeyPair()
    }

    fun getPublicJwk(): Map<String, Any> {
        return rsaJwk.toPublicJWK().toJSONObject()
    }

    fun generateJwt(
        subject: String,
        audience: String,
        scopes: List<String> = emptyList(),
        issuer: String,
        expiresInSeconds: Long = 3600,
        userId: String? = null,
        client: OAuthClientDTO? = null,
        tokenType: TokenType,
        user: OAuthUserDTO? = null
    ): String {
        val now = Instant.now()
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(subject)
            .audience(audience)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(expiresInSeconds)))
            .claim("scope", scopes.joinToString(" "))

        jwtTokenCustomizer?.customize(userId, client, claims)?.forEach {
            claims.claim(it.key, it.value)
        }

        claims.claim("token_type", tokenType.name)

        if (tokenType == TokenType.ID_TOKEN && user != null) {
            if ("profile" in scopes) {
                claims.claim("name", "${user.firstName} ${user.lastName}")
                claims.claim("preferred_username", user.username)
            }
            if ("email" in scopes) {
                claims.claim("email", user.email)
            }
        }

        val claimSet = claims
            .jwtID(UUID.randomUUID().toString())
            .build()

        val signer = RSASSASigner(rsaJwk.toPrivateKey())
        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJwk.keyID)
                .build(),
            claimSet
        )

        signedJWT.sign(signer)
        return signedJWT.serialize()
    }
}

object PemUtils {

    fun loadPrivateKey(filename: String?): RSAPrivateKey {
        val keyBytes = parsePEM(loadTextFile(filename!!), "PRIVATE KEY")
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(keySpec) as RSAPrivateKey
    }

    fun loadPublicKey(filename: String?): RSAPublicKey {
        val keyBytes = parsePEM(loadTextFile(filename!!), "PUBLIC KEY")
        val keySpec = X509EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(keySpec) as RSAPublicKey
    }

    private fun parsePEM(pem: String, type: String): ByteArray {
        val cleanPem = pem
            .replace("-----BEGIN $type-----", "")
            .replace("-----END $type-----", "")
            .replace("\\s".toRegex(), "")
        return Base64.getDecoder().decode(cleanPem)
    }

    fun loadTextFile(path: String): String {
        val file = File(path)

        // 1) Absolute or relative file on host filesystem
        if (file.exists()) {
            return file.readText()
        }

        // 2) Resource inside the JAR (from src/main/resources)
        val resourceStream = object {}.javaClass.classLoader.getResourceAsStream(path)
            ?: error("File '$path' not found on filesystem or resources")

        return resourceStream.bufferedReader().readText()
    }
}

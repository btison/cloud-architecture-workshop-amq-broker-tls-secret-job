package org.globex.retail.kubernetes;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

@ApplicationScoped
public class KubernetesRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(KubernetesRunner.class);

    @Inject
    KubernetesClient client;

    public int run() {

        Security.addProvider(new BouncyCastleProvider());

        String namespace = System.getenv("NAMESPACE");
        if (namespace == null || namespace.isBlank()) {
            LOGGER.error("Environment variable 'NAMESPACE' for namespace not set. Exiting...");
            return -1;
        }

        String amqBrokerService = System.getenv().getOrDefault("AMQ_BROKER_SERVICE", "broker-amqp-0-svc");

        String keystorePassword = System.getenv().getOrDefault("KEYSTORE_PASSWD", "password");

        String keystoreAlias = System.getenv().getOrDefault("KEYSTORE_ALIAS", "broker");

        String truststorePassword = System.getenv().getOrDefault("TRUSTSTORE_PASSWD", "password");

        String truststoreAlias = System.getenv().getOrDefault("TRUSTSTORE_ALIAS", "broker");

        String truststoreName = System.getenv().getOrDefault("TRUSTSTORE_NAME", "client-amq.ts");

        String brokerSecretName = System.getenv().getOrDefault("AMQ_BROKER_SECRET", "amq-tls");

        String clientSecretName = System.getenv().getOrDefault("AMQ_CLIENT_SECRET", "client-amq");

        String clientPropertiesName = System.getenv().getOrDefault("AMQ_CLIENT_PROPERTIES", "amq.properties");

        // create broker private key and certificate
        X509Certificate certificate;
        KeyPair keyPair;
        try {
            keyPair = generateKeyPair();

            // create certificate
            Instant validFrom = Instant.now();
            Instant validUntil = validFrom.plus(365, ChronoUnit.DAYS);
            X500Name x500Name = new X500Name("C = US, O = Apache, OU = Qpid, CN = " + amqBrokerService + "." + namespace +".svc");
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(x500Name, BigInteger.valueOf(System.currentTimeMillis()),
                    Date.from(validFrom), Date.from(validUntil), x500Name, keyPair.getPublic())
                    .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                    .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            X509CertificateHolder certHolder = certificateBuilder.build(signer);
            certificate = new JcaX509CertificateConverter().getCertificate(certHolder);

        } catch (NoSuchAlgorithmException | IOException | OperatorCreationException | CertificateException e) {
            LOGGER.error("Exception creating certificate. Exiting.", e);
            return -1;
        }

        // create keystore for Broker
        byte[] ksBytes;
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            char[] pwdArray = keystorePassword.toCharArray();
            keyStore.load(null, pwdArray);
            X509Certificate[] certificateChain = new X509Certificate[1];
            certificateChain[0] = certificate;
            keyStore.setKeyEntry(keystoreAlias, keyPair.getPrivate(), pwdArray, certificateChain);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            keyStore.store(bos, pwdArray);
            bos.close();

            ksBytes = bos.toByteArray();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            LOGGER.error("Exception creating broker keystore. Exiting.", e);
            return -1;
        }

        // create truststore for clients
        byte[] tsBytes;
        try {
            KeyStore trustStore = KeyStore.getInstance("jks");
            char[] pwdArray = truststorePassword.toCharArray();
            trustStore.load(null, pwdArray);
            trustStore.setCertificateEntry(truststoreAlias, certificate);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            trustStore.store(bos, pwdArray);
            bos.close();

            tsBytes = bos.toByteArray();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            LOGGER.error("Exception creating broker keystore. Exiting.", e);
            return -1;
        }

        // AMQ Broker secret
        Secret brokerSecret = new SecretBuilder().withNewMetadata().withName(brokerSecretName).endMetadata().withType("Opaque")
                .addToData("broker.ks", Base64.getEncoder().encodeToString(ksBytes))
                .addToData("client.ts", Base64.getEncoder().encodeToString(ksBytes))
                .addToData("keyStorePassword", Base64.getEncoder().encodeToString(keystorePassword.getBytes()))
                .addToData("trustStorePassword", Base64.getEncoder().encodeToString(keystorePassword.getBytes()))
                .build();

        client.secrets().inNamespace(namespace).resource(brokerSecret).createOrReplace();

        LOGGER.info("Secret " + brokerSecretName + " created.");

        // AMQ client secret
        String clientProperties = """
                broker.amqp.transport.ts.password = %s
                """.formatted(truststorePassword);

        Secret clientSecret = new SecretBuilder().withNewMetadata().withName(clientSecretName).endMetadata().withType("Opaque")
                .addToData(truststoreName, Base64.getEncoder().encodeToString(tsBytes))
                .addToData(clientPropertiesName, Base64.getEncoder().encodeToString(clientProperties.getBytes()))
                .build();

        client.secrets().inNamespace(namespace).resource(clientSecret).createOrReplace();

        LOGGER.info("Secret " + clientSecretName + " created.");

        return 0;

    }

    private SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        DigestCalculator digCalc =
                new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }

    private AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey) throws OperatorCreationException {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        DigestCalculator digCalc =
                new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, IOException {
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.init(new RSAKeyGenerationParameters(new BigInteger(String.valueOf(65537L)), new SecureRandom(), 4096, 64));
        AsymmetricCipherKeyPair keypair =  keyGen.generateKeyPair();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(keypair.getPrivate());
        final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keypair.getPublic());
        PublicKey publicKey = converter.getPublicKey(publicKeyInfo);
        return new KeyPair(publicKey, privateKey);
    }

}

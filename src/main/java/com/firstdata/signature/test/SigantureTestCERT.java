package com.firstdata.signature.test;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;









import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.security.cert.CertPath;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;


public class SigantureTestCERT {

	public static void main(String[] args) throws Exception {

    	Security.addProvider(new BouncyCastleProvider());
		

    	byte[] data = "event=transaction+amount=1099+currency=USD+ref_data=VEVTVA==+status=approved+transaction_id=ET147471+transaction_tag=26376554+transaction_time=1406223305215+transaction_type=authorize".getBytes();
    	byte[] signature = Base64.decodeBase64("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".getBytes());
    	
    	X509Certificate inter = parseCertificate(IOUtils.toString(SigantureTestCERT.class.getResourceAsStream("/cert/inter.pem")));
    	X509Certificate root = parseCertificate(IOUtils.toString(SigantureTestCERT.class.getResourceAsStream("/cert/root.pem")));
    	
		KeyStore ks2 = KeyStore.getInstance("BKS");
		ks2.load(null, null);
		ks2.setCertificateEntry("caInterCert", inter);
		ks2.setCertificateEntry("caRootCert", root);
    	
        
        boolean verified = verifySignature(data, signature, ks2);
        System.out.println("Verified: " + verified);

	}

	

	public static boolean verifySignature(byte[] data, byte[] signature, KeyStore ks) throws Exception {

		
		CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(data), signature);
	
		// check certificate path
		if (ks != null) {
			checkCertificatePath(signedData, ks);
		}
		
		
		// verify signature
        SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        boolean verified = false;
        for (Object o : signerInformationStore.getSigners()) {
            SignerInformation signer = (SignerInformation) o;
            Collection matches = signedData.getCertificates().getMatches(signer.getSID());
            if (!matches.isEmpty()) {
                X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER_NAME).build(certificateHolder))) {
                    verified = true;
                }
            }
        }
        
        return verified;   
	}



	public static String checkCertificatePath(CMSSignedData signedData, KeyStore ks) throws Exception {
        Store certificateStore = signedData.getCertificates();
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(PROVIDER_NAME);
        for (Object o : certificateStore.getMatches(null)) {
            X509CertificateHolder certificateHolder = (X509CertificateHolder) o;
            certificates.add(certificateConverter.getCertificate(certificateHolder));
        }
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
        CertPath certificatePath = certificateFactory.generateCertPath(certificates);

        PKIXParameters params = new PKIXParameters(ks);
        // TODO: Test certificate has no CRLs.  Merchants must perform revocation checks in production.
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", PROVIDER_NAME);
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)validator.validate(certificatePath, params);
        
        System.out.println(result);
        
        return result.toString();
	}
	
	
	public static X509Certificate parseCertificate(String certStr) throws Exception {

	    String str = certStr.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "");
	    byte [] decoded = Base64.decodeBase64(str.getBytes());

	    return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(decoded));
	}
	
	
}

package implementation;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;

import code.GuiException;
import x509.v3.CodeV3;
import gui.*;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public class MyCode extends CodeV3 {

	private KeyStore keyStore = null;
	private char[] storePassword = "root".toCharArray();
	private String currentAlias;
	private PKCS10CertificationRequestBuilder csrBuilder = null;
	private char[] keyPassword = "pass".toCharArray();
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);

		if (keyStore == null) {
			loadLocalKeystore();
		}
	}

	@Override
	public boolean exportCertificate(File file, int encoding) {
		try {
			X509Certificate c = (X509Certificate) keyStore.getCertificate(currentAlias);

			if (encoding == 0) { // DER
				FileOutputStream fos = new FileOutputStream(file);
				fos.write(c.getEncoded());
				fos.close();
			}
			if (encoding == 1) { // PEM
				FileWriter fw = new FileWriter(file);
				PemObject pem = new PemObject("CERTIFICATE", c.getEncoded());
				JcaPEMWriter writer = new JcaPEMWriter(fw);
				writer.writeObject(pem);
				writer.close();
			}
			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public String getIssuer(String keypair_name) {
		System.out.println("Get issuerrRRRRR \n");
		// X509Certificate certificate = getCertificate(keypair_name);
		X509Certificate certificate;
		try {
			certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
			if (certificate != null) {
				X500Principal p = certificate.getIssuerX500Principal();
				System.out.println(p.getName());
				return p.getName();
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		System.out.println("vration bi nulll \n");
		return null;
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String keypair_name) {
		System.out.println("PUBLIC KEY ISSSU \n");
		X509Certificate certificate;
		try {
			certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
			if (certificate != null) {
				PublicKey pk = certificate.getPublicKey();
				return pk.getAlgorithm();
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		// X509Certificate certificate = getCertificate(keypair_name);
		// if (certificate != null) {
		// PublicKey pk = certificate.getPublicKey();
		// return pk.getAlgorithm();
		// }

		return null;
	}

	@Override
	public int getRSAKeyLength(String keypair_name) {
		System.out.println("RSA KEY LEN\n");
		X509Certificate certificate;
		try {
			certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
			if (certificate != null) {
				PublicKey pk = certificate.getPublicKey();
				if (pk instanceof RSAPublicKey) {
					RSAPublicKey rsaPK = (RSAPublicKey) pk;
					return rsaPK.getModulus().bitLength();
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return -1;
		// X509Certificate certificate = getCertificate(keypair_name);
		// PublicKey pk = certificate.getPublicKey();
		// if(pk instanceof RSAPublicKey){
		// RSAPublicKey rsaPK = (RSAPublicKey) certificate.getPublicKey();
		// return rsaPK.getModulus().bitLength();
		// }

		/*
		 * byte[] param = certificate.getSigAlgParams(); try {
		 * AlgorithmParameters alg = AlgorithmParameters.getInstance("RSA");
		 * alg.init(param);
		 * 
		 * RSAKeyGenParameterSpec spec =
		 * alg.getParameterSpec(RSAKeyGenParameterSpec.class); return
		 * spec.getKeysize(); } catch (NoSuchAlgorithmException e) {
		 * e.printStackTrace(); } catch (IOException e) { e.printStackTrace(); }
		 * catch (InvalidParameterSpecException e) { e.printStackTrace(); }
		 * return -1;
		 */
	}

	@Override
	public boolean importCertificate(File file, String keypair_name) {
		InputStream inStream = null;
		try {
			inStream = new FileInputStream(file);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

			keyStore.setCertificateEntry(keypair_name, cert);

			return true;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} finally {
			if (inStream != null) {
				try {
					inStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return false;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		try {
			keyStore = KeyStore.getInstance("pkcs12");
			// Crate new one
			keyStore.load(null, storePassword);
			importKeypair("ETF", "ETFrootCA.p12", "root");
			return keyStore.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void resetLocalKeystore() {
		System.out.println("resetLocalKeystore \n");

		Enumeration<String> aliases = null;
		try {
			aliases = keyStore.aliases();
			List<String> aliasesString = new ArrayList<>();
			while (aliases != null && aliases.hasMoreElements()) {
				aliasesString.add(aliases.nextElement());
			}
			for (String alies : aliasesString) {
				keyStore.deleteEntry(alies);
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean removeKeypair(String keypair_name) {
		try {
			keyStore.deleteEntry(keypair_name);
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean importKeypair(String keypair_name, String fileS, String passwordS) {
		System.out.println("Import KeyPair /n");
		char[] password = passwordS.toCharArray();

		File file = new File(fileS);
		FileInputStream fs = null;
		try {
			KeyStore localKeyStore = KeyStore.getInstance("pkcs12");
			fs = new FileInputStream(file);
			localKeyStore.load(fs, password);

			Enumeration<String> aliasEnum = localKeyStore.aliases();
			String alias = aliasEnum.nextElement();

			System.out.println("Alieas je " + alias);

			// ProtectionParameter protectionParams = new
			// KeyStore.PasswordProtection(null);
			// Entry e = localKeyStore.getEntry(alias, protectionParams);

			PrivateKey pk = (PrivateKey) localKeyStore.getKey(alias, password);
			Certificate[] c = localKeyStore.getCertificateChain(alias);

			keyStore.setKeyEntry(keypair_name, pk, null, c);

			// keyStore.setEntry(keypair_name, e, protectionParams);

			return true;
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportKeypair(String keypair_name, String fileS, String passwordS) {

		File file = new File(fileS);
		//String alies = "noviKljuc";
		try {
			OutputStream os = new FileOutputStream(file);
			ProtectionParameter protectionParams = new KeyStore.PasswordProtection(keyPassword);

//			PrivateKeyEntry pkEntry = (PrivateKeyEntry) keyStore.getEntry(keypair_name, protectionParams);
//			PrivateKey privateKey = pkEntry.getPrivateKey();
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keypair_name, keyPassword);
			KeyStore outKeyStore = KeyStore.getInstance("pkcs12");
			outKeyStore.load(null, null);

			// Certificate[] chain = new Certificate[1];
			// chain[0] = pkEntry.getCertificate();

//			Certificate[] chain = pkEntry.getCertificateChain();
			Certificate[] chain = keyStore.getCertificateChain(keypair_name);
			outKeyStore.setKeyEntry(keypair_name, privateKey, passwordS.toCharArray(), chain);

			outKeyStore.store(os, passwordS.toCharArray());
			os.flush();
			os.close();
			return true;
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	// PROVERITI

	@Override
	public int loadKeypair(String keypair_name) {
		System.out.println("Load Keypair \n");
		currentAlias = keypair_name;// For export
		X509Certificate c;
		try {

			// Key k = keyStore.getKey(arg0, storePassword);
			c = (X509Certificate) keyStore.getCertificate(keypair_name);

			// String signAlg = c.getSigAlgOID();
			String signAlg = c.getSigAlgName();
			access.setSubjectSignatureAlgorithm(signAlg);
			access.setPublicKeySignatureAlgorithm(signAlg);
			// c.getBasicConstraints();
			// nije -1 to je sertifikacioni autoritett return 2
			// == -1 ; getKeyUsed != null niz boolean 5 bit da li je setovan
			// retrun 2
			// ako je nista da li je selfsigned onda je ne potpisan return 0
			// ako nije onda je return 1

			// X500Principal principal = c.getIssuerX500Principal();
			X500Principal principal = c.getSubjectX500Principal();
			String nameString = principal.getName();

			System.out.println(nameString);
			X500Name n = new X500Name(nameString);

			ASN1ObjectIdentifier[] oznake = new ASN1ObjectIdentifier[] { BCStyle.CN, BCStyle.C, BCStyle.ST, BCStyle.L,
					BCStyle.O, BCStyle.OU };

			for (int i = 0; i < oznake.length; i++) {

				RDN[] niz = n.getRDNs(oznake[i]);
				if (niz != null && niz.length != 0) {

					RDN rdnS = niz[0];
					String print = IETFUtils.valueToString(rdnS.getFirst().getValue());

					switch (i) {
					case 0:
						access.setSubjectCommonName(print);
						break;
					case 1:
						access.setSubjectCountry(print);
						break;
					case 2:
						access.setSubjectState(print);
						break;
					case 3:
						access.setSubjectLocality(print);
						break;
					case 4:
						access.setSubjectOrganization(print);
						break;
					case 5:
						access.setSubjectOrganizationUnit(print);
						break;
					default:
						break;
					}
				}
			} // for

			X500Principal issuerPrincipal = c.getIssuerX500Principal();
			X500Name issuer = new X500Name(issuerPrincipal.getName());
			RDN issuerRDN = issuer.getRDNs(BCStyle.CN)[0];
			System.out.println(IETFUtils.valueToString(issuerRDN.getFirst().getValue()));
			access.setIssuer(IETFUtils.valueToString(issuerRDN.getFirst().getValue()));

			// Date
			Date notBefore = c.getNotBefore();
			Date notAfter = c.getNotAfter();

			access.setNotAfter(notAfter);
			access.setNotBefore(notBefore);
			access.setVersion(Constants.V3);

			// Serial Number
			BigInteger serial = c.getSerialNumber();
			String serialS = String.valueOf(serial);
			access.setSerialNumber(serialS);

			// Key Length
			RSAPublicKey rsaPK = (RSAPublicKey) c.getPublicKey();
			int len = rsaPK.getModulus().bitLength();
			String lenS = String.valueOf(len);
			access.setPublicKeyParameter(lenS);

			// Basic Constraints
			int pathLen = c.getBasicConstraints();

			String pathLenS = Integer.toString(pathLen);
			System.out.println(pathLenS);
			boolean basicC = true;
			if (pathLen == -1) {
				pathLenS = "0";
				basicC = false;
			}
			access.setPathLen(pathLenS);
			access.setCA(basicC);

			// IssuerAlternativeNames
			Collection<List<?>> names = c.getIssuerAlternativeNames();
			if (names != null) {
				int i = 0;
				StringBuffer sb = new StringBuffer();
				for (List<?> l : names) {
					for (Object s : l) {
						sb.append(s);
						i++;
					}
				}

				System.out.println("Altenrative names = " + sb.toString() + " I je " + i);
				access.setAlternativeName(Constants.IAN, sb.toString());
			}
			// Certificate polices
			Set<String> oids = c.getCriticalExtensionOIDs();
			if (oids != null) {
				for (String oid : oids) {
					ASN1ObjectIdentifier indentifier = new ASN1ObjectIdentifier(oid);

					byte[] value = c.getExtensionValue(oid);

					if (indentifier.equals(Extension.certificatePolicies)) {
						String s = new String(value);

						System.out.println(s);
						PolicyInformation pi = new PolicyInformation(indentifier);

						access.setAnyPolicy(true);
						access.setCpsUri(oid);
						access.setCritical(Constants.CP, true);
					}

					if (indentifier.equals(Extension.issuerAlternativeName)) {
						access.setCritical(Constants.IAN, true);
					}

					if (indentifier.equals(Extension.basicConstraints)) {
						access.setCritical(Constants.BC, true);
					}
				}
			}

			printKeyStoreContent();
			if (c.getBasicConstraints() != -1) { // Gets a path length
				return 2; // CA
			} else {
				boolean[] b = c.getKeyUsage();
				if (b != null && b[5]) {
					// keyCertSign, true if public key i used to verify a
					// signature on certificate. Only if it is CA
					return 2;
				}
				if (c.getIssuerX500Principal().getName().equals(c.getSubjectX500Principal().getName())) {
					// Self signed
					return 0;
				} else {
					return 1;
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	// Certificate Polices NE RADI
	@Override
	public boolean saveKeypair(String keypair_name) {
		System.out.println("Save KeyPair \n");

		String serialNulmberS = access.getSerialNumber();
		BigInteger seralNumber = new BigInteger(serialNulmberS);

		Date notBefore = access.getNotBefore();
		Date notAfter = access.getNotAfter();

		// Public Key
		String publicKeyAlgorithm = access.getPublicKeyAlgorithm();
		String publicKeyParameterString = access.getPublicKeyParameter();
		int publicKeyParameter = Integer.parseInt(publicKeyParameterString);

		String publicKeySignatureAlgorithm = access.getPublicKeySignatureAlgorithm();

		String subjectCommonName = access.getSubjectCommonName();
		String subjectCountry = access.getSubjectCountry();
		String subjectLocality = access.getSubjectLocality();
		String subjectOrganization = access.getSubjectOrganization();
		String subjectState = access.getSubjectState();
		String subjectSubjectOrganizationUnit = access.getSubjectOrganizationUnit();

		KeyPairGenerator keyGen;
		try {
			// Generate key pair
			keyGen = KeyPairGenerator.getInstance(publicKeyAlgorithm);
			keyGen.initialize(publicKeyParameter);
			KeyPair key = keyGen.generateKeyPair();
			PrivateKey privateKey = key.getPrivate();

			// Public key encoding
			PublicKey pk = key.getPublic();
			AsymmetricKeyParameter p = PublicKeyFactory.createKey(pk.getEncoded());
			SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(p);

			// Create certificate

			// X500NameBuilder
			X500NameBuilder names = new X500NameBuilder();
			if (!subjectCommonName.equals("")) {
				names.addRDN(BCStrictStyle.CN, subjectCommonName);
			}
			if (!subjectSubjectOrganizationUnit.equals("")) {
				names.addRDN(BCStrictStyle.OU, subjectSubjectOrganizationUnit);
			}
			if (!subjectOrganization.equals("")) {
				names.addRDN(BCStrictStyle.O, subjectOrganization);
			}
			if (!subjectLocality.equals("")) {
				names.addRDN(BCStrictStyle.L, subjectLocality);
			}
			if (!subjectState.equals("")) {
				names.addRDN(BCStrictStyle.ST, subjectState);
			}
			if (!subjectCountry.equals("")) {
				names.addRDN(BCStrictStyle.C, subjectCountry);
			}

			X500Name user = names.build();
			// Same as user
			X500Name issuerX500 = user;

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuerX500, seralNumber, notBefore,
					notAfter, user, info);

			// Extensions
		//	if (access.getAnyPolicy()) { // If any is selected

				// Basic constraints
				String pathLenString = access.getPathLen();
				if (!pathLenString.equals("")) {
					Boolean isCrittical = access.isCritical(Constants.BC);
					int pathLen = Integer.parseInt(pathLenString);
					Boolean isCA = access.isCA();
					BasicConstraints bc = null;
					if (isCA) {
						// Sets CA to true
						bc = new BasicConstraints(pathLen);
					} else {
						// Creates without path length
						bc = new BasicConstraints(isCA);
					}
					builder.addExtension(Extension.basicConstraints, isCrittical, bc);
				}

				// Issuer Alternative names
				String[] IssuerAlternativeNames = access.getAlternativeName(Constants.IAN);
				System.out.println("Sa acces " + IssuerAlternativeNames.toString());
				if (IssuerAlternativeNames.length != 0) {

					Boolean isCrittical = access.isCritical(Constants.IAN);

					GeneralName[] gns = new GeneralName[IssuerAlternativeNames.length];
					for (int i = 0; i < IssuerAlternativeNames.length; i++) {
						System.out.println("i = " + i + "String = " + IssuerAlternativeNames[i]);
						gns[i] = new GeneralName(GeneralName.directoryName, IssuerAlternativeNames[i]);
					}
					GeneralNames gn = new GeneralNames(gns);
					builder.addExtension(Extension.issuerAlternativeName, isCrittical, gn);
					System.out.println("DOdao IAN = " + gn.toString());
				}


				
				// Certificate Polices
				String CpsUri = access.getCpsUri();
				Boolean anyPolicy = access.getAnyPolicy();

				if (!CpsUri.equals("") && anyPolicy) {
					// PolicyInformation pi =
					// PolicyInformation.getInstance(CpsUri);
					PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(CpsUri));

					Boolean isCrittical = access.isCritical(Constants.CP);
					builder.addExtension(Extension.certificatePolicies, isCrittical, new CertificatePolicies(pi));
				}

				/*
				 * CertificatePolicies cp = new CertificatePolicies(a);
				 * PolicyInformation[] certPolicies = new PolicyInformation[2];
				 * certPolicies[0] = new PolicyInformation(new
				 * ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.5"));
				 * certPolicies[1] = new PolicyInformation(new
				 * ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.18"));
				 * certGen.addExtension(Extension.certificatePolicies, false,
				 * new CertificatePolicies(certPolicies));
				 */

		//	} // if(anyPolicy)

			// Signs
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
					.find(publicKeySignatureAlgorithm);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

			ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
					.build(PrivateKeyFactory.createKey(privateKey.getEncoded()));

			X509CertificateHolder holder = builder.build(signer);

			//Build a chain
			Certificate c = new JcaX509CertificateConverter().getCertificate(holder);
			Certificate[] chain = new Certificate[1];
			chain[0] = c;

			keyStore.setKeyEntry(keypair_name, privateKey, keyPassword, chain);

			return true;
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean signCertificate(String issuerS, String algorithm) {
		System.out.println("Sign \n");

		try {
			X509Certificate subjectC = (X509Certificate) keyStore.getCertificate(currentAlias);
			X509Certificate issuerC = (X509Certificate) keyStore.getCertificate(issuerS);

			PrivateKey issuerPrivateKey = (PrivateKey) keyStore.getKey(issuerS, keyPassword);

			// subjectC.getSubjectX500Principal().getName();
			// subjectC.getSerialNumber();

			// Generate signer
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

			ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
					.build(PrivateKeyFactory.createKey(issuerPrivateKey.getEncoded()));

			PKCS10CertificationRequest csr = csrBuilder.build(signer);

			// JcaPKCS10CertificationRequest jcaCsr =
			// (JcaPKCS10CertificationRequest) csrBuilder.build(signer);

			// Generate builder for new certificate
			X500Name issuerN = new X500Name(issuerC.getSubjectX500Principal().getName());
			System.out.println("Issuer: " + issuerN);

			X500Name subjectN = new X500Name(subjectC.getSubjectX500Principal().getName());
			System.out.println("Subject: " + subjectN);

			PublicKey subjectPK = subjectC.getPublicKey();
			AsymmetricKeyParameter p = PublicKeyFactory.createKey(subjectPK.getEncoded());
			SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(p);

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuerN, subjectC.getSerialNumber(),
					access.getNotBefore(), access.getNotAfter(), subjectN, info);

			// Add extensions to builder
			Attribute[] attributes = csr.getAttributes();

			Iterator iterator = (Iterator) attributes[0].getAttrValues().iterator();
			Extensions extensions = (Extensions) iterator.next();
			ASN1ObjectIdentifier[] OIDs = extensions.getExtensionOIDs();
			for (int i = 0; i < OIDs.length; i++) {
				builder.addExtension(extensions.getExtension(OIDs[i]));
			}

			X509CertificateHolder holder = builder.build(signer);

			// X509Certificate newCert = new
			// JcaX509CertificateConverter().getCertificate(builder.build(signer));
			// Certificate[] issuerChain=keyStore.getCertificateChain(issuerS);
			// X509Certificate[] chain=new
			// X509Certificate[issuerChain.length+1];
			// chain[0]=newCert;
			// for(int i=1; i<chain.length; i++)
			// {
			// chain[i]=(X509Certificate) issuerChain[i-1];
			// }
			// PrivateKey subjectPrivateKey = (PrivateKey)
			// keyStore.getKey(currentAlias, null);
			// keyStore.setKeyEntry(currentAlias, subjectPrivateKey, null,
			// chain);

			// Builder certificate chain
			Certificate signedC = new JcaX509CertificateConverter().getCertificate(holder);

			Certificate[] issuerChain = keyStore.getCertificateChain(issuerS);

			Certificate[] chain = new Certificate[issuerChain.length + 1];
			chain[0] = signedC;
			for (int i = 1; i < chain.length; i++) {
				chain[i] = issuerChain[i - 1];
			}

//			Certificate[] chain = new Certificate[1];
//			chain[0] = signedC;
	
			PrivateKey subjectPrivateKey = (PrivateKey) keyStore.getKey(currentAlias, keyPassword);
			keyStore.setKeyEntry(currentAlias, subjectPrivateKey, keyPassword, chain);

			
			
			
			return true;

			// Pokusaj

			// ASN1EncodableVector cert_ASN = new ASN1EncodableVector();
			// cert_ASN.add(csr.toASN1Structure());
			// DERSequence cer = new DERSequence(cert_ASN);
			//
			// //X509Certificate x509Cert = (X509Certificate) cer;
			//
			//
			// InputStream in = new ByteArrayInputStream(cer.getEncoded());
			// CertificateFactory factory =
			// CertificateFactory.getInstance("X.509");
			// X509Certificate cert = (X509Certificate)
			// factory.generateCertificate(in);
			//
			// keyStore.setCertificateEntry("Kako si", cert);
			//
			//
			//
			// //X509v3CertificateBuilder builder = new
			// X509v3CertificateBuilder();
			//

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public List<String> getIssuers(String keypair_name) {

		// BesicConstraints i ili key usega 5 bit onaj
		// Nadji sve CA
		List<String> issuers = new ArrayList<>();

		Enumeration<String> aliases = null;
		try {
			aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {

				String alias = aliases.nextElement();
				X509Certificate c = (X509Certificate) keyStore.getCertificate(alias);

				if (c.getBasicConstraints() != -1) {
					issuers.add(alias);
				}
			}
			System.out.println("Get issuerSSSS\n");

			StringBuffer sb = new StringBuffer();
			int i = 0;
			for (String s : issuers) {
				sb.append(s);
				i++;
			}
			System.out.println(sb.toString());
			System.out.println("\n  i je = " + i);
			return issuers;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public boolean generateCSR(String keypair_name) {
		System.out.println("Geneteate CSR \n");

		X509Certificate c;
		try {
			c = (X509Certificate) keyStore.getCertificate(keypair_name);
			PublicKey pk = c.getPublicKey();
			X500Principal p = c.getSubjectX500Principal();

			csrBuilder = new JcaPKCS10CertificationRequestBuilder(p, pk);

//			Set<String> oids = c.getCriticalExtensionOIDs();
//			Set<String> oids1 = c.getNonCriticalExtensionOIDs();
//
//			if (oids != null) {
//				oids.addAll(oids1);
//			} else if (oids1 != null) {
//				oids1.addAll(oids);
//				oids = oids1;
//			}
//
//			if (oids != null) {
//				for (String oid : oids) {
//					ASN1ObjectIdentifier indentifier = new ASN1ObjectIdentifier(oid);
//
//					byte[] value = c.getExtensionValue(oid);
//					DEROctetString o = new DEROctetString(value);
//					csrBuilder.addAttribute(indentifier, o);
//				}
//			}

			
			 JcaX509CertificateHolder holder=new JcaX509CertificateHolder(c);
			 ExtensionsGenerator gen=new ExtensionsGenerator();
			 List<ASN1ObjectIdentifier> list=holder.getExtensionOIDs() ;
			 for(ASN1ObjectIdentifier oid: list){
				 System.out.println("Prosao kroz ekstenzije");
				 gen.addExtension(holder.getExtension(oid));
			 }
			 csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
			 gen.generate());
			
			System.out.println("Geneteate Zavrsio \n");
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		 catch (CertificateEncodingException e) {
		 // TODO Auto-generated catch block
		 e.printStackTrace();
		 }
		return false;
	}

	// Private methods

	private void printKeyStoreContent() {
		StringBuilder sb = new StringBuilder();
		sb.append("Key store content: ");
		Enumeration<String> aliases = null;
		try {
			aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				sb.append(aliases.nextElement() + " , ");
			}
			sb.append("\n");
			System.out.println(sb);

		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}

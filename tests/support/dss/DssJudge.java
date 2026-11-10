// DssJudge validates a signed file with the European Commission's DSS
// library, an implementation independent of trebaruna, and prints what it
// found, one line per signature and per timestamp, for the Go tests to
// read. It runs offline: no certificate is fetched and no list is read.
// The self-signed certificates the file carries, and the certificates
// named as anchors (a test timestamp authority's root the token leaves
// out), are taken as trust anchors, so that the verdict is about the
// signature and not about a missing root.
//
//   java -cp '<dss lib>/*' DssJudge.java <signed file> [detached=<document>...] [anchor=<certificate>...]
//
// signature <id> <indication> <subindication|-> <format> intact=<b> valid=<b> references=<b>
// reference <id> digest=<present>/<match> issuerSerial=<present>/<match>
// signer <id> identified=<b> certificate=<common name|->
// error <id> <what DSS's AdES validation reports>
// timestamp <signature id> <type> imprint=<b> intact=<b> valid=<b>

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class DssJudge {
    public static void main(String[] arguments) {
        DSSDocument document = new FileDocument(new File(arguments[0]));
        List<DSSDocument> detached = new ArrayList<>();
        CommonTrustedCertificateSource anchors = new CommonTrustedCertificateSource();
        for (int index = 1; index < arguments.length; index++) {
            if (arguments[index].startsWith("detached=")) {
                detached.add(new FileDocument(new File(arguments[index].substring("detached=".length()))));
            } else if (arguments[index].startsWith("anchor=")) {
                anchors.addCertificate(DSSUtils.loadCertificate(new File(arguments[index].substring("anchor=".length()))));
            }
        }
        Reports first = validate(document, detached, new CommonTrustedCertificateSource());
        for (CertificateWrapper certificate : first.getDiagnosticData().getUsedCertificates()) {
            if (certificate.isSelfSigned()) {
                anchors.addCertificate(new CertificateToken(DSSUtils.loadCertificate(certificate.getBinaries()).getCertificate()));
            }
        }
        Reports reports = validate(document, detached, anchors);
        DiagnosticData diagnostic = reports.getDiagnosticData();
        SimpleReport simple = reports.getSimpleReport();
        for (String id : simple.getSignatureIdList()) {
            SignatureWrapper signature = diagnostic.getSignatureById(id);
            boolean references = !signature.getDigestMatchers().isEmpty();
            for (XmlDigestMatcher matcher : signature.getDigestMatchers()) {
                references = references && matcher.isDataFound() && matcher.isDataIntact();
            }
            System.out.printf("signature %s %s %s %s intact=%b valid=%b references=%b%n", id, simple.getIndication(id),
                    simple.getSubIndication(id) == null ? "-" : simple.getSubIndication(id), simple.getSignatureFormat(id),
                    signature.isSignatureIntact(), signature.isSignatureValid(), references);
            for (eu.europa.esig.dss.diagnostic.CertificateRefWrapper reference : signature.getSigningCertificateReferences()) {
                System.out.printf("reference %s digest=%b/%b issuerSerial=%b/%b%n", id, reference.isDigestValuePresent(), reference.isDigestValueMatch(),
                        reference.isIssuerSerialPresent(), reference.isIssuerSerialMatch());
            }
            System.out.printf("signer %s identified=%b certificate=%s%n", id, signature.isSigningCertificateIdentified(),
                    signature.getSigningCertificate() == null ? "-" : signature.getSigningCertificate().getCommonName());
            for (eu.europa.esig.dss.jaxb.object.Message message : simple.getAdESValidationErrors(id)) {
                System.out.printf("error %s %s%n", id, message.getValue());
            }
            for (TimestampWrapper timestamp : signature.getTimestampList()) {
                System.out.printf("timestamp %s %s imprint=%b intact=%b valid=%b%n", id, timestamp.getType(),
                        timestamp.isMessageImprintDataFound() && timestamp.isMessageImprintDataIntact(),
                        timestamp.isSignatureIntact(), timestamp.isSignatureValid());
            }
        }
    }

    static Reports validate(DSSDocument document, List<DSSDocument> detached, CommonTrustedCertificateSource anchors) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
        verifier.setOcspSource(null);
        verifier.setCrlSource(null);
        verifier.setTrustedCertSources(anchors);
        validator.setCertificateVerifier(verifier);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_ONLY);
        if (!detached.isEmpty()) {
            validator.setDetachedContents(detached);
        }
        return validator.validateDocument();
    }
}

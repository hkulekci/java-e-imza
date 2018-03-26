package com.mmo;

import com.smartcard.SmartCardManager;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.common.crypto.BaseSigner;
import tr.gov.tubitak.uekae.esya.api.signature.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Calendar;


public class Signer {

    protected static boolean IS_QUALIFIED = true;      // gets only qualified certificates in smart card

    public static void main(String[] args) throws SignatureException, ESYAException {
        Signer signer = new Signer();

        String pin = args[0]; // Check Pin Valid and Exist
        String pdf = args[1]; // Check PDF File Valid and Exist
        File file = new File(pdf);

        try {
            signer.sign(pin, file);
        } catch (IOException e) {
            System.out.println("File not found!");
        }
    }

    public void sign(String pin, File file) throws IOException, ESYAException, SignatureException {
        FileInputStream pdfObj = new FileInputStream(file);
        SignatureContainer pc = SignatureFactory.readContainer(SignatureFormat.PAdES, pdfObj, PadesContextBuilder.createContext());
        ECertificate eCertificate = SmartCardManager.getInstance().getSignatureCertificate(IS_QUALIFIED, !IS_QUALIFIED);
        BaseSigner signer = SmartCardManager.getInstance().getSigner(pin, eCertificate);

        Signature signature = pc.createSignature(eCertificate);
        signature.setSigningTime(Calendar.getInstance());
        signature.sign(signer);
        pc.write(new FileOutputStream(file.getParent() + "/" + file.getName()));
    }
}
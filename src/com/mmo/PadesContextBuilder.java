package com.mmo;

import tr.gov.tubitak.uekae.esya.api.pades.PAdESContext;
import tr.gov.tubitak.uekae.esya.api.signature.config.Config;

import java.io.File;
import java.net.URL;


public class PadesContextBuilder {
    protected static String ROOT_DIR;

    static {
        URL root = PadesContextBuilder.class.getResource("/");
        String classPath = root.getPath();
        File binDir = new File(classPath);
        ROOT_DIR = binDir.getAbsolutePath();

    }

    /**
     * Creates context for signature creation and validation
     *
     * @return created context
     */
    public static PAdESContext createContext() {
        PAdESContext c = new PAdESContext(new File(ROOT_DIR).toURI());
        Config config = new Config(ROOT_DIR + "/config/esya-signature-config.xml");
        c.setConfig(config);
        return c;
    }

}

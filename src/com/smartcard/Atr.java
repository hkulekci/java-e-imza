package com.smartcard;

import junit.framework.TestCase;
import tr.gov.tubitak.uekae.esya.api.common.util.StringUtil;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.SmartOp;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.card.template.AkisTemplate;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

public class Atr extends TestCase
{
	public void testGetAtr() throws Exception
	{
		String [] terminals = SmartOp.getCardTerminals();
		
		String terminal = terminals[0];
		TerminalFactory tf = TerminalFactory.getDefault();
		CardTerminal ct = tf.terminals().getTerminal(terminal);
        Card card = ct.connect("*");
        
        String ATR = StringUtil.toString(card.getATR().getBytes());
        
        System.out.println(ATR);
	}
	
	public void testAddingAtr() throws Exception
	{
		String AKISv12_ATR = "3B9F158131FE45806755454B41451221318073B3A1805A";
				
		AkisTemplate.addATR(AKISv12_ATR);
	}
}

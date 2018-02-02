/**
 * 
 */
package net.bncf.servlet.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.xml.bind.JAXBException;
import javax.xml.bind.PropertyException;

import org.apache.log4j.Logger;

import mx.randalf.digest.MD5;
import net.bncf.crypting.exception.CryptingException;
import net.bncf.xsd.UtenteXsd;
import net.bncf.xsd.authentication.Anagrafica;
import net.bncf.xsd.authentication.Autorizzazioni;
import net.bncf.xsd.authentication.Autorizzazioni.Diritto;
import net.bncf.xsd.authentication.Login;
import net.bncf.xsd.authentication.Utente;
import net.bncf.xsd.authentication.Utente.MsgError;

/**
 * @author massi
 *
 */
public class AuthenticationTest {

	private static Logger log = Logger.getLogger(AuthenticationTest.class);

	private String urlAuthentication = null;

	private UtenteXsd utenteXsd = null;

	/**
	 * 
	 */
	public AuthenticationTest(String urlAuthentication) {
		this.urlAuthentication = urlAuthentication;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		AuthenticationTest userValidator = null;
		MD5 md5 = null;

		try {
			userValidator = new AuthenticationTest("http://localhost:8080/Authentication/servlet/Authentication");

			printEsito(userValidator, "Randazzo", "G@l@ss1@", "192.168.1.85", "intranet2010", "192.168.1.188");
			
			System.out.println("-------------------------------------------------");
			md5 = new MD5();
			printEsito(userValidator,"CFU8", md5.getDigest("G@l@ss1@"), "192.168.1.85", "public2010", "192.168.1.188");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {}
	}

	private static void printEsito(AuthenticationTest userValidator, String login, String password, String ipClient, String archive, String ipStazione) throws Exception {
		UtenteXsd utenteXsd = null;
		try {
			if (userValidator.validate(login, password, ipClient, archive, ipStazione)) {
				System.out.println("Esito Positivo");
			} else {
				System.out.println("Esisto Negativo");
			}

			utenteXsd = userValidator.getUtenteXsd();
			
			if (utenteXsd.getLogin() != null) {
				System.out.println("Login");
				print("\t",utenteXsd.getLogin());
			}
			
			if (utenteXsd.getUtente() != null) {
				System.out.println("Utente");
				print(utenteXsd.getUtente());
			}
			
			if (utenteXsd.getMsgError() != null && utenteXsd.getMsgError().size()>0) {
				System.out.println("MsgError");
				print("\t",utenteXsd.getMsgError());
			}
		} catch (Exception e) {
			throw e;
		}
	}

	private static void print(Utente utente) {
		if (utente.getLogin() != null) {
			System.out.println("\tLogin");
			print("\t\t",utente.getLogin());
		}
		if (utente.getMsgError() != null && utente.getMsgError().size()>0) {
			System.out.println("\tMsgError");
			print("\t\t",utente.getMsgError());
		}
	}

	private static void print(String prefix, List<MsgError> msgError) {
		
		for(int x=0; x<msgError.size(); x++) {
			System.out.println(prefix+"ID: "+msgError.get(x).getId()+"\tValue: "+msgError.get(x).getValue());
		}
	}

	private static void print(String prefix, Login login) {
		
		System.out.println(prefix+"Archive: "+login.getArchive());
		System.out.println(prefix+"IpClient: "+login.getIpClient());
		System.out.println(prefix+"Login: "+login.getLogin());
		System.out.println(prefix+"Password: "+login.getPassword());
		if (login.getAnagrafica() != null) {
			System.out.println(prefix+"Anagrafica");
			print(prefix+"\t", login.getAnagrafica());
		}
		if (login.getAutorizzazioni() != null) {
			System.out.println(prefix+"Autorizzazioni");
			print(prefix+"\t", login.getAutorizzazioni());
		}
	}

	private static void print(String prefix, Autorizzazioni autorizzazioni) {
		
		System.out.println(prefix+"Nome: "+autorizzazioni.getNome());
		if (autorizzazioni.getDiritto() != null && autorizzazioni.getDiritto().size()>0) {
			System.out.println(prefix+"Diritto");
			for(int x=0; x<autorizzazioni.getDiritto().size(); x++) {
				print(prefix+"\t",autorizzazioni.getDiritto().get(x));
			}
		}
	}

	private static void print(String prefix, Diritto diritto) {
		System.out.println(prefix+"ID: "+diritto.getID()+"\tValue: "+diritto.getValue());
	}

	private static void print(String prefix, Anagrafica anagrafica) {
		System.out.println(prefix+"Cognome Nome: "+anagrafica.getCognomeNome());
		if (anagrafica.getLogin() != null) {
			System.out.println(prefix+"Login");
			print(prefix+"\t",anagrafica.getLogin());
		}
	}

	private static void print(String prefix, net.bncf.xsd.authentication.Anagrafica.Login login) {
		System.out.println(prefix+"Cod Bib Ut: "+login.getCodBibUt()+"\tCod Utente: "+login.getCodUtente()+"\tValue: "+login.getValue());
	}

	public boolean validate(String login, String password, String ipClient, String archive, String ipStazione) throws Exception {
		UtenteXsd utenteXsd = null;
		URL url = null;
		URLConnection urlConnection = null;
		OutputStreamWriter osw = null;
		String xml = "";
		InputStream is = null;
		boolean ris = false;

		try {
			utenteXsd = new UtenteXsd(login, password, ipClient, archive, ipStazione);
			url = new URL(urlAuthentication);
			urlConnection = url.openConnection();
			urlConnection.setDoOutput(true);
			osw = new OutputStreamWriter(urlConnection.getOutputStream());
			xml = utenteXsd.writeToString();
			log.debug("Xml: " + xml);
			osw.write("Xml=" + xml);
			osw.flush();
			osw.close();
			this.utenteXsd = new UtenteXsd();
			is = urlConnection.getInputStream();
			this.utenteXsd.read(is);

			if (this.utenteXsd.getMsgError() == null || this.utenteXsd.getMsgError().size() == 0)
				ris = true;
			else {
				for (int x = 0; x < this.utenteXsd.getMsgError().size(); x++)
					log.info("Msg Err: " + this.utenteXsd.getMsgError().get(x).getId() + " - "
							+ this.utenteXsd.getMsgError().get(x).getValue());
			}
		} catch (MalformedURLException e) {
			throw e;
		} catch (PropertyException e) {
			throw e;
		} catch (CryptingException e) {
			throw e;
		} catch (IOException e) {
			throw e;
		} catch (JAXBException e) {
			throw e;
		} catch (Exception e) {
			throw e;
		}
		return ris;
	}

	/**
	 * @return the utenteXsd
	 */
	public UtenteXsd getUtenteXsd() {
		return utenteXsd;
	}
}

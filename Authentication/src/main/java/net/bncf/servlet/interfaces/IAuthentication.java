/**
 * 
 */
package net.bncf.servlet.interfaces;

import java.security.NoSuchAlgorithmException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import mx.randalf.digest.MD5;
import net.bncf.servlet.Authentication;
import net.bncf.xsd.UtenteXsd;

/**
 * Questa classe viene utilizzata per le interfacce per l'autenticazione
 * 
 * @author Massimiliano Randazzo
 *
 */
public abstract class IAuthentication {

	/**
	 * Questa variabile viene utilizzare per loggare l'applicazione
	 */
	private Logger log = Logger.getLogger(Authentication.class);

	/**
	 * Questa variabile viene utilizzata per gestire le informazioni provenienti dal
	 * client
	 */
	protected HttpServletRequest request = null;

	/**
	 * Questa variabile viene utilizzata per gestire le informazioni verso il client
	 */
	protected HttpServletResponse response = null;

	/**
	 * Questa variabile viene utilizzata per la gestione del tracciato xml
	 * proveniente dal client
	 */
	protected UtenteXsd utenteXsd = null;

	/**
	 * Costruttore
	 */
	public IAuthentication() {
	}

	/**
	 * Questo metodo viene utilizzato per inizializzare le procedure
	 * 
	 * @param request
	 *            Questa variabile viene utilizzata per gestire le informazioni
	 *            provenienti dal Client
	 * @param response
	 *            Questa variabile viene utilizzata per gestire le risposte verso il
	 *            Client
	 * @param utenteXsd
	 *            Questa variabile viene utilizzata per gestire il tracciato Xml
	 *            proveniente dal client
	 */
	public void init(HttpServletRequest request, HttpServletResponse response, UtenteXsd utenteXsd) {
		this.request = request;
		this.response = response;
		this.utenteXsd = utenteXsd;
	}

	/**
	 * Questo metodo viene utilizzato per testare la tipologia di archivio
	 */
	public abstract void verifica();

	protected String getIp() {
		String ipAddress = null;
		String[] ips = null;
		String ip = null;

		ipAddress = request.getHeader("X-FORWARDED-FOR");
		if (ipAddress == null) {
			ipAddress = request.getRemoteAddr();
		}
		if (ipAddress.indexOf(",") > -1) {
			ips = ipAddress.split("\\,");
			ip = ips[(ips.length - 1)];
		} else {
			ip = ipAddress;
		}

		return ip;
	}

	/**
	 * Questo metodo viene utilizzato per testare se il client &egrave; autorizzato
	 * 
	 * @param ipAutorizzati
	 *            Lista degli indirizzi autorizzati
	 * @return Indica se il client &egrave; autorizzato
	 */
	protected boolean checkIP(String ipAutorizzati) {

		return checkIP(getIp(), ipAutorizzati);
	}

	/**
	 * Questo metodo viene utilizzato per testare se il client &egrave; autorizzato
	 * 
	 * @param ipAutorizzati
	 *            Lista degli indirizzi autorizzati
	 * @return Indica se il client &egrave; autorizzato
	 */
	protected boolean checkIP(String ipAddress, String ipAutorizzati) {
		boolean ris = false;
		boolean test = false;
		String[] st = null;
		String[] ipClient = null;
		String[] ipAutor = null;
		String[] ips = null;
		String ipCli = null;

		try {
			if (ipAddress.indexOf(",") > -1) {
				ips = ipAddress.split("\\,");
				ipCli = ips[(ips.length - 1)];
			} else {
				ipCli = ipAddress;
			}

			if (ipCli.equals("::1")) {
				ipCli = "127.0.0.1";
			}
			log.debug("ipCli: " + ipCli + " ipAutorizzati: " + ipAutorizzati);
			ipClient = ipCli.replace(".", "\t").split("\t");
			st = ipAutorizzati.split(",");
			log.debug("st.length: " + st.length);
			for (int x = 0; x < st.length; x++) {
				log.debug("st[" + x + "]: " + st[x].trim());
				ipAutor = st[x].trim().replace(".", "\t").split("\t");
				test = true;
				for (int y = 0; y < ipAutor.length; y++) {
					if ((!ipAutor[y].equals("*")) && !ipAutor[y].trim().equals(ipClient[y]))
						test = false;
				}
				if (test)
					ris = true;
			}
		} catch (ArrayIndexOutOfBoundsException e) {
			e.printStackTrace();
		}
		log.debug("ris: " + ris);
		return ris;
	}

	/**
	 * Questo metodo viene utilizzato per testare la password trasmessa
	 * 
	 * @param password
	 * @param passwordDB
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	protected boolean checkPassword(String password, String passwordDB) throws NoSuchAlgorithmException {
		String pwdMd5 = null;
		String pwdMd5DB = null;
		MD5 md5 = null;

		try {
			if (password.length() == 32)
				pwdMd5 = password;
			else {
				md5 = new MD5();
				pwdMd5 = md5.getDigest(password);
			}
			if (passwordDB.length() == 32)
				pwdMd5DB = passwordDB;
			else {
				md5 = new MD5();
				pwdMd5DB = md5.getDigest(passwordDB);
			}
		} catch (NoSuchAlgorithmException e) {
			throw e;
		}
		return pwdMd5.equals(pwdMd5DB);
	}
}

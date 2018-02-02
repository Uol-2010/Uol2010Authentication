/**
 * 
 */
package net.bncf.servlet.archive;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.util.List;

import org.apache.log4j.Logger;
import org.hibernate.HibernateException;

import mx.randalf.configuration.Configuration;
import mx.randalf.configuration.exception.ConfigurationException;
import mx.randalf.hibernate.exception.HibernateUtilException;
import net.bncf.crypting.Crypting;
import net.bncf.crypting.exception.CryptingException;
import net.bncf.servlet.interfaces.IAuthentication;
import net.bncf.uol2010.database.schema.servizi.dao.UtenteDAO;
import net.bncf.uol2010.database.schema.servizi.entity.Utente;
import net.bncf.xsd.authentication.ObjectFactory;

/**
 * Questo metodo viene utilizzata per gestire l'autenticazione dell'archivio
 * utenti Pubblico
 * 
 * @author Massimiliano Randazzo
 * 
 */
public class Public2010 extends IAuthentication {

	/**
	 * Questa variabile viene utilizzare per loggare l'applicazione
	 */
	private Logger log = Logger.getLogger(Public2010.class);

	/**
	 * Costruttore
	 */
	public Public2010() {
		super();
	}

	/**
	 * Questo metodo viene utilizzato per verificare l'archivio utenti Pubblico
	 * 
	 * @see net.bncf.servlet.interfaces.IAuthentication#verifica()
	 */
	@Override
	public void verifica() {
		UtenteDAO utenteDAO = null;
		List<Utente> utentes = null;
		DecimalFormat df7 = new DecimalFormat("0000000");
		String mylogin = null;
		String login = null;
		String email = null;
		ObjectFactory objectFactory = new ObjectFactory();
		Crypting crypting = null;
		String ipAddress = getIp();
		boolean trovato = false;

		try {
			if (checkIP((String) Configuration.getValueDefault("archive.public2010.IP", "127.0.0.1"))) {
				crypting = new Crypting();
				crypting.decrypt(utenteXsd.getLogin().getPassword());
				if (crypting.isValid()) {
					mylogin = utenteXsd.getLogin().getLogin();
					if (mylogin != null) {
						if (mylogin.indexOf("@") > -1)
							email = mylogin;
						else if (mylogin.toUpperCase().startsWith("CFU"))
							login = " " + mylogin.toUpperCase().substring(0, 2)
									+ df7.format(new Integer(mylogin.toUpperCase().substring(3)));
						else if (mylogin.toUpperCase().startsWith(" CF"))
							login = mylogin.toUpperCase().substring(0, 3)
									+ df7.format(new Integer(mylogin.toUpperCase().substring(3)));
						else if (mylogin.toUpperCase().startsWith("CF"))
							login = " " + mylogin.toUpperCase().substring(0, 2)
									+ df7.format(new Integer(mylogin.toUpperCase().substring(2)));
						else
							utenteXsd.addMsgError("Login non composto correttamente");

						if (login != null || email != null) {
							utenteDAO = new UtenteDAO();
							utentes = utenteDAO.find(login, null, null, email, null);
							if (utentes != null) {
								for (Utente utente : utentes) {
									if (checkPassword(crypting.getPassword(), utente.getPassword())) {
										trovato = true;
										login = utente.getId();
										utenteXsd.getLogin().setAnagrafica(objectFactory.createAnagrafica());
										utenteXsd.getLogin().getAnagrafica()
												.setLogin(objectFactory.createAnagraficaLogin());
										utenteXsd.getLogin().getAnagrafica().getLogin()
												.setCodBibUt(login.substring(0, 3));
										utenteXsd.getLogin().getAnagrafica().getLogin()
												.setCodUtente(new BigInteger(login.substring(3)));
										utenteXsd.getLogin().getAnagrafica().getLogin().setValue(login);
										utenteXsd.getLogin().getAnagrafica()
												.setCognomeNome(utente.getCognome() + " " + utente.getNome());
										break;
									}
								}
								if (!trovato) {
									utenteXsd.addMsgError("La Password non \u00E8 valida");
								}
							} else
								utenteXsd.addMsgError("Login non valido");
						}
					} else
						utenteXsd.addMsgError("Login non risulta essere stato indicato");
				} else
					utenteXsd.addMsgError("La stazione [" + ipAddress + "] non \u00E8 stata validata");
			} else
				utenteXsd.addMsgError("La stazione [" + ipAddress + "] non risulta essere autorizzare");
		} catch (NumberFormatException e) {
			log.error(e.getMessage(),e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (CryptingException e) {
			log.error(e.getMessage(),e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (HibernateException e) {
			log.error(e.getMessage(),e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (HibernateUtilException e) {
			log.error(e.getMessage(),e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			log.error(e.getMessage(),e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (ConfigurationException e) {
			log.error(e.getMessage(),e);
			utenteXsd.addMsgError(e.getMessage());
		}
	}
}

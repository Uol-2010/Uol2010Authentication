/**
 * 
 */
package net.bncf.servlet.archive;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.apache.log4j.Logger;
import org.hibernate.HibernateException;

import mx.randalf.configuration.Configuration;
import mx.randalf.configuration.exception.ConfigurationException;
import mx.randalf.hibernate.FactoryDAO;
import mx.randalf.hibernate.exception.HibernateUtilException;
import net.bncf.crypting.Crypting;
import net.bncf.crypting.exception.CryptingException;
import net.bncf.servlet.interfaces.IAuthentication;
import net.bncf.uol2010.database.schema.servizi.dao.AutBibAutUteDAO;
import net.bncf.uol2010.database.schema.servizi.dao.AutBibModAmmDAO;
import net.bncf.uol2010.database.schema.servizi.dao.AutBibServiziDAO;
import net.bncf.uol2010.database.schema.servizi.dao.UtenteBibDAO;
import net.bncf.uol2010.database.schema.servizi.entity.AutBibAutUte;
import net.bncf.uol2010.database.schema.servizi.entity.AutBibModAmm;
import net.bncf.uol2010.database.schema.servizi.entity.AutBibServizi;
import net.bncf.uol2010.database.schema.servizi.entity.AutorizzazioniBib;
import net.bncf.uol2010.database.schema.servizi.entity.AutorizzazioniUte;
import net.bncf.uol2010.database.schema.servizi.entity.ModuliAmministrazione;
import net.bncf.uol2010.database.schema.servizi.entity.Servizi;
import net.bncf.uol2010.database.schema.servizi.entity.UtenteBib;
import net.bncf.xsd.authentication.Autorizzazioni;
import net.bncf.xsd.authentication.Autorizzazioni.Diritto;
import net.bncf.xsd.authentication.ObjectFactory;

/**
 * Questo metodo viene utilizzata per gestire l'autenticazione dell'archivio
 * utenti Pubblico
 * 
 * @author Massimiliano Randazzo
 * 
 */
public class Intranet2010 extends IAuthentication {

	/**
	 * Questa variabile viene utilizzare per loggare l'applicazione
	 */
	private Logger log = Logger.getLogger(Intranet2010.class);

	/**
	 * Costruttore
	 */
	public Intranet2010() {
		super();
	}

	/**
	 * Questo metodo viene utilizzato per verificare l'archivio utenti Pubblico
	 * 
	 * @see net.bncf.servlet.interfaces.IAuthentication#verifica()
	 */
	@Override
	public void verifica() {
		UtenteBibDAO utenteBibDAO = null;
		List<UtenteBib> utenteBibs = null;
		ObjectFactory objectFactory = new ObjectFactory();
		Crypting crypting = null;
		String ipAddress = getIp();

		try {
			if (checkIP((String) Configuration.getValueDefault("archive.intranet2010.IP", "127.0.0.1"))) {
				crypting = new Crypting();
				crypting.decrypt(utenteXsd.getLogin().getPassword());
				if (crypting.isValid()) {
					if (utenteXsd.getLogin().getLogin() != null) {
						utenteBibDAO = new UtenteBibDAO();
						utenteBibs = utenteBibDAO.findByLogin(utenteXsd.getLogin().getLogin());

						if (utenteBibs != null) {
							for (UtenteBib utenteBib: utenteBibs) {
							if (checkPassword(crypting.getPassword(), utenteBib.getPassword())) {
								if (checkIP(utenteXsd.getLogin().getIpClient(), utenteBib.getIndirizzoIP())) {
									FactoryDAO.initialize(utenteBib.getIdAutorizzazioniBib());
									if (utenteBib.getIdAutorizzazioniBib() != null) {
										utenteXsd.getLogin().setAnagrafica(objectFactory.createAnagrafica());
										utenteXsd.getLogin().getAnagrafica()
												.setLogin(objectFactory.createAnagraficaLogin());
										utenteXsd.getLogin().getAnagrafica().getLogin()
												.setValue(utenteXsd.getLogin().getLogin());
										utenteXsd.getLogin().getAnagrafica().setCognomeNome(utenteBib.getCognome()
												+ (utenteBib.getNome() == null ? "" : (" " + utenteBib.getNome())));

										utenteXsd.getLogin().setAutorizzazioni(objectFactory.createAutorizzazioni());
										utenteXsd.getLogin().getAutorizzazioni()
												.setNome(utenteBib.getIdAutorizzazioniBib().getDescrizione());

										readAutorizzazioniUtente(utenteXsd.getLogin().getAutorizzazioni(),
												utenteBib.getIdAutorizzazioniBib());
										readAutorizzazioniServizi(utenteXsd.getLogin().getAutorizzazioni(),
												utenteBib.getIdAutorizzazioniBib());
										readAutorizzazioniModuli(utenteXsd.getLogin().getAutorizzazioni(),
												utenteBib.getIdAutorizzazioniBib());
									} else
										utenteXsd.addMsgError("Il profilo relatio all'utente non esiste");
								} else
									utenteXsd.addMsgError("Il client finale [" + utenteXsd.getLogin().getIpClient()
											+ "] non \u00E8 autorizzato");
							} else
								utenteXsd.addMsgError("La Password non \u00E8 valida");
							}
						} else
							utenteXsd.addMsgError("Login non valido");
					} else
						utenteXsd.addMsgError("Login non risulta essere stato indicato");
				} else
					utenteXsd.addMsgError("La stazione [" + ipAddress + "] non \u00E8 stata validata");
			} else
				utenteXsd.addMsgError("La stazione [" + ipAddress + "] non risulta essere autorizzare");
		} catch (NumberFormatException e) {
			log.error(e.getMessage(), e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (CryptingException e) {
			log.error(e.getMessage(), e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (HibernateUtilException e) {
			log.error(e.getMessage(), e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			log.error(e.getMessage(), e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (HibernateException e) {
			log.error(e.getMessage(), e);
			utenteXsd.addMsgError(e.getMessage());
		} catch (ConfigurationException e) {
			log.error(e.getMessage(), e);
			utenteXsd.addMsgError(e.getMessage());
		}
	}

	private void readAutorizzazioniUtente(Autorizzazioni autorizzazioni, AutorizzazioniBib autorizzazioniBib)
			throws HibernateUtilException {
		AutBibAutUteDAO autBibAutUteDAO = null;
		List<AutBibAutUte> autBibAutUtes = null;

		try {
			autBibAutUteDAO = new AutBibAutUteDAO();
			autBibAutUtes = autBibAutUteDAO.find(autorizzazioniBib, null, null);
			for (AutBibAutUte autBibAutUte : autBibAutUtes) {
				FactoryDAO.initialize(autBibAutUte.getIdAutorizzazioniUte());
				autorizzazioni.getDiritto().add(getAutorizzazioneUtente(autBibAutUte.getIdAutorizzazioniUte()));
			}
		} catch (HibernateException e) {
			throw e;
		} catch (HibernateUtilException e) {
			throw e;
		}
	}

	private Diritto getAutorizzazioneUtente(AutorizzazioniUte autorizzazioniUtente) {
		Diritto diritto = null;

		if (autorizzazioniUtente != null) {
			diritto = new Diritto();
			diritto.setID(autorizzazioniUtente.getId());
			diritto.setValue(autorizzazioniUtente.getDescrizione());
		}
		return diritto;
	}

	private void readAutorizzazioniServizi(Autorizzazioni autorizzazioni, AutorizzazioniBib autorizzazioniBib) throws HibernateUtilException {
		AutBibServiziDAO autBibServiziDAO = null;
		List<AutBibServizi> autBibServizis = null;

		try {
			autBibServiziDAO = new AutBibServiziDAO();
			autBibServizis = autBibServiziDAO.find(autorizzazioniBib, null, null);
			for (AutBibServizi autBibServizi : autBibServizis) {
				FactoryDAO.initialize(autBibServizi.getIdServizi());
				autorizzazioni.getDiritto().add(getAutorizzazioniServizi(autBibServizi.getIdServizi()));
			}
		} catch (HibernateException e) {
			throw e;
		} catch (HibernateUtilException e) {
			throw e;
		}
	}

	private Diritto getAutorizzazioniServizi(Servizi servizi) {
		Diritto diritto = null;

		if (servizi != null) {
			diritto = new Diritto();
			diritto.setID(servizi.getId());
			diritto.setValue(servizi.getDescrizione());
		}
		return diritto;
	}

	private void readAutorizzazioniModuli(Autorizzazioni autorizzazioni, AutorizzazioniBib autorizzazioniBib) throws HibernateUtilException {
		AutBibModAmmDAO autBibModAmmDAO = null;
		List<AutBibModAmm> autBibModAmms = null;

		try {
			autBibModAmmDAO = new AutBibModAmmDAO();
			autBibModAmms = autBibModAmmDAO.find(autorizzazioniBib, null, null);
			for (AutBibModAmm autBibModAmm : autBibModAmms) {
				FactoryDAO.initialize(autBibModAmm.getIdModuliAmministrazione());
				autorizzazioni.getDiritto()
						.add(getAutorizzazioniModuli(autBibModAmm.getIdModuliAmministrazione()));
			}
		} catch (HibernateException e) {
			throw e;
		} catch (HibernateUtilException e) {
			throw e;
		}
	}

	private Diritto getAutorizzazioniModuli(ModuliAmministrazione moduliAmministrazione) {
		Diritto diritto = null;

		if (moduliAmministrazione != null) {
			diritto = new Diritto();
			diritto.setID(moduliAmministrazione.getId());
			diritto.setValue(moduliAmministrazione.getDescrizione());
		}
		return diritto;
	}
}

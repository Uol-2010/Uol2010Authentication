package net.bncf.servlet;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;

import org.apache.log4j.Logger;

import mx.randalf.configuration.Configuration;
import mx.randalf.configuration.exception.ConfigurationException;
import net.bncf.servlet.archive.Intranet2010;
import net.bncf.servlet.archive.Public2010;
import net.bncf.servlet.interfaces.IAuthentication;
import net.bncf.xsd.UtenteXsd;
import net.bncf.xsd.authentication.Login;

/**
 * Servlet implementation class for Servlet: Authentication
 * 
 */
public class Authentication extends javax.servlet.http.HttpServlet implements javax.servlet.Servlet {

	/**
	 * Questa variabile viene utilizzare per loggare l'applicazione
	 */
	private Logger log = Logger.getLogger(Authentication.class);

	/**
	 * Questa variabile vine utilizzata per indicare il Serial Version UID della
	 * classe
	 */
	static final long serialVersionUID = 1L;

	/**
	 * 
	 * @see javax.servlet.http.HttpServlet#HttpServlet()
	 */
	public Authentication() {
		super();
	}

	/**
	 * 
	 * @see javax.servlet.http.HttpServlet#doGet(HttpServletRequest request,
	 *      HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		esegui(request, response);
	}

	/**
	 * 
	 * @see javax.servlet.http.HttpServlet#doPost(HttpServletRequest request,
	 *      HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		esegui(request, response);
	}

	/**
	 * Questo metodo viene utilizzato per la gestione del risultato della richiesta
	 * sia di tipo Get che Post
	 * 
	 * @param request
	 *            Questa variable indica tutte le informazioni ricevute dal client
	 * @param response
	 *            Questa variabile viene utilizzata per dare le risposte al client
	 * @throws ServletException
	 *             Eccezione di tipo Servlet
	 * @throws IOException
	 *             Eccezione di tipo IO
	 */
	@SuppressWarnings({ "unused", "rawtypes" })
	private void esegui(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		UtenteXsd utenteXsd = null;
		ByteArrayInputStream bais = null;
		Login login = null;
		Class myClass = null;
		IAuthentication archive = null;

		try {
			utenteXsd = new UtenteXsd();
			if (request.getParameter("Xml") != null) {
				bais = new ByteArrayInputStream(request.getParameter("Xml").getBytes());
				utenteXsd.read(bais);
			} else
				utenteXsd.read(request.getInputStream());

			login = utenteXsd.getLogin();
			if (login != null) {
				if (login.getArchive() != null) {
					if (login.getArchive().equals("public2010")) {
						archive = new Public2010();
					} else if (login.getArchive().equals("intranet2010")) {
						archive = new Intranet2010();
					}
					if (archive != null) {
						archive.init(request, response, utenteXsd);
						archive.verifica();
					} else
						utenteXsd.addMsgError("Titpologia di Archivio non gestita");
				} else
					utenteXsd.addMsgError("Archivio non indicato");
			} else
				utenteXsd.addMsgError("Oggetto Passato non ben formattato");
		} catch (JAXBException e) {
			log.error(e);
			throw new ServletException(e.getMessage());
		} finally {
			try {
				if (bais != null)
					bais.close();

				if (utenteXsd != null)
					utenteXsd.write(response.getOutputStream());
//			} catch (PropertyException e) {
//				log.error(e);
//				throw new ServletException(e.getMessage());
			} catch (JAXBException e) {
				log.error(e);
				throw new ServletException(e.getMessage());
			} catch (Exception e) {
				log.error(e);
				throw new ServletException(e.getMessage());
			}
		}
	}

	/**
	 * 
	 * @see javax.servlet.GenericServlet#init()
	 */
	public void init() throws ServletException {
		String pathProperties = "";
		String nomeCatalogo = null;
		String[] st = null;
		File f = null;
		super.init();

		try {
			nomeCatalogo = this.getServletContext().getInitParameter("nomeCatalogo");
			if (nomeCatalogo != null && !nomeCatalogo.trim().equals("")) {
				st = nomeCatalogo.split("\\|");
				for (int x=0 ; x<st.length; x++) {
					if (st[x].startsWith("file://")) {
						f = new File(st[x].substring(7));
					} else {
						f = new File(System.getProperty("catalina.base") + File.separator+st[x]);
					}
					if (f.exists()) {
						pathProperties = f.getAbsolutePath();
						break;
					}
				}
			} 
			
			if (pathProperties ==null) {
				throw new ServletException("Percorso del file di configurazione non indicato o errato");
			}
			Configuration.init(pathProperties, "Servizi.properties");
		} catch (ConfigurationException e) {
			throw new ServletException(e.getMessage(), e);
		}
	}
}
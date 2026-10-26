/**
This application is for demonstration use only. It contains known application security
vulnerabilities that were created expressly for demonstrating the functionality of
application security testing tools. These vulnerabilities may present risks to the
technical environment in which the application is installed. You must delete and
uninstall this demonstration application upon completion of the demonstration for
which it is intended. 

IBM DISCLAIMS ALL LIABILITY OF ANY KIND RESULTING FROM YOUR USE OF THE APPLICATION
OR YOUR FAILURE TO DELETE THE APPLICATION FROM YOUR ENVIRONMENT UPON COMPLETION OF
A DEMONSTRATION. IT IS YOUR RESPONSIBILITY TO DETERMINE IF THE PROGRAM IS APPROPRIATE
OR SAFE FOR YOUR TECHNICAL ENVIRONMENT. NEVER INSTALL THE APPLICATION IN A PRODUCTION
ENVIRONMENT. YOU ACKNOWLEDGE AND ACCEPT ALL RISKS ASSOCIATED WITH THE USE OF THE APPLICATION.

IBM AltoroJ
(c) Copyright IBM Corp. 2008, 2013 All Rights Reserved.
 */
package com.ibm.security.appscan.altoromutual.servlet;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.security.appscan.altoromutual.util.ServletUtil;

/**
 * Administrator login servlet
 * @author Alexei
 */
public class AdminLoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final String PASSWORD_VERIFIER_ENV = "ADMIN_PASSWORD_VERIFIER";
	private static final String PASSWORD_SALT_ENV = "ADMIN_PASSWORD_SALT";
	private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
	private static final int PBKDF2_ITERATIONS = 310000;
	private static final int DERIVED_KEY_LENGTH = 256;
	private static final int MINIMUM_SALT_LENGTH = 16;
	private static final int MAXIMUM_SALT_LENGTH = 1024;
	private volatile PasswordConfiguration passwordConfiguration;

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String password = request.getParameter("password");
		if (password == null){
			response.sendRedirect(request.getContextPath()+"/admin/login.jsp");
			return ;
		} else if (!verifyPassword(password)){
			request.setAttribute("loginError", "Login failed.");
			RequestDispatcher dispatcher = request.getRequestDispatcher("/admin/login.jsp");
			dispatcher.forward(request, response);
			return;
		} else {
			request.getSession(true).setAttribute(ServletUtil.SESSION_ATTR_ADMIN_KEY, ServletUtil.SESSION_ATTR_ADMIN_VALUE);
			response.sendRedirect(request.getContextPath()+"/admin/admin.jsp");
		}
	}

	@Override
	public void init() throws ServletException {
		super.init();
		try {
			passwordConfiguration = loadConfiguration();
		} catch (GeneralSecurityException e) {
			getServletContext().log("Administrator password authentication is unavailable: "
					+ "PBKDF2WithHmacSHA256 is not supported by this runtime.", e);
			passwordConfiguration = null;
		}
	}

	private PasswordConfiguration loadConfiguration() throws GeneralSecurityException {
		byte[] verifier = decodeBase64(System.getenv(PASSWORD_VERIFIER_ENV));
		byte[] salt = decodeBase64(System.getenv(PASSWORD_SALT_ENV));
		try {
			if (verifier == null || verifier.length != DERIVED_KEY_LENGTH / 8
					|| salt == null || salt.length < MINIMUM_SALT_LENGTH
					|| salt.length > MAXIMUM_SALT_LENGTH) {
				return null;
			}
			/* Check provider support during startup instead of the first login. */
			SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
			return new PasswordConfiguration(verifier, salt);
		} finally {
			if (verifier != null) {
				Arrays.fill(verifier, (byte) 0);
			}
			if (salt != null) {
				Arrays.fill(salt, (byte) 0);
			}
		}
	}

	private boolean verifyPassword(String password) {
		PasswordConfiguration configuration = passwordConfiguration;
		if (configuration == null) {
			return false;
		}

		PBEKeySpec keySpec = null;
		byte[] derivedVerifier = null;
		char[] passwordChars = password.toCharArray();
		try {
			keySpec = new PBEKeySpec(passwordChars, configuration.salt,
					PBKDF2_ITERATIONS, DERIVED_KEY_LENGTH);
			derivedVerifier = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
					.generateSecret(keySpec).getEncoded();
			return MessageDigest.isEqual(configuration.verifier, derivedVerifier);
		} catch (GeneralSecurityException e) {
			return false;
		} finally {
			if (keySpec != null) {
				keySpec.clearPassword();
			}
			if (derivedVerifier != null) {
				Arrays.fill(derivedVerifier, (byte) 0);
			}
			Arrays.fill(passwordChars, '\0');
		}
	}

	private static byte[] decodeBase64(String value) {
		if (value == null || value.length() == 0 || (value.length() & 3) != 0) {
			return null;
		}
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
					|| (c >= '0' && c <= '9') || c == '+' || c == '/'
					|| (c == '=' && i >= value.length() - 2))) {
				return null;
			}
		}
		try {
			byte[] decoded = DatatypeConverter.parseBase64Binary(value);
			if (!value.equals(DatatypeConverter.printBase64Binary(decoded))) {
				Arrays.fill(decoded, (byte) 0);
				return null;
			}
			return decoded;
		} catch (IllegalArgumentException e) {
			return null;
		}
	}

	@Override
	public synchronized void destroy() {
		if (passwordConfiguration != null) {
			passwordConfiguration.clear();
			passwordConfiguration = null;
		}
		super.destroy();
	}

	private static final class PasswordConfiguration {
		private final byte[] verifier;
		private final byte[] salt;

		private PasswordConfiguration(byte[] verifier, byte[] salt) {
			this.verifier = Arrays.copyOf(verifier, verifier.length);
			this.salt = Arrays.copyOf(salt, salt.length);
		}

		private void clear() {
			Arrays.fill(verifier, (byte) 0);
			Arrays.fill(salt, (byte) 0);
		}
	}
}

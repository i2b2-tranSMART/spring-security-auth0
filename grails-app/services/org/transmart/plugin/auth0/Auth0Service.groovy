package org.transmart.plugin.auth0

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.jcraft.jsch.UserInfo
import grails.compiler.GrailsCompileStatic
import grails.converters.JSON
import grails.gsp.PageRenderer
import grails.plugin.cache.Cacheable
import grails.plugin.mail.MailService
import grails.plugin.springsecurity.SpringSecurityService
import grails.transaction.Transactional
import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import groovy.transform.Immutable
import groovy.util.logging.Slf4j
import org.apache.commons.validator.routines.EmailValidator
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.transaction.TransactionStatus
import org.springframework.web.context.request.RequestContextHolder
import org.transmart.plugin.custom.CustomizationConfig
import org.transmart.plugin.custom.CustomizationService
import org.transmart.plugin.custom.Settings
import org.transmart.plugin.custom.UserLevel
import org.transmart.plugin.shared.SecurityService
import org.transmart.plugin.shared.UtilService
import org.transmart.plugin.shared.security.Roles
import org.transmart.searchapp.AuthUser
import org.transmart.searchapp.Role
import org.transmartproject.db.log.AccessLogService
import us.monoid.json.JSONArray
import us.monoid.json.JSONObject
import us.monoid.web.Resty

import grails.plugins.rest.client.RestBuilder
import grails.plugins.rest.client.RestResponse

import javax.servlet.http.HttpServletRequest

/**
 * @author <a href='mailto:burt_beckwith@hms.harvard.edu'>Burt Beckwith</a>
 */
@GrailsCompileStatic
@Slf4j('logger')
class Auth0Service implements InitializingBean {

	private static final List<ProviderInfo> AUTH0_PROVIDERS = [
			new ProviderInfo(webtaskName: 'google-oauth2',  displayName: 'Google',                     subPrefix: 'google-oauth2|'),
			new ProviderInfo(webtaskName: 'github',         displayName: 'GitHub',                     subPrefix: 'github|'),
			new ProviderInfo(webtaskName: 'ORCiD',          displayName: 'ORCiD',                      subPrefix: 'oauth2|ORCiD|'),
			new ProviderInfo(webtaskName: 'hms-it',         displayName: 'Harvard Medical School',     subPrefix: 'samlp|'),
			new ProviderInfo(webtaskName: 'nih-gov-prod',   displayName: 'eRA Commons',                subPrefix: 'samlp|'),
			new ProviderInfo(webtaskName: 'ldap-connector', displayName: "Boston Children's Hospital", subPrefix: 'ad|ldap-connector|')].asImmutable()

	private static final String CREDENTIALS_KEY = 'auth0Credentials'
	private static final char DASH = '-'
	private static final char X = 'X'

    private Algorithm algorithm
	private String oauthTokenUrl
	private String userInfoUrl
	private final List<ProviderInfo> activeProviders = []

	@Autowired private AccessLogService accessLogService
	@Autowired private AuthService authService
	@Autowired private CustomizationConfig customizationConfig
	@Autowired private CustomizationService customizationService
	@Autowired private MailService mailService
	@Autowired private PageRenderer groovyPageRenderer
	@Autowired private SecurityService securityService
	@Autowired private SpringSecurityService springSecurityService
	@Autowired private UserService userService
	@Autowired private UtilService utilService

	@Autowired(required = false)
	private Auth0Config auth0Config

	List<ProviderInfo> getAuth0Providers() {
		activeProviders
	}

	/**
	 * Handle the Auth0 callback.
	 * @param code the code to use to get an access token
	 * @return a 1-element map with either a redirect uri under the 'uri' key
	 *         or a redirect action under the 'action' key
	 */
	Map<String, String> callback(String code) {
		logger.debug "callback() starting"

		HttpServletRequest request = currentRequest()
		String port
		String scheme = request.scheme.toLowerCase()
		if ((scheme == 'http' && request.serverPort == 80) || (scheme == 'https' && request.serverPort == 443)) {
			port = ''
		}
		else {
			port = ':' + request.serverPort
		}
		String redirectUri = request.scheme + '://' + request.serverName + port + request.contextPath

        logger.debug 'callback() calling createCredentials() with redirectUri {}', redirectUri
		Credentials credentials = createCredentials(code, redirectUri)
        logger.debug 'callback() credentials:', credentials

		if (credentials.username && credentials.level > UserLevel.ZERO) {
			credentials.tosVerified = verifyTOSAccepted(credentials.id)
			if (credentials.tosVerified) {
				authenticateAs credentials
				logger.info 'callback() Successfully authenticated'
                logger.debug 'callback() redirecting to ',auth0Config.redirectOnSuccess
				[uri: auth0Config.redirectOnSuccess]
			}
			else {
				logger.info 'callback() authenticated but needs TOS, redirecting to `tos`'
				[action: 'tos']
			}
		}
		else {
			if (auth0Config.registrationEnabled) {
				logger.info 'callback() Redirecting to `registration`'
				[action: 'registration']
			}
			else {
				logger.info 'callback() Registration not enabled, redirecting to `notauthorized`'
				[action: 'notauthorized']
			}
		}
	}

	/**
	 * @return the <code>Credentials</code> instance from the HTTP session
	 */
	Credentials credentials() {
		(Credentials) currentRequest().session.getAttribute(CREDENTIALS_KEY)
	}

    /**
     * Determine if the user logging in has already been recorded before, where the sub-id is the same
     * as the uniqueId and email matches the stored e-mail value. After the first successful login,
     * the uniqueId for the user has been updated from the 'sub' claim from the userinfo JSON, and
     * should match every time the logs in again.
     * @param userInfo the full Auth0 profile for the user that was returned by the /userinfo endpoint
     */
    @Transactional
    AuthUser getUser(JSONObject userInfo) {
        logger.debug 'getUser() starting, with userinfo {} ', userInfo

		def auth0provider
		auth0provider = userInfo.getJSONArray('identities').getJSONObject(0).getString('provider')
		if (auth0provider == null || auth0provider.isEmpty()) {
			throw new RuntimeException("Cannot get provider information. User cannot be authenticated.")
		}
        String lookupKey = ""
        //ProviderInfo providerInfo = AUTH0_PROVIDERS.find { ProviderInfo pi -> user.uniqueId?.startsWith pi.subPrefix }
		switch (auth0provider) {
			case "ad":
				// LDAP, use the nickname, which is the BCH user id
                lookupKey = "ad|ldap-connector|"+userInfo.getString('nickname')
				break
			case "samlp":
				// SAML, use the e-mail
                lookupKey = "samlp|"+userInfo.getString('email')
				break
			case "google-oauth2":
				// Google, use the e-mail
                lookupKey = "google-oauth2|"+userInfo.getString('email')
				break
			case "github":
				// Github, use the nickname (a.k.a username on GitHub)
                lookupKey = "github|"+userInfo.getString('nickname')
				break
			case "oauth2":
				// OAUTH2, most likely ORCiD, but use the full `sub` claim, regardless
                lookupKey = "oauth2|"
                String oauth2connectionName = userInfo.getJSONArray('identities').getJSONObject(0).getString('connection')
                if (oauth2connectionName.equals("ORCiD")) {
                    logger.debug 'getUser() connectionName:{}', oauth2connectionName
                    lookupKey = userInfo.getString('sub')
                } else {
                    logger.error "getUser() Unknown Auth0 oauth2 connection {}.", oauth2connectionName
                    throw new RuntimeException("Unknown Auth0 oauth2 connection");
                }
				break
			default:
				logger.error "getUser() Cannot handle Auth0 provider {}.", auth0provider
				throw new RuntimeException("Cannot handle Auth0 provider")
		}
        Map args = [:]
        // Use the `sub` claim by default
        logger.debug 'getUser() lookupKey:{}', lookupKey
        args.uniqueId = lookupKey
        // args.email = userInfo.getString('email').toLowerCase()
        logger.debug 'getUser() lookup by uniqId:{}', args.uniqueId

        // TODO: This should NOT be an SQL statement, maybe later we could convert this to a GORM query!?
		String hql = "select u from AuthUser u where u.passwd='auth0' and lower(u.uniqueId) LIKE lower(:uniqueId)||'%'"
        logger.debug 'getUser() SQL: {}', hql
        List<AuthUser> userRecords = AuthUser.executeQuery(hql, args)

        if (userRecords.size() > 1) {
            logger.error 'getUser() Found more than one ({}) users for uniqueId:{}',
                    userRecords.size(), args.uniqueId
            return null
        } else if (userRecords.size() == 1) {
            logger.debug 'getUser() found one user record {}', userRecords[0]
            // Update the database record with the validated and authenticated Auth0 `userInfo` details
            updateUser userRecords[0], userInfo
            logger.debug "getUser() User record is updated with validated info from `userInfo`"

            logger.debug "getUser() returning full user record {}", userRecords[0]
            return userRecords[0]
        } else {
            logger.warn 'getUser() did not find any user record'
            return null
        }
        // Hopefully, if no user found or more than one user found, this will return NULL?!
    }

    /**
     * Retrieve a previously created user authentication record. If there are any
     * @param code the `code` querystring parameter from the Auth0 callback

    void getUserInfo(String idToken) {
        logger.debug 'getUserInfo() starting, with idToken:{}', idToken

				// Using a service (based on the configured URL) for token introspection
        String userinfoURL = customizationConfig.oauth_server_url
				logger.debug 'getUserInfo() token introspection url: {}', userinfoURL
        String adminToken = customizationConfig.oauth_admin_token

        RestBuilder rest = new RestBuilder()
        RestResponse rsp = rest.post(userinfoURL) {
            auth("Bearer $adminToken")
            contentType("application/x-www-form-urlencoded")
            body("token="+idToken)
        }

        if (rsp.status != 200) {
        	logger.error 'getUserInfo() `userInfo` could not be obtained. status:{} message:{}', rsp.status, rsp.text

        } else {
					logger.debug 'getUserInfo() finished, would return {}', rsp.text

				}
    }*/

    /**
		 * Creates an initial Credentials instance and stores it in the HTTP session.
		 * @param code the 'code' querystring parameter from the Auth0 callback
		 * @param redirectUri base of the callback url, e.g. https://server/contextPath
		 */
		Credentials createCredentials(String code, String redirectUri) {
        logger.debug 'createCredentials() starting'

				JSONObject json = new JSONObject(
						client_id: auth0Config.auth0ClientId,
						client_secret: auth0Config.auth0ClientSecret,
						code: code,
						grant_type: 'authorization_code',
						redirect_uri: redirectUri)

				Resty resty = new Resty()
				logger.debug 'createCredentials() oauthTokenUrl is {}', oauthTokenUrl
				JSONObject tokenInfo = resty.json(oauthTokenUrl, Resty.content(json)).toObject()
				// {
				//   "access_token":"...",
				//   "expires_in":86400,
				//   "id_token":"...",
				//   "token_type":"Bearer"
				// }

				String accessToken = tokenInfo.getString('access_token')
				String idToken = tokenInfo.getString('id_token')

        // TODO: Add oauth server query, based on RFC 7662
        // getUserInfo(idToken)

				logger.debug 'createCredentials() using userInfoUrl {} with access token', userInfoUrl
				JSONObject userInfo = resty.json(userInfoUrl + accessToken).toObject()
				// {
				// 	"app_metadata":
				// 		{
				// 			"roles":["ROLE_CITI_USER"]
				// 		},
				// 		"clientID":"...",
				// 		"created_at":"2017-11-21T15:19:50.683Z",
				// 		"email":"burtbeckwith@gmail.com",
				// 		"email_verified":true,
				// 		"family_name":"Beckwith",
				// 		"gender":"male",
				// 		"given_name":"Burt",
				// 		"identities":[
				// 			{
				// 				"connection":"google-oauth2",
				// 				"isSocial":true,
				// 				"provider":"google-oauth2",
				// 				"user_id":"..."
				// 			}
				// 		],
				// 		"locale":"en",
				// 		"name":"Burt Beckwith",
				// 		"nickname":"burtbeckwith",
				// 		"picture":"https://lh3.googleusercontent.com/-rG-S66wU1LI/AAAAAAAAAAI/AAAAAAAAAfE/ijUU6rz8j3I/photo.jpg",
				// 		"roles":["ROLE_CITI_USER"],
				// 		"sub":"google-oauth2|...",
				// 		"updated_at":"2018-02-20T13:25:20.721Z",
				// 		"user_id":"google-oauth2|..."
				// }

				logger.info 'createCredentials() Auth0 userinfo: {}', userInfo

        // Create a base `Credentials` object, with reasonable defaults.
        Credentials credentials = new Credentials(
                accessToken: accessToken,
                connection: userInfo.getJSONArray('identities').getJSONObject(0).getString('connection'),
                email: userInfo.optString('email'),
                idToken: 'INVALID_TOKEN',
                name: 'unregistered',
                nickname: 'unregistered',
                picture: '',
                uniqueId: 'UNKNOWN',
                level: UserLevel.UNREGISTERED,
                tosVerified: false
        )

        // Check if the user has logged in before (have all matching information against the previously updated) or
        // this is a first-time login, in which case, we need to update the UNINITED user record with the actual
        // credentials, or simply someone who is not yet in the database, and therefore not pre-authorized to log-in.
        logger.debug "createCredentials() lookup original by sub {}", userInfo.getString('sub')

        AuthUser userRecord
        List<AuthUser> users = AuthUser.findAll { uniqueId == userInfo.getString('sub') }
        if (users.size() == 1) {
            logger.debug "createCredentials() found existing record {}", users[0]
            userRecord = users[0]
        } else {
            logger.debug "createCredentials() could not find existing record {} ", users
            userRecord = getUser(userInfo)
        }

        if (userRecord) {
            logger.debug 'createCredentials() Found a `userRecord` based on `userInfo`.'
            // Update the credentials from the user's existing record
            credentials.email = userRecord.email
            credentials.idToken = rebuildJwt(idToken, userRecord.email)
            credentials.name = userRecord.userRealName
            credentials.nickname = userInfo.optString('nickname')
            credentials.picture = userInfo.optString('picture')
            credentials.uniqueId = userRecord.uniqueId
            credentials.level = customizationService.userLevel(userRecord)

            // Additional information from the database
            credentials.id = userRecord.id
            credentials.username = userRecord.username

        } else {
            logger.error 'createCredentials() User is not set up in the database.'
            // Create user record
            if (auth0Config.registrationEnabled) {
                logger.debug 'createCredentials() registration is enabled, create an UNREGISTERED level user'
                credentials.username = UUID.randomUUID().toString()
                credentials.email = userInfo.getString('email')
                createUser credentials, userInfo.getString('user_id')
            } else {
                logger.debug 'createCredentials() registration is not enabled, do not do anything'
            }
        }

        logger.debug 'createCredentials() add `credentials` to the session CREDENTIALS_KEY attribute'
		currentRequest().session.setAttribute CREDENTIALS_KEY, credentials

		logger.debug 'createCredentials() return Auth0 Credentials: {}', credentials
		credentials
	}

	private String rebuildJwt(String idToken, String email) {
		DecodedJWT decodedJwt = JWT.decode(idToken)
		JWT.create()
				.withAudience(decodedJwt.audience as String[]) // 'aud', e.g. 'ywAq4Xu4Kl3uYNdm3m05Cc5ow0OibvXt'
				.withExpiresAt(decodedJwt.expiresAt) // 'exp'
				.withIssuedAt(decodedJwt.issuedAt) // 'iat'
				.withIssuer(decodedJwt.issuer) // 'iss', e.g. 'https://avillachlab.auth0.com/'
				.withKeyId(decodedJwt.keyId) // 'kid', e.g. 'RkNBQjE5OUNENzY3NjIwN0VCMTgwNjE3MDUwRTJDMUZFNDg4NkFERg'
				.withSubject(decodedJwt.subject) // 'sub', e.g. 'google-oauth2|...'
				.withClaim('email', email)
				.sign(algorithm)
	}

	@Transactional
	AuthUser createUser(Credentials credentials, String uniqueId) {
        logger.debug 'createUser() starting'

		AuthUser user = new AuthUser(
				description: buildDescription(credentials.connection, credentials.picture),
				email: credentials.email,
				emailShow: true,
				enabled: true,
				name: credentials.name,
				passwd: 'auth0', // need a non-blank value for validation
				uniqueId: uniqueId,
				username: credentials.username,
				userRealName: credentials.name)
		if (!user.name) {
			user.name = user.userRealName
		}

		user.save()
		if (user.hasErrors()) {
			logger.error 'createUser() Could not create user {} because {}', credentials.username, utilService.errorStrings(user)
		}
		logger.info 'createUser() New user record has been created: {}', credentials.username
		user
	}

	String buildDescription(String connection, String picture) {
		([about     : '',
		  connection: connection,
		  firstname : '',
		  lastname  : '',
		  phone     : '',
		  picture   : picture?:''] as JSON).toString()
	}

	/**
	 * Registration confirmation.
	 * Steps: Validate reCaptcha, via Google
	 *        Find user, based on hidden variable on registration form
	 *        Update user record with registration form information
	 *        Set the basic (Level1) roles for the user
	 *        Send notification e-mail to admin
	 *        Send confirmation e-mail to user
	 *        Set authentication in SpringSecurity
	 *        Redirect to initial page
	 *
	 * @return a 1-element map with either a redirect uri under the 'uri' key
	 *         or a redirect action under the 'action' key
	 */
	@Transactional
	Map<String, String> confirmRegistration(String recaptchaResponse, String username, String email,
	                                        String firstname, String lastname, Credentials credentials,
	                                        Map params, String loginUrl, String appUrl) {
		if (auth0Config.useRecaptcha) {
			verifyRecaptchaResponse recaptchaResponse, username ?: email ?: 'unknown'
		}
		AuthUser authUser = userService.updateAuthUser(null, username, email, firstname, lastname, credentials, params)
		sendSignupEmails username, email, authUser, loginUrl, appUrl
		grantRolesAndStoreAuth authUser, username
	}

	private void verifyRecaptchaResponse(String recaptchaResponse, String username) {
		// Verification parameters, per Googly's information  https://developers.google.com/recaptcha/docs/verify
		Resty resty = new Resty()
		JSONObject confirmation = resty.json(auth0Config.captchaVerifyUrl, resty.form(
				resty.data('secret', auth0Config.captchaSecret),
				resty.data('response', recaptchaResponse))).toObject()

		if (confirmation.getBoolean('success')) {
			accessLog username, 'captcha_verify-INFO',
					'Registration process has been allowed, per reCAPTCHAverification from ' + currentRequest().remoteHost
		}
		else {
			// If Google does not return a success message, log the error response and throw description exception back to the user
			accessLog username, 'captcha_verify-ERROR',
					confirmation.toString() + ' from host ' + currentRequest().remoteHost
			throw new RuntimeException('Captcha verification step has failed.')
		}
	}

	private void sendSignupEmails(String username, String email, AuthUser authUser, String loginUrl, String appUrl) {
		Map personDescription = (Map) JSON.parse(authUser.description)
		String emailLogo = customizationConfig.emailLogo
		if (!emailLogo.startsWith('data:')) {
			if (appUrl.endsWith('/') && emailLogo.startsWith('/')) {
				emailLogo = appUrl + emailLogo.substring(1)
			}
			else {
				emailLogo = appUrl + emailLogo
			}
		}

		// Send notification to admin that a user has completed the sign-up form
		String body = groovyPageRenderer.render(
				template: '/auth0/email_signup', model: [
				appUrl      : appUrl,
				emailLogo   : emailLogo,
				instanceName: customizationConfig.instanceName,
				person      : personDescription])
		sendEmail customizationConfig.emailNotify, 'Registration Request', body

		logger.debug 'Sent `Registration Request` e-mail to administrator(s)'

		accessLog username ?: email ?: 'unknown', 'user_registration-INFO',
				"New user $email has been registered"

		// Send registration confirmation e-mail to the user, once the form has been submitted.
		body = groovyPageRenderer.render(template: '/auth0/email_thankyou', model: [
				email       : personDescription.email ?: 'E-mailAddress',
				emailLogo   : emailLogo,
				firstName   : personDescription.firstname ?: 'FirstName',
				instanceName: customizationConfig.instanceName,
				lastName    : personDescription.lastname ?: 'LastName',
				loginUrl    : loginUrl,
				user        : authUser])
		sendEmail authUser.email, 'Registration Confirmation', body
		logger.debug 'Sent `Registration Confirmation` e-mail to user'
		accessLog email, 'user_registration-INFO', "Confirmation e-mails for $email has been sent"
	}

	/**
	 * @return a 1-element map with either a redirect uri under the 'uri' key
	 *         or a redirect action under the 'action' key
	 */
	private Map<String, String> grantRolesAndStoreAuth(AuthUser authUser, String username) {
		if ('auto'.equalsIgnoreCase(customizationConfig.accessLevel1)) {
			// If configuration is set to auto-approve, go ahead and assign the basic roles.
			authService.grantRoles authUser, Roles.STUDY_OWNER
			logger.debug 'Assigned basic, Level1 access to new user'

			// If configuration is set to auto-approve, after filling out the registration form
			// the user will be redirected to the default internal page of the applications.
			securityService.authenticateAs username
			logger.info 'Automated approval is set. User {} has roles assigned and logged into the app.', username

			[uri: auth0Config.redirectOnSuccess]
		}
		else {
			authService.grantRoles authUser, Roles.PUBLIC_USER
			logger.debug 'Assigned basic, Level 0 access to new user. Will have to wait for administrative approval.'
			logger.info 'Automated approval is NOT set. User {} needs to wait for administrator to approve.', username
			[action: 'thankyou']
		}
	}

	private void accessLog(String username, String event, String message = null) {
		accessLogService.report username, event, message
	}

	@CompileDynamic
	private void sendEmail(String recipient, String theSubject, String body) {
		mailService.sendMail {
			to recipient
			subject theSubject
			html body
		}
	}

	@Transactional
	boolean createOrUpdate(AuthUser authUser, boolean create, UserLevel userLevel, String message, String appUrl) {

		if (authUser.save(flush: true)) {
			if (create || userLevel != customizationService.userLevel(authUser)) {
				changeUserLevel authUser, userLevel, appUrl
			}

			accessLogService.report "User ${create ? 'Created' : 'Updated'}", message
			true
		}
		else {
			transactionStatus.setRollbackOnly()
			false
		}
	}

	@Transactional
	void changeUserLevel(AuthUser user, UserLevel newLevel, String appUrl) {

		updateRoles newLevel, user

		String alertMsg = "User <b>$user.username</b> has been granted <b>$newLevel.description</b> access."
		logger.info alertMsg
		accessLog securityService.currentUsername(), 'GrantAccess', alertMsg

		if (!user.email) {
			return
		}

		ProviderInfo providerInfo = AUTH0_PROVIDERS.find { ProviderInfo pi -> user.uniqueId?.startsWith pi.subPrefix }

		String providerId = (providerInfo ? user.uniqueId - providerInfo.subPrefix : '') - '_UNINITIALIZED'

		String body = groovyPageRenderer.render(template: '/auth0/email_accessgranted', model: [
				adminEmailMessage : auth0Config.adminEmailMessage,
				appUrl            : appUrl,
				authProvider      : providerInfo?.displayName,
				authProviderId    : providerId,
				emailLogo         : customizationConfig.emailLogo,
				instanceName      : customizationConfig.instanceName,
				level1EmailMessage: auth0Config.level1EmailMessage,
				level2EmailMessage: auth0Config.level2EmailMessage,
				levelName         : newLevel.description,
				quickStartUrl     : customizationConfig.quickStartUrl,
				supportEmail      : customizationConfig.supportEmail,
				user              : user,
				userGuideUrl      : customizationConfig.userGuideUrl])

		try {
			sendEmail user.email, 'Access Granted', body
		} catch (Exception e) {
			logger.error 'changeUserLevel() Could not send the e-mail about granting access. {}', e.getMessage()
		}

	}

	private void updateRoles(UserLevel level, AuthUser user) {
		if (user.authorities) {
			for (Role role in (user.authorities as List<Role>)) { // cast to create a new collection to avoid ConcurrentModificationException
				role.removeFromPeople user
			}
		}

		switch (level) {
			case UserLevel.ZERO:  authService.grantRoles user, Roles.PUBLIC_USER; break
			case UserLevel.ONE:   authService.grantRoles user, Roles.STUDY_OWNER; break
			case UserLevel.TWO:   authService.grantRoles user, Roles.DATASET_EXPLORER_ADMIN; break
			case UserLevel.ADMIN: authService.grantRoles user, Roles.ADMIN; break
		}
	}

	/**
	 * Check if the latest TOS has been re-agreed-to by the current user.
	 *
	 * The date the latest TOS has been created is stored in , and the
	 * flag storing the confirmation (or if flag missing, the NOT confirmation)
	 * by the user is in the user account.
	 */
	boolean verifyTOSAccepted(long potentialUserId) {
		logger.debug 'verifyTOSAccepted({})', potentialUserId

		Settings defaultTosSettings = customizationService.setting('tos.text')
		if (!defaultTosSettings) {
			logger.debug 'There is no TOS set up.'
			// There is no TOS settings. Verify by default. If the Settings does
			// not exist, it means we do not have TOS for anybody to re-agree to.
			return true
		}

		Settings userTosSettings = customizationService.userSetting('tos.text', potentialUserId)
		if (!userTosSettings) {
			logger.debug 'User never accepted TOS, before.'
			// User never approved TOS. Fail by default.
			return false
		}

		if (defaultTosSettings.lastUpdated < userTosSettings.lastUpdated) {
			// If the date of the latest TOS is less then the user's agreement date, it means the latest TOS has been accepted by the user.
			// As a side note, the date of the user's agreeing to the TOS, should have a corresponding AccessLog entry in the database.
			logger.debug 'User already accepted the latest TOS.{} < {}',
					defaultTosSettings.lastUpdated, userTosSettings.lastUpdated
			return true
		}

		logger.debug 'User has not accepted the latest TOS. Will be forced to. def: {} < usr: {}',
				defaultTosSettings.lastUpdated, userTosSettings.lastUpdated
		false
	}

	@Transactional
	void checkTOS(Credentials credentials) {
		Settings tosTextSettings = customizationService.userSetting('tos.text', credentials.id)
		if (!tosTextSettings) {
			// This is the first time accepting. Create new settings record
			new Settings(userid: credentials.id, fieldname: 'tos.text', fieldvalue: 'Accepted').save()
		}
		else {
			tosTextSettings.lastUpdated = new Date()
			tosTextSettings.save()
		}

		credentials.tosVerified = null

		authenticateAs credentials
	}

	/**
	 * Build an <code>Authentication</code> for the given credentials and register
	 * it in the security context.
	 */
	void authenticateAs(Credentials credentials) {
		Auth0JWTToken tokenAuth = new Auth0JWTToken(credentials.idToken)
		tokenAuth.principal = authService.loadAuthUserDetailsByUniqueId(credentials.uniqueId)
		tokenAuth.authenticated = true
		SecurityContextHolder.context.authentication = tokenAuth
		logger.debug 'authenticateAs username {} email {} id {}',
				tokenAuth.principal.username, tokenAuth.principal.email, tokenAuth.principal.id
	}

	@Cacheable('webtask')
	String webtaskJavaScript() {
		webtask 'client_id=' + auth0Config.auth0ClientId
	}

	@Cacheable('webtask')
	String webtaskCSS() {
		webtask 'css=true'
	}

	/**
	 * Convenience method to get the JWT token from the current authentication.
	 */
	String jwtToken() {
		if (securityService.loggedIn()) {
			Authentication auth = securityService.authentication()
			if (auth instanceof Auth0JWTToken) {
				((Auth0JWTToken) auth).jwtToken
			}
		}
        null
	}

	@Transactional
	void autoCreateAdmin() {
		if (!auth0Config?.autoCreateAdmin) {
			logger.info 'Auth0 is disabled, or admin auto-create is disabled, not creating admin user'
			return
		}

		if (Role.findByAuthority(Roles.ADMIN.authority).people) {
			logger.info 'admin auto-create is enabled but an admin user exists, not creating admin user'
			return
		}

		String username = auth0Config.autoCreateAdminUsername
		if (!username) {
			logger.error 'admin auto-create is enabled but no username is specified, cannot create admin user'
			return
		}

		if (AuthUser.countByUsername(username)) {
			logger.error 'admin auto-create is enabled but non-admin user "{}" exists, not creating admin user', username
			return
		}

		String password = auth0Config.autoCreateAdminPassword
		if (!password) {
			logger.error 'admin auto-create is enabled but no password is specified, cannot create admin user'
			return
		}

		String email = auth0Config.autoCreateAdminEmail // can be null

		// don't double-hash
		boolean hashed = (password.length() == 59 || password.length() == 60) &&
				(password.startsWith('$2a$') || password.startsWith('$2b$') || password.startsWith('$2y$'))

		AuthUser admin = new AuthUser(description: 'System admin', email: email ?: null, enabled: true,
				name: 'System admin', passwd: hashed ? password : springSecurityService.encodePassword(password),
				uniqueId: username, userRealName: 'System admin', username: username)

		String errorMessage = createAdmin(admin, transactionStatus)
		if (errorMessage) {
			accessLogService.report 'BootStrap', 'admin auto-create', errorMessage
		}
	}

	/**
	 * Validates that the string is a valid ORCiD.
	 *
	 * @param orcid the id
	 * @return null if ok, a warning/error message otherwise
	 */
	String validateOrcid(String orcid) {
		if (!(orcid ==~ /\d{4}-\d{4}-\d{4}-\d{3}(\d|X)/)) {
			return 'Failed regex check'
		}

		int total = 0
		for (int i = 0; i < 18; i++) {
			char c = orcid.charAt(i)
			if (c == DASH) continue
			total = (total + Character.getNumericValue(c)) * 2
		}
		int remainder = total % 11
		int result = (12 - remainder) % 11
		char checksumChar = result == 10 ? X : Character.forDigit(result, 10)
		if (checksumChar != orcid.charAt(18)) {
			return 'Failed check digit'
		}
	}

	private String createAdmin(AuthUser admin, TransactionStatus transactionStatus) {
		if (admin.save(flush: true)) {
			Role.findByAuthority(Roles.ADMIN.authority).addToPeople admin
			logger.info 'auto-created admin user'
			accessLogService.report 'BootStrap', 'admin auto-create', 'created admin user'
			null
		}
		else {
			transactionStatus.setRollbackOnly()
			String message = 'auto-create admin user failed: ' + utilService.errorStrings(admin)
			logger.error message
			message
		}
	}

	private String webtask(String urlMethod) {
		(auth0Config.webtaskBaseUrl + '/connection_details_base64?webtask_no_cache=1&' + urlMethod).toURL().text
	}

	private HttpServletRequest currentRequest() {
		((GrailsWebRequest) RequestContextHolder.currentRequestAttributes()).request
	}

	private void determineProviders() {
        logger.debug 'determineProviders() starting'
		String webtaskJs = webtaskJavaScript()
		int start = webtaskJs.indexOf('var connections = [{') + 18
		int end = webtaskJs.indexOf('}];\tvar lock =', start) + 1

		Collection<String> webtaskNames = JSON.parse(webtaskJs[start..end]).collect { it['name'] } as Collection
        logger.debug 'determineProviders() webtaskNames:{}', webtaskNames.toString()

		for (ProviderInfo info in AUTH0_PROVIDERS) {
            logger.debug 'determineProviders() provider {} / {} maybe?', info.displayName, info.webtaskName
			if (info.webtaskName in webtaskNames) {
                logger.debug 'determineProviders() selecting'
				activeProviders << info
			} else {
                logger.warn 'determineProviders() skipping'
            }
		}
        logger.debug 'determineProviders() finished'
	}

    private boolean updateUser(AuthUser userRecord, JSONObject userInfo) {
        logger.debug 'updateUser() starting'

        userRecord.description = buildDescription(userInfo.getJSONArray('identities').getJSONObject(0).getString('connection'), userInfo.optString('picture'))
        userRecord.userRealName = userInfo.optString('name');
        userRecord.name = userInfo.optString('name');
        userRecord.email = userInfo.getString('email');
        userRecord.uniqueId = userInfo.getString('sub');
        logger.debug 'updateUser() new details {}', userRecord
        return userRecord.save()
    }

	void afterPropertiesSet() {
		if (!auth0Config) { // not injected if active=false
			return
		}

		algorithm = Algorithm.HMAC256(auth0Config.auth0ClientSecret)
		oauthTokenUrl = 'https://' + auth0Config.auth0Domain + '/oauth/token'
		userInfoUrl = 'https://' + auth0Config.auth0Domain + '/userinfo?access_token='

		determineProviders()
	}

	@CompileStatic
	@Immutable
	static class ProviderInfo {
		String webtaskName
		String displayName
		String subPrefix
	}
}

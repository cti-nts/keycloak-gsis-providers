/*
 * Copyright 2021 Greek School Network and Networking Technologies Directorate (http://nts.cti.gr/),
 * Konstantinos Togias (ktogias@cti.gr) and/or their affiliates and other contributors as indicated
 * by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package gr.cti.nts.keycloak.idp.social.gsis;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import gr.cti.nts.keycloak.idp.social.gsis.resource.GsisLogoutResource;
import gr.cti.nts.keycloak.idp.social.gsis.resource.GsisLogoutResourceProviderFactory;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import lombok.extern.jbosslog.JBossLog;

@JBossLog
public abstract class GsisAbstractIdentityProvider
    extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

  public static final String FEDERATED_ID_TOKEN = "FEDERATED_ID_TOKEN";

  // Cache API detection results to avoid repeated reflection
  private static final boolean USE_NEW_CONTEXT_API;
  private static final java.lang.reflect.Constructor<?> CONTEXT_CONSTRUCTOR;
  private static final java.lang.reflect.Method SET_IDP_CONFIG_METHOD;
  private static final java.lang.reflect.Method SET_IDP_METHOD;

  static {
    boolean useNewApi = false;
    java.lang.reflect.Constructor<?> constructor;
    java.lang.reflect.Method setIdpConfigMethod = null;
    java.lang.reflect.Method setIdpMethod = null;

    try {
      // Try new API: BrokeredIdentityContext(IdentityProviderModel)
      constructor = BrokeredIdentityContext.class
        .getConstructor(org.keycloak.models.IdentityProviderModel.class);
      useNewApi = true;
      log.infof("Using new BrokeredIdentityContext(IdentityProviderModel) constructor");
    } catch (NoSuchMethodException e) {
      // Fall back to old API: BrokeredIdentityContext(String)
      try {
        constructor = BrokeredIdentityContext.class.getConstructor(String.class);
        log.infof("Using old BrokeredIdentityContext(String) constructor");
      } catch (NoSuchMethodException ex) {
        throw new RuntimeException("Could not find any compatible BrokeredIdentityContext constructor", ex);
      }
    }

    // Detect setIdpConfig(IdentityProviderModel)
    try {
      setIdpConfigMethod = BrokeredIdentityContext.class.getMethod("setIdpConfig", org.keycloak.models.IdentityProviderModel.class);
      log.infof("Detected setIdpConfig(IdentityProviderModel) method");
    } catch (NoSuchMethodException e) {
      log.infof("setIdpConfig method NOT available on this Keycloak version (Modern Keycloak logic applies)");
    }

    // Detect setIdp(IdentityProvider) - Was removed in v25.
    try {
      setIdpMethod = BrokeredIdentityContext.class.getMethod("setIdp", org.keycloak.broker.provider.IdentityProvider.class);
      log.infof("Detected setIdp(IdentityProvider) method");
    } catch (NoSuchMethodException e) {
      log.infof("setIdp method NOT available on this Keycloak version (Modern Keycloak logic applies)");
    }

    USE_NEW_CONTEXT_API = useNewApi;
    CONTEXT_CONSTRUCTOR = constructor;
    SET_IDP_CONFIG_METHOD = setIdpConfigMethod;
    SET_IDP_METHOD = setIdpMethod;
  }

  public GsisAbstractIdentityProvider(KeycloakSession session,
      OAuth2IdentityProviderConfig config) {
    super(session, config);
    config.setAuthorizationUrl(getAuthUrl());
    config.setTokenUrl(getTokenUrl());
  }

  protected abstract String getAuthUrl();

  protected abstract String getTokenUrl();

  protected abstract String getDefaultScope();

  protected abstract String getUserInfoUrl();

  protected abstract String getLogoutUrl();

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new OIDCEndpoint(callback, realm, event, this);
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  /**
   * Create a BrokeredIdentityContext using cached constructor/method references. API detection
   * happens once at class load time, not at runtime.
   *
   * Older API: new BrokeredIdentityContext(String id) + setIdpConfig(config) Newer API: new
   * BrokeredIdentityContext(IdentityProviderModel) - no setIdpConfig
   */
  private BrokeredIdentityContext createBrokeredIdentityContext(OAuth2IdentityProviderConfig config, String username) {
    try {
      BrokeredIdentityContext context;

      if (USE_NEW_CONTEXT_API) {
        // New API: BrokeredIdentityContext(IdentityProviderModel)
        context = (BrokeredIdentityContext) CONTEXT_CONSTRUCTOR.newInstance(config);
      } else {
        // Old API: BrokeredIdentityContext(String)
        context = (BrokeredIdentityContext) CONTEXT_CONSTRUCTOR.newInstance(username);
      }

      // Call setIdpConfig if the method exists
      if (SET_IDP_CONFIG_METHOD != null) {
        SET_IDP_CONFIG_METHOD.invoke(context, config);
      }

      return context;
    } catch (Exception e) {
      throw new RuntimeException(
        "Failed to create BrokeredIdentityContext for username: " + username, e);
    }
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event,
      JsonNode profile) {
    String username = getJsonProperty(profile, "userid");
    String firstname = getJsonProperty(profile, "firstname");
    String lastname = getJsonProperty(profile, "lastname");

    OAuth2IdentityProviderConfig config = getConfig();
    BrokeredIdentityContext user = createBrokeredIdentityContext(config, username);

    user.setId(username);
    user.setUsername(username);
    user.setFirstName(firstname);
    user.setLastName(lastname);
    user.setEmail("");

    if (SET_IDP_METHOD != null) {
      try {
        SET_IDP_METHOD.invoke(user, this);
      } catch (Exception e) {
        log.warn("Failed to call setIdp via reflection", e);
      }
    }
    // In new versions, setIdp is not needed because the IDP is
    // linked via the IdentityProviderModel passed in the constructor.

    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, config.getAlias());

    return user;
  }

  @Override
  protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
    String profileUrl = getUserInfoUrl();
    String jsonStringProfile = "";

    try {
      Object request = SimpleHttpAdapter.doGet(profileUrl, session);
      request = SimpleHttpAdapter.header(request, "Authorization", "Bearer " + accessToken);
      String profile = SimpleHttpAdapter.asString(request);

      SAXParserFactory parserFactory = SAXParserFactory.newInstance();
      parserFactory.setValidating(false);
      parserFactory.setXIncludeAware(false);
      parserFactory.setNamespaceAware(false);

      final Map<String, String> userFields = new HashMap<String, String>();
      SAXParser parser = parserFactory.newSAXParser();

      parser.parse(new InputSource(new StringReader(profile)), new DefaultHandler() {
        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes)
            throws SAXException {
          if ("userinfo".equals(qName)) {
            userFields.put("userid", attributes.getValue("userid"));
            userFields.put("taxid", attributes.getValue("taxid"));
            userFields.put("lastname", attributes.getValue("lastname"));
            userFields.put("firstname", attributes.getValue("firstname"));
            userFields.put("fathername", attributes.getValue("fathername"));
            userFields.put("mothername", attributes.getValue("mothername"));
            userFields.put("birthyear", attributes.getValue("birthyear"));
          }
        }
      });

      jsonStringProfile += "{";

      int index = 0;
      for (Map.Entry<String, String> m : userFields.entrySet()) {
        if (index > 0) {
          jsonStringProfile += ", ";
        }
        jsonStringProfile += "\"" + m.getKey() + "\":\"" + m.getValue() + "\"";
        index++;
      }

      jsonStringProfile += "}";

      ObjectMapper mapper = new ObjectMapper();
      JsonNode jsonProfile = mapper.readTree(jsonStringProfile);

      return extractIdentityFromProfile(null, jsonProfile);
    } catch (Exception e) {
      throw new IdentityBrokerException(
          "Could not obtain user profile from gsis. *** Profile:" + jsonStringProfile + " ***", e);
    }
  }

  @Override
  protected String getDefaultScopes() {
    return getDefaultScope();
  }

  private String getIDTokenForLogout(KeycloakSession session, UserSessionModel userSession) {
    String tokenExpirationString = userSession.getNote(FEDERATED_TOKEN_EXPIRATION);
    long expirationTime = tokenExpirationString == null ? 0 : Long.parseLong(tokenExpirationString);
    int currentTime = Time.currentTime();

    if (expirationTime > 0 && currentTime > expirationTime) {
      String response = refreshTokenForLogout(session, userSession);
      AccessTokenResponse tokenResponse = null;

      try {
        tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }

      return tokenResponse.getIdToken();
    }

    return userSession.getNote(FEDERATED_ID_TOKEN);
  }

  protected static class OIDCEndpoint extends Endpoint {
    public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
        AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig> provider) {
      super(callback, realm, event, provider);
    }
  }

  /**
   * Returns access token response as a string from a refresh token invocation on the remote OIDC
   * broker
   *
   * @param session
   * @param userSession
   * @return
   */
  public String refreshTokenForLogout(KeycloakSession session, UserSessionModel userSession) {
    String refreshToken = userSession.getNote(FEDERATED_REFRESH_TOKEN);
    OAuth2IdentityProviderConfig config = getConfig();
    String clientSecret = config.getClientSecret();

    try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(clientSecret)) {
      Object request = buildRefreshTokenRequest(session, refreshToken, config.getClientId(),
          vaultStringSecret.get().orElse(clientSecret));
      return SimpleHttpAdapter.asString(request);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Build a refresh token request. Returns Object instead of specific type to handle API
   * differences between Keycloak versions.
   */
  protected Object buildRefreshTokenRequest(KeycloakSession session, String refreshToken,
      String clientId, String clientSecret) {
    Object refreshTokenRequest = SimpleHttpAdapter.doPost(getConfig().getTokenUrl(), session);
    refreshTokenRequest =
        SimpleHttpAdapter.param(refreshTokenRequest, "refresh_token", refreshToken);
    refreshTokenRequest =
        SimpleHttpAdapter.param(refreshTokenRequest, "grant_type", "refresh_token");
    refreshTokenRequest = SimpleHttpAdapter.param(refreshTokenRequest, "client_id", clientId);
    refreshTokenRequest =
        SimpleHttpAdapter.param(refreshTokenRequest, "client_secret", clientSecret);

    return refreshTokenRequest;
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
                                                 UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {

    String logoutUrl = getLogoutUrl();
    if (logoutUrl == null || logoutUrl.trim().isEmpty()) {
      return null;
    }

    log.infof("Initiating GSIS logout for user session: %s", userSession.getId());

    OAuth2IdentityProviderConfig config = getConfig();
    String sessionId = userSession.getId();
    String idToken = getIDTokenForLogout(session, userSession);

    // Point GSIS at a RealmResourceProvider endpoint that completes the Keycloak-side logout.
    // We can't use a @Path subresource on OIDCEndpoint here because Keycloak 24+ (Quarkus REST)
    // doesn't route subclass @Path methods returned from IdentityBrokerService.getEndpoint(),
    // even with a Jandex index. RealmResourceProvider gives us a first-class top-level path.
    // NOTE: GSIS validates `url=` against the registered redirect URI. If GSIS does strict
    // prefix-matching (only paths under /broker/{alias}/endpoint), this URL will be rejected
    // and the user will fall back to the registered redirect URI as before. In that case,
    // the registered URL with GSIS needs to be widened, or use the authResponse-override path.
    String redirectUri = UriBuilder.fromUri(uriInfo.getBaseUri())
        .path("realms").path(realm.getName())
        .path(GsisLogoutResourceProviderFactory.ID)
        .path(GsisLogoutResource.LOGOUT_RESPONSE_PATH)
        .queryParam("state", sessionId)
        .build()
        .toString();

    UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);
    if (idToken != null) {
      logoutUri.queryParam("id_token_hint", idToken);
    }
    logoutUri.queryParam("url", redirectUri);
    URI builtUri = logoutUri.build(config.getClientId());

    return Response.status(302).location(builtUri).build();
  }
}

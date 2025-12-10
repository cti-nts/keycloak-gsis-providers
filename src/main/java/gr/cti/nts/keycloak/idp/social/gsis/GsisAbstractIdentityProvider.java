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
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import lombok.extern.jbosslog.JBossLog;

@JBossLog
public abstract class GsisAbstractIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

  public static final String FEDERATED_ID_TOKEN = "FEDERATED_ID_TOKEN";

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

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event,
      JsonNode profile) {
    String username = getJsonProperty(profile, "userid");
    String firstname = getJsonProperty(profile, "firstname");
    String lastname = getJsonProperty(profile, "lastname");

    BrokeredIdentityContext user = new BrokeredIdentityContext(username);
    OAuth2IdentityProviderConfig config = getConfig();

    user.setUsername(username);
    user.setFirstName(firstname);
    user.setLastName(lastname);
    user.setEmail("");
    user.setIdpConfig(config);
    user.setIdp(this);

    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, config.getAlias());

    return user;
  }

  @Override
  protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
    String profileUrl = getUserInfoUrl();
    String jsonStringProfile = "";

    try {
      SimpleHttp request = SimpleHttp.doGet(profileUrl, session);
      String profile = request.header("Authorization", "Bearer " + accessToken).asString();

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

    @Override
    public SimpleHttp generateTokenRequest(String authorizationCode) {
      SimpleHttp simpleHttp = super.generateTokenRequest(authorizationCode);
      return simpleHttp;
    }

    @GET
    @Path("logout_response")
    public Response logoutResponse(@QueryParam("state") String state) {
      if (state == null) {
        logger.error("no state parameter returned");
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        event.event(EventType.LOGOUT);
        event.error(Errors.USER_SESSION_NOT_FOUND);

        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
            Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
      }

      UserSessionModel userSession = session.sessions().getUserSession(realm, state);
      if (userSession == null) {
        logger.error("no valid user session");
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        event.event(EventType.LOGOUT);
        event.error(Errors.USER_SESSION_NOT_FOUND);

        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
            Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
      }

      if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
        logger.error("usersession in different state");
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        event.event(EventType.LOGOUT);
        event.error(Errors.USER_SESSION_NOT_FOUND);

        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
            Messages.SESSION_NOT_ACTIVE);
      }

      return AuthenticationManager.finishBrowserLogout(session, realm, userSession,
          session.getContext().getUri(), clientConnection, headers);
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
      return getRefreshTokenRequest(session, refreshToken, config.getClientId(),
          vaultStringSecret.get().orElse(clientSecret)).asString();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  protected SimpleHttp getRefreshTokenRequest(KeycloakSession session, String refreshToken,
      String clientId, String clientSecret) {
    SimpleHttp refreshTokenRequest = SimpleHttp.doPost(getConfig().getTokenUrl(), session)
        .param(OAUTH2_GRANT_TYPE_REFRESH_TOKEN, refreshToken)
        .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_REFRESH_TOKEN);

    return authenticateTokenRequest(refreshTokenRequest);
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
      UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
    log.infof("keycloakInitiatedBrowserLogout");
    String logoutUrl = getLogoutUrl();

    if (logoutUrl == null || logoutUrl.trim().length() == 0) {
      return null;
    }

    String idToken = getIDTokenForLogout(session, userSession);
    String sessionId = userSession.getId();
    UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);

    if (idToken != null) {
      logoutUri.queryParam("id_token_hint", idToken);
    }

    OAuth2IdentityProviderConfig config = getConfig();
    String redirect = RealmsResource.brokerUrl(uriInfo)
        .path(IdentityBrokerService.class, "getEndpoint").path(OIDCEndpoint.class, "logoutResponse")
        .queryParam("state", sessionId).build(realm.getName(), config.getAlias()).toString();
    logoutUri.queryParam("url", redirect);

    return Response.status(302).location(logoutUri.build(config.getClientId())).build();
  }
}

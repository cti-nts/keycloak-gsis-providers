package gr.cti.nts.keycloak.idp.social.gsis;

import org.keycloak.broker.social.SocialIdentityProvider;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;

/** */
@JBossLog
public class GsisGovuserIdentityProvider extends GsisAbstractIdentityProvider
    implements SocialIdentityProvider {

  public static final String AUTH_URL = "https://www1.gsis.gr/oauth2servergov/oauth/authorize";

  public static final String TOKEN_URL = "https://www1.gsis.gr/oauth2servergov/oauth/token";

  public static final String DEFAULT_SCOPE = "";

  private static final String USER_INFO_URL =
      "https://www1.gsis.gr/oauth2servergov/userinfo?format=xml";

  private static final String LOGOUT_URL =
      "https://www1.gsis.gr/oauth2servergov/logout/{clientId}/";

  public GsisGovuserIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  protected  String getAuthUrl(){
    return AUTH_URL;
  }

  @Override
  protected  String getTokenUrl(){
    return TOKEN_URL;
  }

  @Override
  protected  String getDefaultScope(){
    return DEFAULT_SCOPE;
  }

  @Override
  protected  String getUserInfoUrl(){
    return USER_INFO_URL;
  }

  @Override
  protected  String getLogoutUrl(){
    return LOGOUT_URL;
  }

}

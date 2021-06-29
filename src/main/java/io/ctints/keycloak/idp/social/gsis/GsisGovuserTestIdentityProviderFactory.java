package gr.cti.nts.keycloak.idp.social.gsis;

import com.google.auto.service.AutoService;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/** */
@AutoService(SocialIdentityProviderFactory.class)
public class GsisGovuserTestIdentityProviderFactory
    extends AbstractIdentityProviderFactory<GsisGovuserTestIdentityProvider>
    implements SocialIdentityProviderFactory<GsisGovuserTestIdentityProvider> {

  public static final String PROVIDER_ID = "gsis-govuser";

  @Override
  public String getName() {
    return "GsisGovuserTest";
  }

  @Override
  public GsisGovuserTestIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new GsisGovuserTestIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
  }

  @Override
  public OAuth2IdentityProviderConfig createConfig() {
    return new OAuth2IdentityProviderConfig();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}

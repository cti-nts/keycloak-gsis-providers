package gr.cti.nts.keycloak.idp.social.gsis;

import com.google.auto.service.AutoService;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.IdentityProviderMapper;

/** */
@AutoService(IdentityProviderMapper.class)
public class GsisGovuserUserAttributeMapper extends AbstractJsonUserAttributeMapper {

  public static final String PROVIDER_ID = "gsis-govuser-user-attribute-mapper";
  private static final String[] cp = new String[] {GsisGovuserTestIdentityProviderFactory.PROVIDER_ID};

  @Override
  public String[] getCompatibleProviders() {
    return cp;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}

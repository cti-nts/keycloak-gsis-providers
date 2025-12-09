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

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import com.google.auto.service.AutoService;

@SuppressWarnings("rawtypes")
@AutoService(SocialIdentityProviderFactory.class)
public class GsisGovuserIdentityProviderFactory
    extends AbstractIdentityProviderFactory<GsisGovuserIdentityProvider>
    implements SocialIdentityProviderFactory<GsisGovuserIdentityProvider> {

  public static final String PROVIDER_ID = "gsis-govuser";

  @Override
  public String getName() {
    return "GsisGovuser";
  }

  @Override
  public GsisGovuserIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new GsisGovuserIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
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

/*
 * Copyright 2021 Greek School Network and Networking Technologies Directorate (http://nts.cti.gr/),
 * Konstantinos Togias (ktogias@cti.gr) and/or their affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gr.cti.nts.keycloak.idp.social.gsis;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

import lombok.extern.jbosslog.JBossLog;

/** */
@JBossLog
public class GsisTaxisTestIdentityProvider extends GsisAbstractIdentityProvider
    implements SocialIdentityProvider {

  public static final String AUTH_URL = "https://test.gsis.gr/oauth2server/oauth/authorize";

  public static final String TOKEN_URL = "https://test.gsis.gr/oauth2server/oauth/token";

  public static final String DEFAULT_SCOPE = "";

  private static final String USER_INFO_URL = "https://test.gsis.gr/oauth2server/userinfo?format=xml";

  private static final String LOGOUT_URL = "https://test.gsis.gr/oauth2server/logout/{clientId}/";

  public GsisTaxisTestIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  protected String getAuthUrl() {
    return AUTH_URL;
  }

  @Override
  protected String getTokenUrl() {
    return TOKEN_URL;
  }

  @Override
  protected String getDefaultScope() {
    return DEFAULT_SCOPE;
  }

  @Override
  protected String getUserInfoUrl() {
    return USER_INFO_URL;
  }

  @Override
  protected String getLogoutUrl() {
    return LOGOUT_URL;
  }

}

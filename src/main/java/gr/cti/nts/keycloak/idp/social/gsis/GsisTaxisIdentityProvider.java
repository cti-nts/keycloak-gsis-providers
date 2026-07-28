/*
 * Copyright 2021 Greek School Network and Networking Technologies Directorate (https://www.cti.gr/nts-department/),
 * Konstantinos Togias (ktogias@cti.gr) and/or their affiliates and other contributors as indicated
 * by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package gr.cti.nts.keycloak.idp.social.gsis;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

public class GsisTaxisIdentityProvider extends GsisAbstractIdentityProvider {

  public static final String BASE_URL = "https://oauth2.gsis.gr/oauth2server";

  public static final String DEFAULT_SCOPE = "";

  public GsisTaxisIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
    super(session, config, BASE_URL);
  }

  @Override
  protected String getDefaultScope() {
    return DEFAULT_SCOPE;
  }
}

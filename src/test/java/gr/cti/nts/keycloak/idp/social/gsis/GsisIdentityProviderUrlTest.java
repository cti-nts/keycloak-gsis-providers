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

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;

class GsisIdentityProviderUrlTest {

  private final OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();

  @Test
  void gsisTaxis() {
    assertUrls(new GsisTaxisIdentityProvider(null, config), "https://oauth2.gsis.gr/oauth2server");
  }

  @Test
  void gsisTaxisTest() {
    assertUrls(new GsisTaxisTestIdentityProvider(null, config), "https://test.gsis.gr/oauth2server");
  }

  @Test
  void gsisTaxisOtp() {
    assertUrls(new GsisTaxisOtpIdentityProvider(null, config),
        "https://oauth2.gsis.gr/oauth2serverotp");
  }

  @Test
  void gsisTaxisOtpTest() {
    assertUrls(new GsisTaxisOtpTestIdentityProvider(null, config),
        "https://test.gsis.gr/oauth2serverpilototp");
  }

  @Test
  void gsisGovuser() {
    assertUrls(new GsisGovuserIdentityProvider(null, config),
        "https://oauth2.gsis.gr/oauth2servergov");
  }

  @Test
  void gsisGovuserTest() {
    assertUrls(new GsisGovuserTestIdentityProvider(null, config),
        "https://test.gsis.gr/oauth2servergov");
  }

  // Second copy of the paths GsisAbstractIdentityProvider appends, so changing one there fails here
  private void assertUrls(GsisAbstractIdentityProvider idp, String baseUrl) {
    assertEquals(baseUrl + "/oauth/authorize", config.getAuthorizationUrl());
    assertEquals(baseUrl + "/oauth/token", config.getTokenUrl());
    assertEquals(baseUrl + "/userinfo?format=xml", idp.getUserInfoUrl());
    assertEquals(baseUrl + "/logout/{clientId}/", idp.getLogoutUrl());
  }
}

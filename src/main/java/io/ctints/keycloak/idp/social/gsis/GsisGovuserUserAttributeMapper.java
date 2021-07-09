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

import com.google.auto.service.AutoService;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.IdentityProviderMapper;

/** */
@AutoService(IdentityProviderMapper.class)
public class GsisGovuserUserAttributeMapper extends AbstractJsonUserAttributeMapper {

  public static final String PROVIDER_ID = "gsis-govuser-user-attribute-mapper";
  private static final String[] cp = new String[] {
    GsisGovuserTestIdentityProviderFactory.PROVIDER_ID, 
    GsisGovuserIdentityProviderFactory.PROVIDER_ID, 
    GsisTaxisTestIdentityProviderFactory.PROVIDER_ID, 
    GsisTaxisIdentityProviderFactory.PROVIDER_ID
  };

  @Override
  public String[] getCompatibleProviders() {
    return cp;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}

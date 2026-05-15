package gr.cti.nts.keycloak.idp.social.gsis.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class GsisLogoutResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  public GsisLogoutResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return new GsisLogoutResource(session);
  }

  @Override
  public void close() {}
}
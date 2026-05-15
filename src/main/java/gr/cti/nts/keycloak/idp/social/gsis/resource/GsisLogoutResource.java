package gr.cti.nts.keycloak.idp.social.gsis.resource;

import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class GsisLogoutResource {

  public static final String LOGOUT_RESPONSE_PATH = "response";

  private final KeycloakSession session;

  public GsisLogoutResource(KeycloakSession session) {
    this.session = session;
  }

  @GET
  @Path(LOGOUT_RESPONSE_PATH)
  public Response handleLogoutResponse(@QueryParam("state") String state) {
    RealmModel realm = session.getContext().getRealm();

    if (state == null) {
      log.error("No state parameter returned");
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);

      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    UserSessionModel userSession = session.sessions().getUserSession(realm, state);
    if (userSession == null) {
      log.error("no valid user session");
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);

      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
      log.error("usersession in different state");
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);

      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.SESSION_NOT_ACTIVE);
    }

    return AuthenticationManager.finishBrowserLogout(session, realm, userSession,
        session.getContext().getUri(), session.getContext().getConnection(),
        session.getContext().getRequestHeaders());
  }
}

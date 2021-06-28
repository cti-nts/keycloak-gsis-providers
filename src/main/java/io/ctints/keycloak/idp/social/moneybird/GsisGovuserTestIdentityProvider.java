package gr.cti.nts.keycloak.idp.social.gsis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import java.io.StringReader;
import org.xml.sax.InputSource;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;



/** */
@JBossLog
public class GsisGovuserTestIdentityProvider extends AbstractOAuth2IdentityProvider
    implements SocialIdentityProvider {

  public static final String AUTH_URL = "https://test.gsis.gr/oauth2servergov/oauth/authorize";
  public static final String TOKEN_URL = "https://test.gsis.gr/oauth2servergov/oauth/token";
  public static final String DEFAULT_SCOPE = "";

  private static final String USER_INFO_URL =
      "https://test.gsis.gr/oauth2servergov/userinfo?format=xml";

  public GsisGovuserTestIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
    super(session, config);
    config.setAuthorizationUrl(AUTH_URL);
    config.setTokenUrl(TOKEN_URL);
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(
      EventBuilder event, JsonNode profile) {
    log.infof("profile %s", jsonString(profile));

    BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"));

    String username = getJsonProperty(profile, "taxid");
    user.setUsername(username);
    user.setName(getJsonProperty(profile, "firstname")+getJsonProperty(profile, "lastname"));
    //user.setEmail(getJsonProperty(profile, "email"));
    user.setIdpConfig(getConfig());
    user.setIdp(this);

    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(
        user, profile, getConfig().getAlias());

    return user;
  }

  @Override
  protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
    String profileUrl = USER_INFO_URL;
    String profile = "";
    String jsonStringProfile = "";
    
    try {
      profile =
          SimpleHttp.doGet(profileUrl, session)
              .header("Authorization", "Bearer " + accessToken)
              .asString();
      final Map<String, String> userFields = new HashMap();
      SAXParserFactory parserFactory = SAXParserFactory.newInstance();
      parserFactory.setValidating(false);
      parserFactory.setXIncludeAware(false);
      parserFactory.setNamespaceAware(false);
      SAXParser parser = parserFactory.newSAXParser();
      parser.parse(new InputSource(new StringReader(profile)), new DefaultHandler() {
        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes)
                        throws SAXException {
          if ("userinfo".equals(qName)) {
            userFields.put("userid", attributes.getValue("userid"));
            userFields.put("taxid", attributes.getValue("taxid"));
            userFields.put("lastname", attributes.getValue("lastname"));
            userFields.put("firstname", attributes.getValue("firstname"));
            userFields.put("fathername", attributes.getValue("fathername"));
            userFields.put("mothername", attributes.getValue("mothername"));
            userFields.put("birthyear", attributes.getValue("birthyear"));
          }
        }
      });

      jsonStringProfile +="{";

      int index = 0;
      for(Map.Entry m:userFields.entrySet()){  
        if (index >0 ){
          jsonStringProfile+=", ";
        }
        jsonStringProfile += "\""+m.getKey()+"\":\""+m.getValue()+"\"";
        index++;
      }  

      jsonStringProfile +="}";

      ObjectMapper mapper = new ObjectMapper();
      JsonNode jsonProfile = mapper.readTree(jsonStringProfile);

      BrokeredIdentityContext user = extractIdentityFromProfile(null, jsonProfile);
      return user;
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not obtain user profile from gsis. *** Profile:"+jsonStringProfile+" ***", e);
    }
  }

  @Override
  protected String getDefaultScopes() {
    return DEFAULT_SCOPE;
  }

  private static String jsonString(JsonNode jsonNode) {
    try {
      ObjectMapper mapper = new ObjectMapper();
      Object json = mapper.readValue(jsonNode.toString(), Object.class);
      return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
    } catch (Exception e) {
      return null;
    }
  }

}

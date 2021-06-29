# Keycloak Gsis Providers

This <a href="https://www.keycloak.org/" target="_blank">Keycloak</a> plugin adds an production and testing identity providers allowing to use <a href="https://gsis.gr/en" target="_blank">Greek Public Administration</a> <a href="https://oauth.net/2/" target="_blank">OAuth 2</a> Services.

<a href="https://www.keycloak.org/" target="_blank">Keycloak</a> is an open source Identity and Access Management solution aimed at modern applications and services. It makes it easy to secure applications and services with little to no code. 

<a href="https://oauth.net/2/" target="_blank">OAuth 2</a> is an authorization framework that enables applications to obtain limited access to user accounts on an HTTP service, such as Facebook, GitHub, and Google. It works by delegating user authentication to the service that hosts the user account, and authorizing third-party applications to access the user account. OAuth 2 provides authorization flows for web and desktop applications, and mobile devices.

## Implemented identity providers

- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oauth20" target="_blank">TAXISnet OAuth2.0 authentication service</a> testing environmet (gsis-taxis-test)
- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oauth20" target="_blank">TAXISnet OAuth2.0 authentication service</a> production environmet (gsis-taxis)
- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oAuth2.0.PA" target="_blank">Employees OAuth2.0 authentication service</a> testing environmet (gsis-govuser-test)
- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oAuth2.0.PA" target="_blank">Employees OAuth2.0 authentication service</a> production environmet (gsis-govuser)

## How to get permissions for using Gsis OAuth 2.0 authentication services for your application

In order to be able to use Gsis OAuth 2.0 authentication services you need to request permission from Greek Public Administration. Instructions can be found at <a href="https://www.gsis.gr/en/public-administration/ked" target="_blank">Interoperability Center of the Ministry of Digital Governance (KE.D) web site</a>. 

After your request to KE.D is approved you will be given a clientId and a clientSecret for connectiong your application with Gsis OAuth2.0 providers.

## How to install Keycloak Gsis Providers extension 

**Quick**: Download keycloak-gsis-providers-<version>.jar from Releases page. Then deploy it into $KEYCLOAK_HOME/standalone/deployments/ directory.

You will need a functional Keycloak deployment. You can read <a href="https://www.keycloak.org/docs/latest/getting_started/" target="_blank">Keycloak getting started guide</a> for instructions on setting up a keycloak instance. You can also <a href="https://www.keycloak.org/getting-started/getting-started-docker" target="_blank">run Keycloak as a Docker Container</a> , or deploy Keycloak on Kubernetes via <a href="https://www.keycloak.org/getting-started/getting-started-kube" target="_blank">plain manifest</a> or using the <a href="https://www.keycloak.org/getting-started/getting-started-operator-kubernetes" target="_blank">Keycloak Operator</a>. 

After having set up your Keycloak download <a href="https://github.com/cti-nts/keycloak-gsis-providers/releases/latest">the latest Keycloak Gsis Providers release jar</a> and install it to your instance. See <a href="https://www.keycloak.org/docs/latest/server_installation/index.html#distribution-directory-structure" target="_blank">Keycloak server installation documnetation</a> for more info. You can also easily <a href="https://www.keycloak.org/docs/latest/server_installation/index.html#_operator-extensions" target="_blank"> deploy the extension wthrough Keycloak Manifest</a> if you are using Keycloak Operator on Kubernetes.  

## How to use Keycloak Gsis Providers extension

After installing the extension the following options will be available through Identity Providers -> Add Provider Keycloak administration console menu:

- GsisTaxisTest (TAXISnet testing)
- GsisTaxis (TAXISnet production)
- GsisGovuserTest (Employees testing)
- GsisGovUser (Employees production)

Select the one you want to use and fill in the settings form with the appropriate info and credentials for your application. See the <a href="https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker" target="_blank">Identity Brokering section of Keycloak Server Admin</a> for more info. 

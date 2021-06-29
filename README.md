# Keycloak Gsis Providers

This Keycloak plugin adds an production and testing identity providers allowing to use Greek Public Administration OAuth2 Services.

## Implemented identity providers

- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oauth20" target="_blank">TAXISnet OAuth2.0 authentication</a> testing environmet (gsis-taxis-test)
- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oauth20" target="_blank">TAXISnet OAuth2.0 authentication</a> production environmet (gsis-taxis)
- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oAuth2.0.PA" target="_blank">Employees OAuth2.0 authentication</a> testing environmet (gsis-govuser-test)
- <a href="https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oAuth2.0.PA" target="_blank">Employees OAuth2.0 authentication</a> production environmet (gsis-govuser)

## How to get permissions for using Gsis OAuth 2.0 authentication services for your application

In order to be able to use Gsis OAuth 2.0 authentication services you need to request permission from Greek Public Administration. Instructions can be found at <a href="https://www.gsis.gr/en/public-administration/ked" target="_blank">Interoperability Center of the Ministry of Digital Governance (KE.D) web site</a>. 

After your request to KE.D is approved you will be given a clientId and a clientSecret for connectiong your application with Gsis OAuth2.0 providers.




# Keycloak Gsis Providers [![Build Status](https://github.com/cti-nts/keycloak-gsis-providers/workflows/CI/badge.svg)](https://github.com/cti-nts/keycloak-gsis-providers/actions?query=workflow%3ACI+branch%3Amain)

This [Keycloak](https://www.keycloak.org/) plugin adds production and testing identity providers for using [Greek General Secretariat of Information Systems for Public Administration (GSIS)](https://gsis.gr/en) [OAuth 2](https://oauth.net/2/) Services.

[Keycloak](https://www.keycloak.org/) is an open-source Identity and Access Management solution aimed at modern applications and services. It makes it easy to secure applications and services with little to no code.

[OAuth 2](https://oauth.net/2/) is an authorization framework that enables applications to obtain limited access to user accounts on an HTTP service, such as Facebook, GitHub, and Google. It works by delegating user authentication to the service that hosts the user account and authorizing third-party applications to access the user account. OAuth 2 provides authorization flows for web and desktop applications, and mobile devices.

## Implemented identity providers

- [TAXISnet OAuth2.0 authentication service](https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oauth20) testing environment (gsis-taxis-test)
- [TAXISnet OAuth2.0 authentication service](https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oauth20) production environment (gsis-taxis)
- [Employees OAuth2.0 authentication service](https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oAuth2.0.PA) testing environment (gsis-govuser-test)
- [Employees OAuth2.0 authentication service](https://www.gsis.gr/dimosia-dioikisi/ked/webservices/oAuth2.0.PA) production environment (gsis-govuser)

## How to get permissions for using Gsis OAuth 2.0 authentication services for your application

In order to be able to use Gsis OAuth 2.0 authentication services you need to request permission from GSIS. Instructions can be found at the [Interoperability Center of the Ministry of Digital Governance (KE.D) website](https://www.gsis.gr/en/public-administration/ked).

After your request to KE.D is approved you will be given a `clientId` and a `clientSecret` for connecting your application with Gsis OAuth 2.0 providers.

**IMPORTANT NOTICE:**

You must acquire separate permission (separate `clientId`) for each specific application you want to use GSIS OAuth2 with. Providing GSIS OAuth2 identification and authorization data to applications other than those an acquired permission is for is against the service license provided by GSIS and will result in revoking your access to the service.

## Installation

**Quick**: Download [latest release](https://github.com/cti-nts/keycloak-gsis-providers/releases/latest) jar from Releases page. Then deploy it into `$KEYCLOAK_HOME/standalone/deployments/` directory.

You will need a functional Keycloak deployment. You can read [Keycloak getting started guide](https://www.keycloak.org/docs/latest/getting_started/) for instructions on setting up a Keycloak instance. You can also [run Keycloak as a Docker Container](https://www.keycloak.org/getting-started/getting-started-docker), or deploy Keycloak on Kubernetes via [plain manifest](https://www.keycloak.org/getting-started/getting-started-kube) or using the [Keycloak Operator](https://www.keycloak.org/getting-started/getting-started-operator-kubernetes).

After having set up your Keycloak download [the latest Keycloak Gsis Providers release](https://github.com/cti-nts/keycloak-gsis-providers/releases/latest) jar and install it to your instance. See [Keycloak server installation documentation](https://www.keycloak.org/docs/latest/server_installation/index.html#distribution-directory-structure) for more info. You can also easily [deploy the extension through Operator Keycloak Manifest](https://www.keycloak.org/docs/latest/server_installation/index.html#_operator-extensions) if you are using Keycloak Operator on Kubernetes.

After successfully installing the extension the following options will be available through Identity Providers → Add Provider Keycloak administration console menu:

- GsisTaxisTest (TAXISnet testing)
- GsisTaxis (TAXISnet production)
- GsisGovuserTest (Employees testing)
- GsisGovUser (Employees production)

## Setup

- Add the Gsis Identity Provider you want to use in the realm which you want to configure.
- In the Gsis identity provider page, set Client Id and Client Secret.
- (Optional) Set the alias for the provider and other options if you want.
- (Optional) Set up provider mappers (See profile fields)

See the [Identity Brokering section of Keycloak Server Admin](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker) for more info.

### Profile Fields

Gsis OAuth 2.0 service provides the following profile fields for **individuals**:

- `userid`
- `taxid`
- `lastname`
- `firstname`
- `fathername`
- `mothername`
- `birthyear`

In Identity Provider Mapper page Select `Attribute Importer` as `Mapper Type` to import a profile field as a user attribute.

## Source Build

Clone this repository and run `mvn package`. You can see `keycloak-gsis-providers-{version}.jar` under the target directory.

## Licence

Apache License, Version 2.0

## Author

- [Konstantinos Togias](https://github.com/ktogias)

Built for the needs of [Greek School Network and Networking Technologies Directorate](http://nts.cti.gr/).  
Based on [this sample extension](https://github.com/xgp/keycloak-moneybird-idp) by [xgp](https://github.com/xgp).

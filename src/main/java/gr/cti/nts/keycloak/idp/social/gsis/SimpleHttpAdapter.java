/*
 * Copyright 2021 Greek School Network and Networking Technologies Directorate (http://nts.cti.gr/),
 * Konstantinos Togias (ktogias@cti.gr) and/or their affiliates and other contributors as indicated
 * by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package gr.cti.nts.keycloak.idp.social.gsis;

import java.lang.reflect.Method;
import org.keycloak.models.KeycloakSession;
import lombok.extern.jbosslog.JBossLog;

/**
 * Runtime adapter for SimpleHttp API differences between Keycloak versions.
 * 
 * Older API (Keycloak <= 22.x):
 * - org.keycloak.broker.provider.util.SimpleHttp
 * - static doGet/doPost methods returning SimpleHttp
 * 
 * Newer API (Keycloak >= 24.x):
 * - org.keycloak.http.simple.SimpleHttpRequest
 * - static get/post methods returning SimpleHttpRequest
 */
@JBossLog
public class SimpleHttpAdapter {

  private static final String OLD_CLASS = "org.keycloak.broker.provider.util.SimpleHttp";
  private static final String NEW_CLASS = "org.keycloak.http.simple.SimpleHttpRequest";
  
  private static Class<?> httpClass;
  private static boolean isNewApi;
  private static Method getMethod;
  private static Method postMethod;
  
  static {
    // Detect API version once at class load time
    try {
      httpClass = Class.forName(NEW_CLASS);
      isNewApi = true;
      log.infof("Using new SimpleHttpRequest API from %s", NEW_CLASS);
      // Cache method references for new API
      getMethod = httpClass.getMethod("get", String.class, KeycloakSession.class);
      postMethod = httpClass.getMethod("post", String.class, KeycloakSession.class);
    } catch (ClassNotFoundException e) {
      // Fall back to old API
      try {
        httpClass = Class.forName(OLD_CLASS);
        isNewApi = false;
        log.infof("Using old SimpleHttp API from %s", OLD_CLASS);
        // Cache method references for old API
        getMethod = httpClass.getMethod("doGet", String.class, KeycloakSession.class);
        postMethod = httpClass.getMethod("doPost", String.class, KeycloakSession.class);
      } catch (ClassNotFoundException | NoSuchMethodException ex) {
        throw new RuntimeException("Could not find SimpleHttp API class or methods", ex);
      }
    } catch (NoSuchMethodException e) {
      throw new RuntimeException("Could not find required methods in SimpleHttpRequest API", e);
    }
  }
  
  /**
   * Create a GET request adapter.
   * 
   * @param url The URL to GET
   * @param session The Keycloak session
   * @return Request object (SimpleHttp or SimpleHttpRequest)
   */
  public static Object doGet(String url, KeycloakSession session) {
    try {
      return getMethod.invoke(null, url, session);
    } catch (Exception e) {
      throw new RuntimeException("Failed to create GET request for URL: " + url, e);
    }
  }
  
  /**
   * Create a POST request adapter.
   * 
   * @param url The URL to POST to
   * @param session The Keycloak session
   * @return Request object (SimpleHttp or SimpleHttpRequest)
   */
  public static Object doPost(String url, KeycloakSession session) {
    try {
      return postMethod.invoke(null, url, session);
    } catch (Exception e) {
      throw new RuntimeException("Failed to create POST request for URL: " + url, e);
    }
  }
  
  /**
   * Add a header to the request.
   * 
   * @param request Request object
   * @param name Header name
   * @param value Header value
   * @return The same request object for chaining
   */
  public static Object header(Object request, String name, String value) {
    try {
      Method headerMethod = request.getClass().getMethod("header", String.class, String.class);
      return headerMethod.invoke(request, name, value);
    } catch (Exception e) {
      throw new RuntimeException("Failed to set header", e);
    }
  }
  
  /**
   * Add a parameter to the request.
   * 
   * @param request Request object
   * @param name Parameter name
   * @param value Parameter value
   * @return The same request object for chaining
   */
  public static Object param(Object request, String name, String value) {
    try {
      Method paramMethod = request.getClass().getMethod("param", String.class, String.class);
      return paramMethod.invoke(request, name, value);
    } catch (Exception e) {
      throw new RuntimeException("Failed to set parameter", e);
    }
  }
  
  /**
   * Execute the request and return the response as a string.
   * 
   * @param request Request object
   * @return Response body as string
   */
  public static String asString(Object request) {
    try {
      Method asStringMethod = request.getClass().getMethod("asString");
      return (String) asStringMethod.invoke(request);
    } catch (Exception e) {
      throw new RuntimeException("Failed to execute request", e);
    }
  }
}

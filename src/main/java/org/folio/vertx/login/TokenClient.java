package org.folio.vertx.login;

import io.netty.handler.codec.http.cookie.ClientCookieDecoder;
import io.netty.handler.codec.http.cookie.Cookie;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.WebClient;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.okapi.common.XOkapiHeaders;
import org.folio.vertx.tokencache.TokenCache;

public class TokenClient {
  private static final Logger log = LogManager.getLogger(TokenClient.class);

  private final TokenCache cache;
  private final WebClient client;
  private final String okapiUrl;
  private final String tenant;
  private final String username;
  private final Supplier<Future<String>> getPasswordSupplier;

  /**
   * Refresh legacy tokens older than this.
   */
  private static final long AGE_LEGACY_TOKEN = 86400L;

  /**
   * Subtract this many seconds of age, before considering expired
   */
  private static final long AGE_DIFF_TOKEN = 10L;

  public TokenClient(String okapiUrl, WebClient client, TokenCache cache, String tenant,
      String username, Supplier<Future<String>> getPasswordSupplier) {
    this.cache = cache;
    this.client = client;
    this.okapiUrl = okapiUrl;
    this.tenant = tenant;
    this.username = username;
    this.getPasswordSupplier = getPasswordSupplier;
  }

  Future<HttpRequest<Buffer>> getTokenLegacy(HttpRequest<Buffer> request, JsonObject payload) {
    return client.postAbs(okapiUrl + "/authn/login")
        .putHeader("Accept", "*/*")
        .putHeader(XOkapiHeaders.TENANT, tenant)
        .sendJsonObject(payload).map(res -> {
          if (res.statusCode() != 201) {
            throw new RuntimeException(res.bodyAsString());
          }
          String newToken = res.getHeader(XOkapiHeaders.TOKEN);
          request.putHeader(XOkapiHeaders.TOKEN, newToken);
          cache.put(tenant, username, newToken, System.currentTimeMillis() + AGE_LEGACY_TOKEN * 1000);
          return request;
        });
  }

  Future<HttpRequest<Buffer>> getTokenWithExpiry(HttpRequest<Buffer> request, JsonObject payload) {
    return client.postAbs(okapiUrl + "/authn/login-with-expiry")
        .putHeader("Accept", "*/*")
        .putHeader(XOkapiHeaders.TENANT, tenant)
        .sendJsonObject(payload).map(res -> {
          if (res.statusCode() == 201) {
            res.headers().forEach(n -> {
              if ("Set-Cookie".equals(n.getKey())) {
                Cookie cookie = ClientCookieDecoder.STRICT.decode(n.getValue());
                // TODO use COOKIE_ACCESS_TOKEN from Okapi (not released yet)
                if ("folioAccessToken".equals(cookie.name())) {
                  request.putHeader(XOkapiHeaders.TOKEN, cookie.value());
                  long age = cookie.maxAge() - AGE_DIFF_TOKEN;
                  if (age < 0L) {
                    age = 0L;
                  }
                  cache.put(tenant, username, cookie.value(), System.currentTimeMillis() + age * 1000);
                }
              }
            });
            return request;
          } else if (res.statusCode() == 404) {
            return null;
          } else {
            throw new RuntimeException(res.bodyAsString());
          }
        });
  }

  public Future<HttpRequest<Buffer>> getToken(HttpRequest<Buffer> request) {
    String cacheValue;
    try {
      cacheValue = cache.get(tenant, username);
    } catch (Exception e) {
      log.warn("Failed to access TokenCache {}", e.getMessage(), e);
      return Future.failedFuture("Failed to access TokenCache");
    }
    if (cacheValue != null) {
      request.putHeader(XOkapiHeaders.TOKEN, cacheValue);
      return Future.succeededFuture(request);
    }
    return getPasswordSupplier.get().compose(password -> {
      JsonObject payload = new JsonObject()
          .put("username", username)
          .put("password", password);
      return getTokenWithExpiry(request, payload)
          .compose(res -> res != null ? Future.succeededFuture(res) : getTokenLegacy(request, payload));
    });
  }
}

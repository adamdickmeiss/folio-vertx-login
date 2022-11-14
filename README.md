# folio-vertx-login

A library for obtaining tokens for system users in Vert.x based FOLIO modules.

## How to use

Create a token cache. Only one instance per Verticle or process.

```java
   TokenCache tokenCache = TokenCache.create(1000);
```

For each request (per request, per tenant), create an `TokenClient`:

```java
   String okapiUrl = "...";
   String tenant = "...";
   String user = "myuser"; // system user presumably
   String password = "..."; // system password presumably
   TokenClient tokenClient = new TokenClient(
           okapiUrl, webClient, tokenCache, tenant, user,
           () -> Future.succeededFuture(password));

```

For each HTTP request that the module must do, use the `getToken`
method with `WebClient`:

```java
    tokenClient.getToken(webClient.postAbs(okapiUrl + "/echo")
        .putHeader("Content-Type", "text/xml")
        .expect(ResponsePredicate.SC_CREATED))
      .compose(request -> request.sendBuffer(xmlBody))
      .compose(response -> {
          // handle response
      }));
```





# Halo cms V2.21.10存在url重定向漏洞

POC

```
http(s)://target_domain/apis/api.storage.halo.run/v1alpha1/thumbnails/-/via-uri?uri=http(s)://redirect_url&size=m
```


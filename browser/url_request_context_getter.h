// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-CHROMIUM file.

#ifndef BRIGHTRAY_BROWSER_URL_REQUEST_CONTEXT_GETTER_H_
#define BRIGHTRAY_BROWSER_URL_REQUEST_CONTEXT_GETTER_H_

#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "content/public/browser/content_browser_client.h"
#include "net/http/http_cache.h"
#include "net/http/url_security_manager.h"
#include "net/url_request/url_request_context_getter.h"

namespace base {
class MessageLoop;
}

namespace net {
class HostMappingRules;
class HostResolver;
class NetworkDelegate;
class ProxyConfigService;
class URLRequestContextStorage;
class URLRequestJobFactory;
}

namespace brightray {

class NetLog;
class URLRequestContextGetterFactory;

class URLRequestContextGetter : public net::URLRequestContextGetter {
 public:
  class Delegate {
   public:
    Delegate() {}
    virtual ~Delegate() {}

    virtual net::NetworkDelegate* CreateNetworkDelegate() { return NULL; }
    virtual std::string GetUserAgent();
    virtual net::URLRequestJobFactory* CreateURLRequestJobFactory(
        content::ProtocolHandlerMap* protocol_handlers,
        content::URLRequestInterceptorScopedVector* protocol_interceptors);
    virtual net::HttpCache::BackendFactory* CreateHttpCacheBackendFactory(
        const base::FilePath& base_path);
  };

  explicit URLRequestContextGetter(URLRequestContextGetterFactory* factory);
  virtual ~URLRequestContextGetter();

  // net::URLRequestContextGetter:
  net::URLRequestContext* GetURLRequestContext() override;
  scoped_refptr<base::SingleThreadTaskRunner> GetNetworkTaskRunner() const override;

  net::HostResolver* host_resolver();
  void NotifyContextShuttingDown();
  static URLRequestContextGetter* CreateMainRequestContext(
      Delegate* delegate,
      NetLog* net_log,
      const base::FilePath& base_path,
      base::MessageLoop* io_loop,
      base::MessageLoop* file_loop,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector protocol_interceptors);
  static URLRequestContextGetter* CreateIsolatedRequestContext(
      Delegate* delegate,
      scoped_refptr<net::URLRequestContextGetter> main_request_context_getter,
      const base::FilePath& partition_path, bool in_memory,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector protocol_interceptors);

 private:
  scoped_ptr<URLRequestContextGetterFactory> factory_;
  net::URLRequestContext* url_request_context_;

  // Ensures URLRequestContextGetterFactory::Create is called only once.
  bool initialized_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestContextGetter);
};

}  // namespace brightray

#endif

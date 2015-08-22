// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-CHROMIUM file.

#include "browser/url_request_context_getter.h"

#include <algorithm>

#include "browser/net_log.h"
#include "browser/network_delegate.h"

#include "base/command_line.h"
#include "base/strings/string_util.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/threading/worker_pool.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/cookie_store_factory.h"
#include "content/public/common/content_switches.h"
#include "net/base/host_mapping_rules.h"
#include "net/cert/cert_verifier.h"
#include "net/cookies/cookie_monster.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_server_properties_impl.h"
#include "net/log/net_log.h"
#include "net/proxy/dhcp_proxy_script_fetcher_factory.h"
#include "net/proxy/proxy_config_service.h"
#include "net/proxy/proxy_script_fetcher_impl.h"
#include "net/proxy/proxy_service.h"
#include "net/proxy/proxy_service_v8.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/url_request/data_protocol_handler.h"
#include "net/url_request/file_protocol_handler.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_storage.h"
#include "net/url_request/url_request_intercepting_job_factory.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "url/url_constants.h"
#include "storage/browser/quota/special_storage_policy.h"

using content::BrowserThread;

namespace brightray {

namespace {

// Comma-separated list of rules that control how hostnames are mapped.
//
// For example:
//    "MAP * 127.0.0.1" --> Forces all hostnames to be mapped to 127.0.0.1
//    "MAP *.google.com proxy" --> Forces all google.com subdomains to be
//                                 resolved to "proxy".
//    "MAP test.com [::1]:77 --> Forces "test.com" to resolve to IPv6 loopback.
//                               Will also force the port of the resulting
//                               socket address to be 77.
//    "MAP * baz, EXCLUDE www.google.com" --> Remaps everything to "baz",
//                                            except for "www.google.com".
//
// These mappings apply to the endpoint host in a net::URLRequest (the TCP
// connect and host resolver in a direct connection, and the CONNECT in an http
// proxy connection, and the endpoint host in a SOCKS proxy connection).
const char kHostRules[] = "host-rules";

// Don't use a proxy server, always make direct connections. Overrides any
// other proxy server flags that are passed.
const char kNoProxyServer[] = "no-proxy-server";

// Uses a specified proxy server, overrides system settings. This switch only
// affects HTTP and HTTPS requests.
const char kProxyServer[] = "proxy-server";

// Uses the pac script at the given URL.
const char kProxyPacUrl[] = "proxy-pac-url";

}  // namespace

std::string URLRequestContextGetter::Delegate::GetUserAgent() {
  return base::EmptyString();
}

net::URLRequestJobFactory* URLRequestContextGetter::Delegate::CreateURLRequestJobFactory(
    content::ProtocolHandlerMap* protocol_handlers,
    content::URLRequestInterceptorScopedVector* protocol_interceptors) {
  scoped_ptr<net::URLRequestJobFactoryImpl> job_factory(new net::URLRequestJobFactoryImpl);

  for (auto it = protocol_handlers->begin(); it != protocol_handlers->end(); ++it)
    job_factory->SetProtocolHandler(it->first, it->second.release());
  protocol_handlers->clear();

  job_factory->SetProtocolHandler(url::kDataScheme, new net::DataProtocolHandler);
  job_factory->SetProtocolHandler(url::kFileScheme, new net::FileProtocolHandler(
      BrowserThread::GetBlockingPool()->GetTaskRunnerWithShutdownBehavior(
          base::SequencedWorkerPool::SKIP_ON_SHUTDOWN)));

  // Set up interceptors in the reverse order.
  scoped_ptr<net::URLRequestJobFactory> top_job_factory = job_factory.Pass();
  content::URLRequestInterceptorScopedVector::reverse_iterator i;
  for (i = protocol_interceptors->rbegin(); i != protocol_interceptors->rend(); ++i)
    top_job_factory.reset(new net::URLRequestInterceptingJobFactory(
        top_job_factory.Pass(), make_scoped_ptr(*i)));
  protocol_interceptors->weak_clear();

  return top_job_factory.release();
}

net::HttpCache::BackendFactory*
URLRequestContextGetter::Delegate::CreateHttpCacheBackendFactory(const base::FilePath& base_path) {
  base::FilePath cache_path = base_path.Append(FILE_PATH_LITERAL("Cache"));
  return new net::HttpCache::DefaultBackend(
      net::DISK_CACHE,
      net::CACHE_BACKEND_DEFAULT,
      cache_path,
      0,
      BrowserThread::GetMessageLoopProxyForThread(BrowserThread::CACHE));
}

class URLRequestContextGetterFactory {
  public:
   URLRequestContextGetterFactory() {}
   virtual ~URLRequestContextGetterFactory() {}

   virtual net::URLRequestContext* Create() = 0;
  protected:
   DISALLOW_COPY_AND_ASSIGN(URLRequestContextGetterFactory);
};

// Container Class that owns cookie_store and http_factory
// to ensure their deletion.
class IsolatedRequestContext : public net::URLRequestContext {
  public:
   IsolatedRequestContext() {}

   void SetCookieStore(net::CookieStore* cookie_store) {
     cookie_store_ = cookie_store;
     set_cookie_store(cookie_store);
   }

   void SetHttpTransactionFactory(net::HttpTransactionFactory* http_factory) {
     http_factory_.reset(http_factory);
     set_http_transaction_factory(http_factory_.get());
   }

   void SetJobFactory(net::URLRequestJobFactory* job_factory) {
     job_factory_.reset(job_factory);
     set_job_factory(job_factory_.get());
   }

  private:
   scoped_refptr<net::CookieStore> cookie_store_;
   scoped_ptr<net::HttpTransactionFactory> http_factory_;
   scoped_ptr<net::URLRequestJobFactory> job_factory_;
};

// Factory to create Isolated URLRequestContext.
class IsolatedRequestContextFactory : public URLRequestContextGetterFactory {
  public:
   IsolatedRequestContextFactory(
      URLRequestContextGetter::Delegate* delegate,
      scoped_refptr<net::URLRequestContextGetter> main_request_context_getter,
      const base::FilePath& partition_path,
      bool in_memory,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector protocol_interceptors)
      : delegate_(delegate),
        main_request_context_(main_request_context_getter),
        base_path_(partition_path),
        in_memory_(in_memory),
        protocol_interceptors_(protocol_interceptors.Pass()) {
      // Must first be created on the UI thread.
      DCHECK_CURRENTLY_ON(BrowserThread::UI);

      std::swap(protocol_handlers_, *protocol_handlers);
    }

   net::URLRequestContext* Create() override {
     DCHECK_CURRENTLY_ON(BrowserThread::IO);

     net::URLRequestContext* main_context =
        main_request_context_->GetURLRequestContext();
     IsolatedRequestContext* isolated_context = new IsolatedRequestContext();

     isolated_context->CopyFrom(main_context);

     scoped_refptr<net::CookieStore> cookie_store = nullptr;
     if (in_memory_) {
        cookie_store = content::CreateCookieStore(content::CookieStoreConfig());
     } else {
       auto cookie_config = content::CookieStoreConfig(
           base_path_.Append(FILE_PATH_LITERAL("Cookies")),
           content::CookieStoreConfig::EPHEMERAL_SESSION_COOKIES,
           NULL, NULL);
       cookie_store = content::CreateCookieStore(cookie_config);
     }

    net::HttpCache::BackendFactory* backend = nullptr;
    if (in_memory_) {
      backend = net::HttpCache::DefaultBackend::InMemory(0);
    } else {
      backend = delegate_->CreateHttpCacheBackendFactory(base_path_);
    }
    net::HttpNetworkSession* network_session =
        main_context->http_transaction_factory()->GetSession();

     isolated_context->SetCookieStore(cookie_store.get());
     isolated_context->SetHttpTransactionFactory(
        new net::HttpCache(network_session->params(), backend));
     isolated_context->SetJobFactory(delegate_->CreateURLRequestJobFactory(
        &protocol_handlers_, &protocol_interceptors_));

      return isolated_context;
   }

  private:
   URLRequestContextGetter::Delegate* delegate_;

   base::FilePath base_path_;
   bool in_memory_;

   scoped_refptr<net::URLRequestContextGetter> main_request_context_;
   content::ProtocolHandlerMap protocol_handlers_;
   content::URLRequestInterceptorScopedVector protocol_interceptors_;

   DISALLOW_COPY_AND_ASSIGN(IsolatedRequestContextFactory);
};

// Factory to create the main URLRequestContext.
class MainRequestContextFactory : public URLRequestContextGetterFactory {
  public:
   MainRequestContextFactory(
      URLRequestContextGetter::Delegate* delegate,
      NetLog* net_log,
      const base::FilePath& base_path,
      base::MessageLoop* io_loop,
      base::MessageLoop* file_loop,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector protocol_interceptors)
      : delegate_(delegate),
        net_log_(net_log),
        base_path_(base_path),
        io_loop_(io_loop),
        file_loop_(file_loop),
        url_sec_mgr_(net::URLSecurityManager::Create(NULL, NULL)),
        protocol_interceptors_(protocol_interceptors.Pass()) {
      // Must first be created on the UI thread.
      DCHECK_CURRENTLY_ON(BrowserThread::UI);

      std::swap(protocol_handlers_, *protocol_handlers);

      // We must create the proxy config service on the UI loop on Linux because it
      // must synchronously run on the glib message loop. This will be passed to
      // the URLRequestContextStorage on the IO thread in GetURLRequestContext().
      proxy_config_service_.reset(net::ProxyService::CreateSystemProxyConfigService(
          io_loop_->message_loop_proxy(), file_loop_->message_loop_proxy()));
    }

   net::URLRequestContext* Create() override {
     DCHECK_CURRENTLY_ON(BrowserThread::IO);

      auto& command_line = *base::CommandLine::ForCurrentProcess();
      net::URLRequestContext* main_context = new net::URLRequestContext();

      // --log-net-log
      net_log_->StartLogging(main_context);
      main_context->set_net_log(net_log_);

      network_delegate_.reset(delegate_->CreateNetworkDelegate());
      main_context->set_network_delegate(network_delegate_.get());

      storage_.reset(new net::URLRequestContextStorage(main_context));

      auto cookie_config = content::CookieStoreConfig(
          base_path_.Append(FILE_PATH_LITERAL("Cookies")),
          content::CookieStoreConfig::EPHEMERAL_SESSION_COOKIES,
          NULL, NULL);
      scoped_refptr<net::CookieStore> cookie_store = content::CreateCookieStore(cookie_config);

      storage_->set_cookie_store(cookie_store.get());
      storage_->set_channel_id_service(make_scoped_ptr(
          new net::ChannelIDService(new net::DefaultChannelIDStore(NULL),
                                    base::WorkerPool::GetTaskRunner(true))));
      storage_->set_http_user_agent_settings(new net::StaticHttpUserAgentSettings(
          "en-us,en", delegate_->GetUserAgent()));

      scoped_ptr<net::HostResolver> host_resolver(net::HostResolver::CreateDefaultResolver(nullptr));

      // --host-resolver-rules
      if (command_line.HasSwitch(switches::kHostResolverRules)) {
        scoped_ptr<net::MappedHostResolver> remapped_resolver(
           new net::MappedHostResolver(host_resolver.Pass()));
        remapped_resolver->SetRulesFromString(
            command_line.GetSwitchValueASCII(switches::kHostResolverRules));
        host_resolver = remapped_resolver.Pass();
      }

      // --proxy-server
      net::DhcpProxyScriptFetcherFactory dhcp_factory;
      if (command_line.HasSwitch(kNoProxyServer)) {
        storage_->set_proxy_service(net::ProxyService::CreateDirect());
      } else if (command_line.HasSwitch(kProxyServer)) {
        storage_->set_proxy_service(net::ProxyService::CreateFixed(
            command_line.GetSwitchValueASCII(kProxyServer)));
      } else if (command_line.HasSwitch(kProxyPacUrl)) {
        auto proxy_config = net::ProxyConfig::CreateFromCustomPacURL(
            GURL(command_line.GetSwitchValueASCII(kProxyPacUrl)));
        proxy_config.set_pac_mandatory(true);
        storage_->set_proxy_service(net::ProxyService::CreateFixed(
            proxy_config));
      } else {
        storage_->set_proxy_service(
            net::CreateProxyServiceUsingV8ProxyResolver(
                proxy_config_service_.release(),
                new net::ProxyScriptFetcherImpl(main_context),
                dhcp_factory.Create(main_context),
                host_resolver.get(),
                NULL,
                main_context->network_delegate()));
      }

      std::vector<std::string> schemes;
      schemes.push_back(std::string("basic"));
      schemes.push_back(std::string("digest"));
      schemes.push_back(std::string("ntlm"));
      schemes.push_back(std::string("negotiate"));

      auto auth_handler_factory =
          net::HttpAuthHandlerRegistryFactory::Create(
              schemes,
              url_sec_mgr_.get(),
              host_resolver.get(),
              std::string(),  // gssapi_library_name
              false,          // negotiate_disable_cname_lookup
              true);          // negotiate_enable_port

      storage_->set_cert_verifier(net::CertVerifier::CreateDefault());
      storage_->set_transport_security_state(new net::TransportSecurityState);
      storage_->set_ssl_config_service(new net::SSLConfigServiceDefaults);
      storage_->set_http_auth_handler_factory(auth_handler_factory);
      scoped_ptr<net::HttpServerProperties> server_properties(
          new net::HttpServerPropertiesImpl);
      storage_->set_http_server_properties(server_properties.Pass());

      net::HttpNetworkSession::Params network_session_params;
      network_session_params.cert_verifier = main_context->cert_verifier();
      network_session_params.proxy_service = main_context->proxy_service();
      network_session_params.ssl_config_service = main_context->ssl_config_service();
      network_session_params.network_delegate = main_context->network_delegate();
      network_session_params.http_server_properties = main_context->http_server_properties();
      network_session_params.ignore_certificate_errors = false;
      network_session_params.transport_security_state =
          main_context->transport_security_state();
      network_session_params.channel_id_service =
          main_context->channel_id_service();
      network_session_params.http_auth_handler_factory =
          main_context->http_auth_handler_factory();
      network_session_params.net_log = main_context->net_log();

      // --ignore-certificate-errors
      if (command_line.HasSwitch(switches::kIgnoreCertificateErrors))
        network_session_params.ignore_certificate_errors = true;

      // --host-rules
      if (command_line.HasSwitch(kHostRules)) {
        host_mapping_rules_.reset(new net::HostMappingRules);
        host_mapping_rules_->SetRulesFromString(command_line.GetSwitchValueASCII(kHostRules));
        network_session_params.host_mapping_rules = host_mapping_rules_.get();
      }

      // Give |storage_| ownership at the end in case it's |mapped_host_resolver|.
      storage_->set_host_resolver(host_resolver.Pass());
      network_session_params.host_resolver = main_context->host_resolver();

      net::HttpCache::BackendFactory* backend =
          delegate_->CreateHttpCacheBackendFactory(base_path_);
      storage_->set_http_transaction_factory(new net::HttpCache(network_session_params, backend));

      storage_->set_job_factory(delegate_->CreateURLRequestJobFactory(
          &protocol_handlers_, &protocol_interceptors_));

     return main_context;
   }

  private:
   URLRequestContextGetter::Delegate* delegate_;

   NetLog* net_log_;
   base::FilePath base_path_;
   base::MessageLoop* io_loop_;
   base::MessageLoop* file_loop_;

   scoped_ptr<net::ProxyConfigService> proxy_config_service_;
   scoped_ptr<net::NetworkDelegate> network_delegate_;
   scoped_ptr<net::URLRequestContextStorage> storage_;
   scoped_ptr<net::HostMappingRules> host_mapping_rules_;
   scoped_ptr<net::URLSecurityManager> url_sec_mgr_;
   content::ProtocolHandlerMap protocol_handlers_;
   content::URLRequestInterceptorScopedVector protocol_interceptors_;

   DISALLOW_COPY_AND_ASSIGN(MainRequestContextFactory);
};

URLRequestContextGetter::URLRequestContextGetter(
    URLRequestContextGetterFactory* factory)
    : factory_(factory),
      url_request_context_(nullptr),
      initialized_(false) {}

URLRequestContextGetter::~URLRequestContextGetter() {
}

net::URLRequestContext* URLRequestContextGetter::GetURLRequestContext() {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  if (!initialized_) {
    initialized_ = true;
    url_request_context_ = factory_->Create();
  }

  return url_request_context_;
}

scoped_refptr<base::SingleThreadTaskRunner> URLRequestContextGetter::GetNetworkTaskRunner() const {
  return BrowserThread::GetMessageLoopProxyForThread(BrowserThread::IO);
}

void URLRequestContextGetter::NotifyContextShuttingDown() {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  factory_.reset();
  url_request_context_ = nullptr;
  net::URLRequestContextGetter::NotifyContextShuttingDown();
}

net::HostResolver* URLRequestContextGetter::host_resolver() {
  return url_request_context_->host_resolver();
}

// static
URLRequestContextGetter* URLRequestContextGetter::CreateMainRequestContext(
    Delegate* delegate, NetLog* net_log, const base::FilePath& base_path,
    base::MessageLoop* io_loop, base::MessageLoop* file_loop,
    content::ProtocolHandlerMap* protocol_handlers,
    content::URLRequestInterceptorScopedVector protocol_interceptors) {
  return new URLRequestContextGetter(
      new MainRequestContextFactory(delegate,
                                    net_log,
                                    base_path,
                                    io_loop,
                                    file_loop,
                                    protocol_handlers,
                                    protocol_interceptors.Pass()));
}

// static
URLRequestContextGetter* URLRequestContextGetter::CreateIsolatedRequestContext(
    Delegate* delegate,
    scoped_refptr<net::URLRequestContextGetter> main_request_context_getter,
    const base::FilePath& partition_path, bool in_memory,
    content::ProtocolHandlerMap* protocol_handlers,
    content::URLRequestInterceptorScopedVector protocol_interceptors) {
  return new URLRequestContextGetter(
      new IsolatedRequestContextFactory(delegate,
                                        main_request_context_getter,
                                        partition_path,
                                        in_memory,
                                        protocol_handlers,
                                        protocol_interceptors.Pass()));
}

}  // namespace brightray

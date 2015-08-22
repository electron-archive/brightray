// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-CHROMIUM file.

#include "browser/browser_context.h"

#include "browser/brightray_paths.h"
#include "browser/inspectable_web_contents_impl.h"
#include "browser/network_delegate.h"
#include "browser/permission_manager.h"
#include "common/application_info.h"

#include "base/files/file_path.h"
#include "base/path_service.h"
#include "base/prefs/json_pref_store.h"
#include "base/prefs/pref_registry_simple.h"
#include "base/prefs/pref_service.h"
#include "base/prefs/pref_service_factory.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/resource_context.h"
#include "content/public/browser/storage_partition.h"
#include "net/ssl/client_cert_store.h"

#if defined(USE_NSS_CERTS)
#include "net/ssl/client_cert_store_nss.h"
#elif defined(OS_WIN)
#include "net/ssl/client_cert_store_win.h"
#elif defined(OS_MACOSX)
#include "net/ssl/client_cert_store_mac.h"
#endif

using content::BrowserThread;

namespace brightray {

namespace {

struct StoragePartitionDescriptor {
  StoragePartitionDescriptor(const base::FilePath& partition_path,
                            const bool in_memory)
      : partition_path_(partition_path),
        in_memory_(in_memory) {}

  bool operator<(const StoragePartitionDescriptor& rhs) const {
    if (partition_path_ != rhs.partition_path_)
      return partition_path_ < rhs.partition_path_;
    else if (in_memory_ != rhs.in_memory_)
      return in_memory_ < rhs.in_memory_;
    else
      return false;
  }

  const base::FilePath& partition_path_;
  const bool in_memory_;
};

void NotifyContextShuttingDownInIO(
    scoped_ptr<BrowserContext::URLRequestContextGetterVector> getters) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  for (auto& url_request_context_getter : *getters )
    url_request_context_getter->NotifyContextShuttingDown();
}

}  // namespace

class BrowserContext::ResourceContext : public content::ResourceContext {
 public:
  ResourceContext() : getter_(nullptr) {}

  void set_url_request_context_getter(URLRequestContextGetter* getter) {
    getter_ = getter;
  }

 private:
  net::HostResolver* GetHostResolver() override {
    return getter_->host_resolver();
  }

  net::URLRequestContext* GetRequestContext() override {
    return getter_->GetURLRequestContext();
  }

  scoped_ptr<net::ClientCertStore> CreateClientCertStore() override {
    #if defined(USE_NSS_CERTS)
      return scoped_ptr<net::ClientCertStore>(new net::ClientCertStoreNSS(
          net::ClientCertStoreNSS::PasswordDelegateFactory()));
    #elif defined(OS_WIN)
      return scoped_ptr<net::ClientCertStore>(new net::ClientCertStoreWin());
    #elif defined(OS_MACOSX)
      return scoped_ptr<net::ClientCertStore>(new net::ClientCertStoreMac());
    #elif defined(USE_OPENSSL)
      return scoped_ptr<net::ClientCertStore>();
    #endif
  }

  URLRequestContextGetter* getter_;
};

BrowserContext::BrowserContext() : resource_context_(new ResourceContext) {
}

void BrowserContext::Initialize() {
  if (!PathService::Get(DIR_USER_DATA, &path_)) {
    PathService::Get(DIR_APP_DATA, &path_);
    path_ = path_.Append(base::FilePath::FromUTF8Unsafe(GetApplicationName()));
    PathService::Override(DIR_USER_DATA, path_);
  }

  auto prefs_path = GetPath().Append(FILE_PATH_LITERAL("Preferences"));
  base::PrefServiceFactory prefs_factory;
  prefs_factory.SetUserPrefsFile(prefs_path,
      JsonPrefStore::GetTaskRunnerForFile(
          prefs_path, BrowserThread::GetBlockingPool()).get());

  auto registry = make_scoped_refptr(new PrefRegistrySimple);
  RegisterInternalPrefs(registry.get());
  RegisterPrefs(registry.get());

  prefs_ = prefs_factory.Create(registry.get());
}

BrowserContext::~BrowserContext() {
  BrowserThread::PostTask(BrowserThread::IO,
                          FROM_HERE,
                          base::Bind(&NotifyContextShuttingDownInIO,
                                     base::Passed(GetAllRequestContext())));
  BrowserThread::DeleteSoon(BrowserThread::IO,
                            FROM_HERE,
                            resource_context_.release());
}

void BrowserContext::RegisterInternalPrefs(PrefRegistrySimple* registry) {
  InspectableWebContentsImpl::RegisterPrefs(registry);
}

net::URLRequestContextGetter* BrowserContext::CreateRequestContext(
    NetLog* net_log,
    content::ProtocolHandlerMap* protocol_handlers,
    content::URLRequestInterceptorScopedVector protocol_interceptors) {
  DCHECK(!url_request_getter_.get());
  url_request_getter_ = URLRequestContextGetter::CreateMainRequestContext(
      this,
      net_log,
      GetPath(),
      BrowserThread::UnsafeGetMessageLoopForThread(BrowserThread::IO),
      BrowserThread::UnsafeGetMessageLoopForThread(BrowserThread::FILE),
      protocol_handlers,
      protocol_interceptors.Pass());
  resource_context_->set_url_request_context_getter(url_request_getter_.get());
  return url_request_getter_.get();
}

net::URLRequestContextGetter* BrowserContext::CreateRequestContextForStoragePartition(
    const base::FilePath& partition_path,
    bool in_memory,
    content::ProtocolHandlerMap* protocol_handlers,
    content::URLRequestInterceptorScopedVector protocol_interceptors) {
  CHECK(partition_path != GetPath());

  StoragePartitionDescriptor partition_descriptor(partition_path, in_memory);

  URLRequestContextGetter* context = URLRequestContextGetter::CreateIsolatedRequestContext(
      this,
      make_scoped_refptr(GetRequestContext()),
      partition_path,
      in_memory,
      protocol_handlers,
      protocol_interceptors.Pass());
  url_request_context_getter_map_[partition_descriptor] = context;
  return context;
}

net::NetworkDelegate* BrowserContext::CreateNetworkDelegate() {
  return new NetworkDelegate;
}

base::FilePath BrowserContext::GetPath() const {
  return path_;
}

scoped_ptr<BrowserContext::URLRequestContextGetterVector>
BrowserContext::GetAllRequestContext() {
  scoped_ptr<URLRequestContextGetterVector> getters(
      new URLRequestContextGetterVector);

  // isolated request context.
  URLRequestContextGetterMap::iterator iter =
      url_request_context_getter_map_.begin();
  for (; iter != url_request_context_getter_map_.end(); ++iter)
    getters->push_back(iter->second);

  // main request context.
  getters->push_back(url_request_getter_);

  return getters.Pass();
}

scoped_ptr<content::ZoomLevelDelegate> BrowserContext::CreateZoomLevelDelegate(
    const base::FilePath& partition_path) {
  return scoped_ptr<content::ZoomLevelDelegate>();
}

bool BrowserContext::IsOffTheRecord() const {
  return false;
}

net::URLRequestContextGetter* BrowserContext::GetRequestContext() {
  return GetDefaultStoragePartition(this)->GetURLRequestContext();
}

net::URLRequestContextGetter* BrowserContext::GetRequestContextForRenderProcess(
    int renderer_child_id) {
  return GetRequestContext();
}

net::URLRequestContextGetter* BrowserContext::GetMediaRequestContext() {
  return GetRequestContext();
}

net::URLRequestContextGetter*
    BrowserContext::GetMediaRequestContextForRenderProcess(
        int renderer_child_id) {
  return GetRequestContext();
}

net::URLRequestContextGetter*
    BrowserContext::GetMediaRequestContextForStoragePartition(
        const base::FilePath& partition_path,
        bool in_memory) {
  // Since we have already created URLRequestContext to be used for the partition,
  // this can be NULL.
  return nullptr;
}

content::ResourceContext* BrowserContext::GetResourceContext() {
  return resource_context_.get();
}

content::DownloadManagerDelegate* BrowserContext::GetDownloadManagerDelegate() {
  return nullptr;
}

content::BrowserPluginGuestManager* BrowserContext::GetGuestManager() {
  return nullptr;
}

storage::SpecialStoragePolicy* BrowserContext::GetSpecialStoragePolicy() {
  return nullptr;
}

content::PushMessagingService* BrowserContext::GetPushMessagingService() {
  return nullptr;
}

content::SSLHostStateDelegate* BrowserContext::GetSSLHostStateDelegate() {
  return nullptr;
}

content::PermissionManager* BrowserContext::GetPermissionManager() {
  if (!permission_manager_.get())
    permission_manager_.reset(new PermissionManager);
  return permission_manager_.get();
}

}  // namespace brightray

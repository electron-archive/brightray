// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-CHROMIUM file.

#ifndef BRIGHTRAY_BROWSER_BROWSER_CONTEXT_H_
#define BRIGHTRAY_BROWSER_BROWSER_CONTEXT_H_

#include "browser/permission_manager.h"
#include "browser/url_request_context_getter.h"

#include "content/public/browser/browser_context.h"

class PrefRegistrySimple;
class PrefService;

namespace brightray {

class PermissionManager;

class BrowserContext : public content::BrowserContext,
                       public brightray::URLRequestContextGetter::Delegate {
 public:
  using URLRequestContextGetterVector =
      std::vector<scoped_refptr<URLRequestContextGetter>>;

  BrowserContext();
  ~BrowserContext();

  virtual void Initialize();

  // content::BrowserContext:
  scoped_ptr<content::ZoomLevelDelegate> CreateZoomLevelDelegate(
      const base::FilePath& partition_path) override;
  bool IsOffTheRecord() const override;
  net::URLRequestContextGetter* GetRequestContext() override;
  net::URLRequestContextGetter* GetRequestContextForRenderProcess(
      int renderer_child_id) override;
  net::URLRequestContextGetter* GetMediaRequestContext() override;
  net::URLRequestContextGetter* GetMediaRequestContextForRenderProcess(
      int renderer_child_id) override;
  net::URLRequestContextGetter* GetMediaRequestContextForStoragePartition(
      const base::FilePath& partition_path, bool in_memory) override;
  content::ResourceContext* GetResourceContext() override;
  content::DownloadManagerDelegate* GetDownloadManagerDelegate() override;
  content::BrowserPluginGuestManager* GetGuestManager() override;
  storage::SpecialStoragePolicy* GetSpecialStoragePolicy() override;
  content::PushMessagingService* GetPushMessagingService() override;
  content::SSLHostStateDelegate* GetSSLHostStateDelegate() override;
  content::PermissionManager* GetPermissionManager() override;

  net::URLRequestContextGetter* CreateRequestContext(
      NetLog* net_log,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector protocol_interceptors);
  net::URLRequestContextGetter* CreateRequestContextForStoragePartition(
      const base::FilePath& partition_path,
      bool in_memory,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector protocol_interceptors);

  net::URLRequestContextGetter* url_request_context_getter() const {
    return url_request_getter_.get();
  }

  PrefService* prefs() { return prefs_.get(); }

 protected:
  // Descriptor to map partition info (path, in_memory) => URLRequestContextGetter.
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

  // Subclasses should override this to register custom preferences.
  virtual void RegisterPrefs(PrefRegistrySimple* pref_registry) {}

  // URLRequestContextGetter::Delegate:
  net::NetworkDelegate* CreateNetworkDelegate() override;

  base::FilePath GetPath() const override;

  // Returns all the URLRequestContextGetter created for this browser context.
  scoped_ptr<URLRequestContextGetterVector> GetAllRequestContext();

 private:
  using URLRequestContextGetterMap = std::map<StoragePartitionDescriptor,
                                              scoped_refptr<URLRequestContextGetter>>;
  class ResourceContext;

  void RegisterInternalPrefs(PrefRegistrySimple* pref_registry);

  base::FilePath path_;
  scoped_ptr<ResourceContext> resource_context_;
  scoped_refptr<URLRequestContextGetter> url_request_getter_;
  scoped_ptr<PrefService> prefs_;
  scoped_ptr<PermissionManager> permission_manager_;
  mutable URLRequestContextGetterMap url_request_context_getter_map_;

  DISALLOW_COPY_AND_ASSIGN(BrowserContext);
};

}  // namespace brightray

#endif

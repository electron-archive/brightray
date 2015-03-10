// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-CHROMIUM file.

#ifndef BRIGHTRAY_BROWSER_BROWSER_CLIENT_H_
#define BRIGHTRAY_BROWSER_BROWSER_CLIENT_H_

#include "content/public/browser/content_browser_client.h"
#include "content/public/common/resource_type.h"

namespace brightray {

class BrowserContext;
class BrowserMainParts;
class NotificationPresenter;

class BrowserClient : public content::ContentBrowserClient {
 public:
  static BrowserClient* Get();

  BrowserClient();
  ~BrowserClient();

  BrowserContext* browser_context();
  BrowserMainParts* browser_main_parts() { return browser_main_parts_; }
  NotificationPresenter* notification_presenter();

 protected:
  // Subclasses should override this to provide their own BrowserMainParts
  // implementation. The lifetime of the returned instance is managed by the
  // caller.
  virtual BrowserMainParts* OverrideCreateBrowserMainParts(
      const content::MainFunctionParams&);

  // Subclasses that override this (e.g., to provide their own protocol
  // handlers) should call this implementation after doing their own work.
  net::URLRequestContextGetter* CreateRequestContext(
      content::BrowserContext* browser_context,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector protocol_interceptors) override;

 private:
  content::BrowserMainParts* CreateBrowserMainParts(
      const content::MainFunctionParams&) override;
  void ShowDesktopNotification(
      const content::ShowDesktopNotificationHostMsgParams& params,
      content::BrowserContext* browser_context,
      int render_process_id,
      scoped_ptr<content::DesktopNotificationDelegate> delegate,
      base::Closure* cancel_callback) override;
  content::MediaObserver* GetMediaObserver() override;
  void GetAdditionalAllowedSchemesForFileSystem(
      std::vector<std::string>* additional_schemes) override;
  base::FilePath GetDefaultDownloadDirectory() override;
  content::DevToolsManagerDelegate* GetDevToolsManagerDelegate() override;
  void AllowCertificateError(int render_process_id,
                             int render_frame_id,
                             int cert_error,
                             const net::SSLInfo& ssl_info,
                             const GURL& request_url,
                             content::ResourceType resource_type,
                             bool override,
                             bool strict_enforcement,
                             bool expired_previous_decision,
                             const base::Callback<void(bool)>& callback,
                             content::CertificateRequestResultType* result) override;

  BrowserMainParts* browser_main_parts_;
  scoped_ptr<NotificationPresenter> notification_presenter_;

  DISALLOW_COPY_AND_ASSIGN(BrowserClient);
};

}  // namespace brightray

#endif

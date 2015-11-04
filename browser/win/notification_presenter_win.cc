// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Copyright (c) 2013 Patrick Reynolds <piki@github.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-CHROMIUM file.

#include "browser/win/notification_presenter_win.h"

#include "base/bind.h"
#include "base/logging.h"
#include "base/files/file_enumerator.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "content/public/browser/desktop_notification_delegate.h"
#include "content/public/common/platform_notification_data.h"
#include "common/application_info.h"
#include <stdlib.h>
#include <vector>
#include "third_party/skia/include/core/SkBitmap.h"
#include "base/win/windows_version.h"

namespace brightray {

namespace {

}  // namespace

// static
NotificationPresenter* NotificationPresenter::Create() {
  return new NotificationPresenterWin;
}

NotificationPresenterWin::NotificationPresenterWin() {
}

NotificationPresenterWin::~NotificationPresenterWin() {
}

void NotificationPresenterWin::ShowNotification(
  // https://msdn.microsoft.com/en-us/library/ee330740(v=VS.85).aspx
  // To display a notification, you must have an icon in the notification area. 
  // In certain cases, such as Microsoft Communicator or battery level, that icon will already be present. 
  // In many other cases, however, you will add an icon to the notification area only as long as is needed to show the notification. 
  // In either case, this is accomplished using the Shell_NotifyIcon function.

    const content::PlatformNotificationData& data,
    const SkBitmap& icon,
    scoped_ptr<content::DesktopNotificationDelegate> delegate_ptr,
    base::Closure* cancel_callback) {

    UINT icon_id_ = 1;
    HWND window_ = CreateWindow(0, 0, WS_POPUP, 0, 0, 0, 0, 0, 0, 0, 0);

    NOTIFYICONDATA icon_data;

    memset(&icon_data, 0, sizeof(NOTIFYICONDATA));
    icon_data.cbSize = sizeof(NOTIFYICONDATA);
    icon_data.hWnd = window_;
    icon_data.uID = icon_id_;
    icon_data.uFlags |= NIF_INFO;
    icon_data.dwInfoFlags = NIIF_INFO;
    
    wcscpy_s(icon_data.szInfoTitle, data.title.c_str());
    wcscpy_s(icon_data.szInfo, data.body.c_str());
    icon_data.uTimeout = 0;

  content::DesktopNotificationDelegate* delegate = delegate_ptr.release();
  delegate->NotificationDisplayed();
  
  logging::LogMessage("CONSOLE", 0, 0).stream() << "Test";
  LOG(ERROR) << "blah";
    /*
    base::win::Version win_version = base::win::GetVersion();
    if (!icon.IsEmpty() && win_version != base::win::VERSION_PRE_XP) {
      balloon_icon_.Set(IconUtil::CreateHICONFromSkBitmap(icon.AsBitmap()));
      icon_data.hBalloonIcon = balloon_icon_.Get();
      icon_data.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON;
    }*/

    Shell_NotifyIcon(NIM_MODIFY, &icon_data);
}

void NotificationPresenterWin::CancelNotification() {
}

void NotificationPresenterWin::DeleteNotification() {
}

}  // namespace brightray

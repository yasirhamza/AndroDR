package com.androdr.fixture.notiflistener
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
class Svc : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification?) {}
    override fun onNotificationRemoved(sbn: StatusBarNotification?) {}
}

package com.androdr.fixture.smsnotif
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
class Svc : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification?) {}
    override fun onNotificationRemoved(sbn: StatusBarNotification?) {}
}

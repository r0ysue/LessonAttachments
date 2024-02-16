/*
 * Copyright (C) 2017 Peter Gregus for GravityBox Project (C3C076@xda)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ceco.nougat.gravitybox.quicksettings;

import java.util.List;

import com.ceco.nougat.gravitybox.BroadcastSubReceiver;
import com.ceco.nougat.gravitybox.GravityBox;
import com.ceco.nougat.gravitybox.GravityBoxSettings;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.service.notification.StatusBarNotification;
import android.view.MotionEvent;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class QsQuickPulldownHandler implements BroadcastSubReceiver {
    private static final String TAG = "GB:QsQuickPulldownHandler";
    private static final boolean DEBUG = false;

    private static final int MODE_OFF = 0;
    private static final int MODE_RIGHT = 1;
    private static final int MODE_LEFT = 2;
    //private static final int MODE_BOTH = 3;

    private static final int MODE_AUTO_OFF = 0;
    private static final int MODE_AUTO_NONE = 1;
    //private static final int MODE_AUTO_ONGOING = 2;

    private static final String CLASS_NOTIF_PANEL = 
            "com.android.systemui.statusbar.phone.NotificationPanelView";

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    private Context mContext;
    private XSharedPreferences mPrefs;
    private int mMode;
    private int mModeAuto;
    private int mSizePercent;
    private Object mNotificationData;

    public QsQuickPulldownHandler(Context context, XSharedPreferences prefs, 
            QsTileEventDistributor eventDistributor) {
        mContext = context;
        mPrefs = prefs;
        eventDistributor.registerBroadcastSubReceiver(this);

        initPreferences();
        createHooks();
        if (DEBUG) log("Quick pulldown handler created");
    }

    private void initPreferences() {
        mMode = Integer.valueOf(mPrefs.getString(
                GravityBoxSettings.PREF_KEY_QUICK_PULLDOWN, "0"));
        mSizePercent = mPrefs.getInt(GravityBoxSettings.PREF_KEY_QUICK_PULLDOWN_SIZE, 15);
        mModeAuto = Integer.valueOf(mPrefs.getString(
                GravityBoxSettings.PREF_KEY_QUICK_SETTINGS_AUTOSWITCH, "0"));
        if (DEBUG) log("initPreferences: mode=" + mMode + "; size%=" + mSizePercent +
                "; modeAuto=" + mModeAuto);
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_QUICKSETTINGS_CHANGED)) {
            if (intent.hasExtra(GravityBoxSettings.EXTRA_QUICK_PULLDOWN)) {
                mMode = intent.getIntExtra(GravityBoxSettings.EXTRA_QUICK_PULLDOWN, MODE_OFF);
                if (DEBUG) log("onBroadcastReceived: mode=" + mMode);
            }
            if (intent.hasExtra(GravityBoxSettings.EXTRA_QUICK_PULLDOWN_SIZE)) {
                mSizePercent = intent.getIntExtra(GravityBoxSettings.EXTRA_QUICK_PULLDOWN_SIZE, 15);
                if (DEBUG) log("onBroadcastReceived: size%=" + mSizePercent);
            }
            if (intent.hasExtra(GravityBoxSettings.EXTRA_QS_AUTOSWITCH)) {
                mModeAuto = intent.getIntExtra(GravityBoxSettings.EXTRA_QS_AUTOSWITCH, MODE_AUTO_OFF);
                if (DEBUG) log("onBroadcastReceived: modeAuto=" + mModeAuto);
            }
        }
    }

    public static String getQsExpandFieldName() {
        switch (Build.VERSION.SDK_INT) {
            default: return "mQsExpandImmediate";
        }
    }

    private void createHooks() {
        try {
            ClassLoader cl = mContext.getClassLoader();

            final String qsExpandFieldName = getQsExpandFieldName();

            XposedHelpers.findAndHookMethod(CLASS_NOTIF_PANEL, cl,
                    "onTouchEvent", MotionEvent.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    final Object o = param.thisObject;
                    if ((mMode == MODE_OFF && mModeAuto == MODE_AUTO_OFF) ||
                        XposedHelpers.getBooleanField(o, "mBlockTouches") ||
                        XposedHelpers.getBooleanField(o, "mOnlyAffordanceInThisMotion") ||
                        XposedHelpers.getBooleanField(o, qsExpandFieldName) ||
                        isQsContainerCustomizing(o) ||
                        (!XposedHelpers.getBooleanField(o, qsExpandFieldName) && 
                                XposedHelpers.getBooleanField(o, "mQsTracking") &&
                                !XposedHelpers.getBooleanField(o, "mConflictingQsExpansionGesture"))) {
                        return;
                    }

                    final MotionEvent event = (MotionEvent) param.args[0];
                    boolean oneFingerQsOverride = event.getActionMasked() == MotionEvent.ACTION_DOWN
                            && shouldQuickSettingsIntercept(o, event.getX(), event.getY(), -1)
                            && event.getY(event.getActionIndex()) < 
                                XposedHelpers.getIntField(o, "mStatusBarMinHeight");
                    if (oneFingerQsOverride) {
                        XposedHelpers.setBooleanField(o, qsExpandFieldName, true);
                        XposedHelpers.callMethod(o, "requestPanelHeightUpdate");
                        XposedHelpers.callMethod(o, "setListening", true);
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private boolean shouldQuickSettingsIntercept(Object o, float x, float y, float yDiff) {
        if (!XposedHelpers.getBooleanField(o, "mQsExpansionEnabled")) {
            return false;
        }

        boolean showQsOverride = false;

        // quick
        if (mMode != MODE_OFF) {
            final int w = (int) XposedHelpers.callMethod(o, "getMeasuredWidth");
            float region = (w * (mSizePercent/100f));
            showQsOverride |= (mMode == MODE_RIGHT) ? 
                    (x > w - region) : (mMode == MODE_LEFT) ? (x < region) :
                        (x > w - region) || (x < region);
        }

        // auto
        if (mModeAuto != MODE_AUTO_OFF && !showQsOverride) {
            showQsOverride |= (mModeAuto == MODE_AUTO_NONE) ?
                    !hasNotifications(o) : !hasClearableNotifications(o);
        }

        return showQsOverride;
    }

    private boolean hasNotifications(Object o) {
        try {
            if (mNotificationData == null) {
                mNotificationData = XposedHelpers.getObjectField(
                        XposedHelpers.getObjectField(o, "mStatusBar"), "mNotificationData");
            }
            List<?> list = (List<?>)XposedHelpers.callMethod(mNotificationData, "getActiveNotifications");
            return list.size() > 0;
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return true;
        }
    }

    private boolean hasClearableNotifications(Object o) {
        try {
            if (mNotificationData == null) {
                mNotificationData = XposedHelpers.getObjectField(
                        XposedHelpers.getObjectField(o, "mStatusBar"), "mNotificationData");
            }
            List<?> list = (List<?>)XposedHelpers.callMethod(mNotificationData, "getActiveNotifications");
            boolean hasClearableNotifications = false;
            for (Object entry : list) {
                StatusBarNotification sbn = (StatusBarNotification) XposedHelpers.getObjectField(entry, "notification");
                hasClearableNotifications |= sbn.isClearable();
            }
            return hasClearableNotifications;
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return true;
        }
    }

    private boolean isQsContainerCustomizing(Object panel) {
        try {
            Object container = XposedHelpers.getObjectField(panel, "mQsContainer");
            return (boolean) XposedHelpers.callMethod(container, "isCustomizing");
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error in isQsContainerCustomizing: ", t);
            return false;
        }
    }
}

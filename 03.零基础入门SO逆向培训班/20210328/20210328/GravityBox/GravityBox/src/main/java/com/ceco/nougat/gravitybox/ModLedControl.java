/*
 * Copyright (C) 2018 Peter Gregus for GravityBox Project (C3C076@xda)
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

package com.ceco.nougat.gravitybox;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.ceco.nougat.gravitybox.ModStatusBar.StatusBarState;
import com.ceco.nougat.gravitybox.ledcontrol.LedSettings;
import com.ceco.nougat.gravitybox.ledcontrol.QuietHours;
import com.ceco.nougat.gravitybox.ledcontrol.QuietHoursActivity;
import com.ceco.nougat.gravitybox.ledcontrol.LedSettings.ActiveScreenMode;
import com.ceco.nougat.gravitybox.ledcontrol.LedSettings.HeadsUpMode;
import com.ceco.nougat.gravitybox.ledcontrol.LedSettings.LedMode;
import com.ceco.nougat.gravitybox.ledcontrol.LedSettings.Visibility;
import com.ceco.nougat.gravitybox.ledcontrol.LedSettings.VisibilityLs;

import android.app.ActivityManager;
import android.app.KeyguardManager;
import android.app.Notification;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.media.AudioManager;
import android.os.Binder;
import android.os.Handler;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.Settings;
import android.service.notification.StatusBarNotification;
import android.telephony.TelephonyManager;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class ModLedControl {
    private static final String TAG = "GB:ModLedControl";
    public static final boolean DEBUG = false;
    private static final String CLASS_NOTIFICATION_MANAGER_SERVICE = "com.android.server.notification.NotificationManagerService";
    private static final String CLASS_VIBRATOR_SERVICE = "com.android.server.VibratorService";
    private static final String CLASS_BASE_STATUSBAR = "com.android.systemui.statusbar.BaseStatusBar";
    private static final String CLASS_PHONE_STATUSBAR = "com.android.systemui.statusbar.phone.PhoneStatusBar";
    private static final String CLASS_NOTIF_DATA = "com.android.systemui.statusbar.NotificationData";
    private static final String CLASS_NOTIF_DATA_ENTRY = "com.android.systemui.statusbar.NotificationData.Entry";
    private static final String CLASS_NOTIFICATION_RECORD = "com.android.server.notification.NotificationRecord";
    private static final String CLASS_HEADS_UP_MANAGER_ENTRY = "com.android.systemui.statusbar.policy.HeadsUpManager.HeadsUpEntry";
    public static final String PACKAGE_NAME_SYSTEMUI = "com.android.systemui";

    private static final String NOTIF_EXTRA_HEADS_UP_MODE = "gbHeadsUpMode";
    private static final String NOTIF_EXTRA_HEADS_UP_TIMEOUT = "gbHeadsUpTimeout";
    private static final String NOTIF_EXTRA_ACTIVE_SCREEN = "gbActiveScreen";
    private static final String NOTIF_EXTRA_ACTIVE_SCREEN_MODE = "gbActiveScreenMode";
    private static final String NOTIF_EXTRA_ACTIVE_SCREEN_POCKET_MODE = "gbActiveScreenPocketMode";
    public static final String NOTIF_EXTRA_PROGRESS_TRACKING = "gbProgressTracking";
    public static final String NOTIF_EXTRA_VISIBILITY_LS = "gbVisibilityLs";
    public static final String NOTIF_EXTRA_HIDE_PERSISTENT = "gbHidePersistent";

    private  static final String SETTING_ZEN_MODE = "zen_mode";

    public static final String ACTION_CLEAR_NOTIFICATIONS = "gravitybox.intent.action.CLEAR_NOTIFICATIONS";

    private static XSharedPreferences mUncPrefs;
    private static XSharedPreferences mQhPrefs;
    private static Context mContext;
    private static PowerManager mPm;
    private static SensorManager mSm;
    private static KeyguardManager mKm;
    private static Sensor mProxSensor;
    private static QuietHours mQuietHours;
    private static Map<String, Long> mNotifTimestamps = new HashMap<String, Long>();
    private static Object mNotifManagerService;
    private static boolean mProximityWakeUpEnabled;
    private static boolean mScreenOnDueToActiveScreen;
    private static AudioManager mAudioManager;
    private static Integer mDefaultNotificationLedColor;
    private static Integer mDefaultNotificationLedOn;
    private static Integer mDefaultNotificationLedOff;
    private static TelephonyManager mTelephonyManager;
    private static boolean mActiveScreenEnabled;

    private static SensorEventListener mProxSensorEventListener = new SensorEventListener() {
        @Override
        public void onSensorChanged(SensorEvent event) {
            try {
                final boolean screenCovered = 
                        event.values[0] != mProxSensor.getMaximumRange(); 
                if (DEBUG) log("mProxSensorEventListener: " + event.values[0] +
                        "; screenCovered=" + screenCovered);
                if (!screenCovered) {
                    performActiveScreen();
                }
            } catch (Throwable t) {
                GravityBox.log(TAG, t);
            } finally {
                try { 
                    mSm.unregisterListener(this, mProxSensor); 
                } catch (Throwable t) {
                    // should never happen
                }
            }
        }
        @Override
        public void onAccuracyChanged(Sensor sensor, int accuracy) { }
    };

    private static BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            final String action = intent.getAction();
            if (action.equals(LedSettings.ACTION_UNC_SETTINGS_CHANGED)) {
                mUncPrefs.reload();
                updateActiveScreenFeature();
            } else if (action.equals(QuietHoursActivity.ACTION_QUIET_HOURS_CHANGED)) {
                mQhPrefs.reload();
                mQuietHours = new QuietHours(mQhPrefs);
            } else if (action.equals(Intent.ACTION_USER_PRESENT)) {
                if (DEBUG) log("User present");
                mScreenOnDueToActiveScreen = false;
            } else if (action.equals(Intent.ACTION_SCREEN_OFF)) {
                mScreenOnDueToActiveScreen = false;
            } else if (action.equals(ACTION_CLEAR_NOTIFICATIONS)) {
                clearNotifications();
            } else if (action.equals(GravityBoxSettings.ACTION_PREF_POWER_CHANGED) &&
                    intent.hasExtra(GravityBoxSettings.EXTRA_POWER_PROXIMITY_WAKE)) {
                mProximityWakeUpEnabled = intent.getBooleanExtra(
                        GravityBoxSettings.EXTRA_POWER_PROXIMITY_WAKE, false);
            }
        }
    };

    public static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    public static void initAndroid(final XSharedPreferences mainPrefs,
            final XSharedPreferences uncPrefs, final XSharedPreferences qhPrefs,
            final ClassLoader classLoader) {
        mUncPrefs = uncPrefs;
        mQhPrefs = qhPrefs;
        mQuietHours = new QuietHours(mQhPrefs);

        mProximityWakeUpEnabled = mainPrefs.getBoolean(GravityBoxSettings.PREF_KEY_POWER_PROXIMITY_WAKE, false);

        try {
            final Class<?> nmsClass = XposedHelpers.findClass(CLASS_NOTIFICATION_MANAGER_SERVICE, classLoader);
            XposedBridge.hookAllConstructors(nmsClass, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(final MethodHookParam param) throws Throwable {
                    if (mNotifManagerService == null) {
                        mNotifManagerService = param.thisObject;
                        mContext = (Context) XposedHelpers.callMethod(param.thisObject, "getContext");

                        IntentFilter intentFilter = new IntentFilter();
                        intentFilter.addAction(LedSettings.ACTION_UNC_SETTINGS_CHANGED);
                        intentFilter.addAction(Intent.ACTION_USER_PRESENT);
                        intentFilter.addAction(QuietHoursActivity.ACTION_QUIET_HOURS_CHANGED);
                        intentFilter.addAction(Intent.ACTION_SCREEN_OFF);
                        intentFilter.addAction(ACTION_CLEAR_NOTIFICATIONS);
                        intentFilter.addAction(GravityBoxSettings.ACTION_PREF_POWER_CHANGED);
                        mContext.registerReceiver(mBroadcastReceiver, intentFilter);

                        updateUncTrialCountdown();
                        updateActiveScreenFeature();
                        hookNotificationDelegate();

                        if (DEBUG) log("Notification manager service initialized");
                    }
                }
            });

            XposedHelpers.findAndHookMethod(CLASS_NOTIFICATION_MANAGER_SERVICE, classLoader,
                    "enqueueNotificationInternal", String.class, String.class,
                    int.class, int.class, String.class, 
                    int.class, Notification.class, int[].class, int.class, notifyHook);

            XposedHelpers.findAndHookMethod(CLASS_NOTIFICATION_MANAGER_SERVICE, classLoader,
                    "applyZenModeLocked", CLASS_NOTIFICATION_RECORD, applyZenModeHook);

            XposedHelpers.findAndHookMethod(CLASS_NOTIFICATION_MANAGER_SERVICE, classLoader,
                    "updateLightsLocked", updateLightsLockedHook);

            XposedBridge.hookAllMethods(XposedHelpers.findClass(CLASS_VIBRATOR_SERVICE, classLoader),
                    "startVibrationLocked", startVibrationHook);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static void updateUncTrialCountdown() {
        try {
            final ContentResolver cr = mContext.getContentResolver();
            int uncTrialCountdown = Settings.System.getInt(cr,
                    SystemPropertyProvider.SETTING_UNC_TRIAL_COUNTDOWN, -1);
            if (uncTrialCountdown == -1) {
                Settings.System.putInt(cr,
                        SystemPropertyProvider.SETTING_UNC_TRIAL_COUNTDOWN, 50);
            } else {
                if (--uncTrialCountdown >= 0) {
                    Settings.System.putInt(cr,
                            SystemPropertyProvider.SETTING_UNC_TRIAL_COUNTDOWN, uncTrialCountdown);
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static XC_MethodHook notifyHook = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
            try {
                if (mUncPrefs.getBoolean(LedSettings.PREF_KEY_LOCKED, false)) {
                    if (DEBUG) log("Ultimate notification control feature locked.");
                    return;
                }

                Notification n = (Notification) param.args[6];

                if (Utils.isVerneeDevice()) {
                    XposedHelpers.setIntField(param.thisObject, "mDefaultNotificationColor",
                            ((n.defaults & Notification.DEFAULT_LIGHTS) != 0 ?
                                    getDefaultNotificationLedColor() : n.ledARGB));
                    XposedHelpers.setIntField(param.thisObject, "mDefaultNotificationLedOn",
                            ((n.defaults & Notification.DEFAULT_LIGHTS) != 0 ?
                                    getDefaultNotificationLedOn() : n.ledOnMS));
                    XposedHelpers.setIntField(param.thisObject, "mDefaultNotificationLedOff",
                            ((n.defaults & Notification.DEFAULT_LIGHTS) != 0 ?
                                    getDefaultNotificationLedOff() : n.ledOffMS));
                }

                Object oldRecord = getOldNotificationRecord(param.args[0], param.args[4],
                        param.args[5], param.args[8]);
                Notification oldN = getNotificationFromRecord(oldRecord);
                final String pkgName = (String) param.args[0];
                final boolean userPresent = isUserPresent();

                LedSettings ls;
                if (n.extras.containsKey("gbUncPreviewNotification")) {
                    ls = LedSettings.deserialize("preview", n.extras.getStringArrayList(
                            LedSettings.EXTRA_UNC_PACKAGE_SETTINGS));
                    if (DEBUG) log("Received UNC preview notification");
                } else {
                    ls = LedSettings.deserialize(mUncPrefs.getStringSet(pkgName, null));
                    if (!ls.getEnabled()) {
                        // use default settings in case they are active
                        ls = LedSettings.deserialize(mUncPrefs.getStringSet("default", null));
                        if (!ls.getEnabled() && !mQuietHours.quietHoursActive(ls, n, userPresent)) {
                            return;
                        }
                    }
                    if (DEBUG) log(pkgName + ": " + ls.toString());
                }

                final boolean qhActive = mQuietHours.quietHoursActive(ls, n, userPresent);
                final boolean qhActiveIncludingLed = qhActive && mQuietHours.shouldMuteLed();
                final boolean qhActiveIncludingVibe = qhActive && (
                        (mQuietHours.mode != QuietHours.Mode.WEAR && mQuietHours.shouldMuteVibe()) ||
                        (mQuietHours.mode == QuietHours.Mode.WEAR && userPresent));
                final boolean qhActiveIncludingActiveScreen = qhActive &&
                        !mUncPrefs.getBoolean(LedSettings.PREF_KEY_ACTIVE_SCREEN_IGNORE_QUIET_HOURS, false);

                if (ls.getEnabled()) {
                    n.extras.putBoolean(NOTIF_EXTRA_PROGRESS_TRACKING, ls.getProgressTracking());
                    n.extras.putString(NOTIF_EXTRA_VISIBILITY_LS, ls.getVisibilityLs().toString());
                    n.extras.putBoolean(NOTIF_EXTRA_HIDE_PERSISTENT, ls.getHidePersistent());
                }

                // whether to ignore ongoing notification
                boolean isOngoing = ((n.flags & Notification.FLAG_ONGOING_EVENT) != 0 || 
                        (n.flags & Notification.FLAG_FOREGROUND_SERVICE) != 0);
                // additional check if old notification had a foreground service flag set since it seems not to be propagated
                // for updated notifications (until Notification gets processed by WorkerHandler which is too late for us)
                if (!isOngoing && oldN != null) {
                    isOngoing = (oldN.flags & Notification.FLAG_FOREGROUND_SERVICE) != 0;
                    if (DEBUG) log("Old notification foreground service check: isOngoing=" + isOngoing);
                }
                if (isOngoing && !ls.getOngoing() && !qhActive) {
                    if (DEBUG) log("Ongoing led control disabled. Ignoring.");
                    return;
                }

                // lights
                if (qhActiveIncludingLed || 
                        (ls.getEnabled() && !(isOngoing && !ls.getOngoing()) &&
                            (ls.getLedMode() == LedMode.OFF ||
                             currentZenModeDisallowsLed(ls.getLedDnd()) ||
                             shouldIgnoreUpdatedNotificationLight(oldRecord, ls.getLedIgnoreUpdate())))) {
                    n.defaults &= ~Notification.DEFAULT_LIGHTS;
                    n.flags &= ~Notification.FLAG_SHOW_LIGHTS;
                } else if (ls.getEnabled() && ls.getLedMode() == LedMode.OVERRIDE &&
                        !(isOngoing && !ls.getOngoing())) {
                    n.flags |= Notification.FLAG_SHOW_LIGHTS;
                    if (Utils.isVerneeDevice()) {
                        n.defaults |= Notification.DEFAULT_LIGHTS;
                        XposedHelpers.setIntField(param.thisObject,
                                "mDefaultNotificationColor", ls.getColor());
                        XposedHelpers.setIntField(param.thisObject,
                                "mDefaultNotificationLedOn", ls.getLedOnMs());
                        XposedHelpers.setIntField(param.thisObject,
                                "mDefaultNotificationLedOff", ls.getLedOffMs());
                    } else {
                        n.defaults &= ~Notification.DEFAULT_LIGHTS;
                        n.ledOnMS = ls.getLedOnMs();
                        n.ledOffMS = ls.getLedOffMs();
                        n.ledARGB = ls.getColor();
                    }
                }

                // vibration
                if (qhActiveIncludingVibe) {
                    n.defaults &= ~Notification.DEFAULT_VIBRATE;
                    n.vibrate = null;
                } else if (ls.getEnabled() && !(isOngoing && !ls.getOngoing())) {
                    if (ls.getVibrateOverride() && ls.getVibratePattern() != null &&
                            ((n.defaults & Notification.DEFAULT_VIBRATE) != 0 || 
                             n.vibrate != null || !ls.getVibrateReplace())) {
                        n.defaults &= ~Notification.DEFAULT_VIBRATE;
                        n.vibrate = ls.getVibratePattern();
                    }
                }

                // sound
                if (qhActive || (ls.getEnabled() && 
                        ls.getSoundToVibrateDisabled() && isRingerModeVibrate())) {
                    n.defaults &= ~Notification.DEFAULT_SOUND;
                    n.sound = null;
                    n.flags &= ~Notification.FLAG_INSISTENT;
                } else {
                    if (ls.getSoundOverride() &&
                        ((n.defaults & Notification.DEFAULT_SOUND) != 0 ||
                          n.sound != null || !ls.getSoundReplace())) {
                        n.defaults &= ~Notification.DEFAULT_SOUND;
                        n.sound = ls.getSoundUri();
                    }
                    if (ls.getSoundOnlyOnce()) {
                        if (ls.getSoundOnlyOnceTimeout() > 0) {
                            if (mNotifTimestamps.containsKey(pkgName)) {
                                long delta = System.currentTimeMillis() - mNotifTimestamps.get(pkgName);
                                if (delta > 500 &&  delta < ls.getSoundOnlyOnceTimeout()) {
                                    n.defaults &= ~Notification.DEFAULT_SOUND;
                                    n.defaults &= ~Notification.DEFAULT_VIBRATE;
                                    n.sound = null;
                                    n.vibrate = null;
                                    n.flags &= ~Notification.FLAG_ONLY_ALERT_ONCE;
                                } else {
                                    mNotifTimestamps.put(pkgName, System.currentTimeMillis());
                                }
                            } else {
                                mNotifTimestamps.put(pkgName, System.currentTimeMillis());
                            }
                        } else {
                            n.flags |= Notification.FLAG_ONLY_ALERT_ONCE;
                        }
                    } else {
                        n.flags &= ~Notification.FLAG_ONLY_ALERT_ONCE;
                    }
                    if (ls.getInsistent()) {
                        n.flags |= Notification.FLAG_INSISTENT;
                    } else {
                        n.flags &= ~Notification.FLAG_INSISTENT;
                    }
                }

                if (ls.getEnabled()) {
                    // heads up mode
                    n.extras.putString(NOTIF_EXTRA_HEADS_UP_MODE, ls.getHeadsUpMode().toString());
                    if (ls.getHeadsUpMode() != HeadsUpMode.OFF) {
                        n.extras.putInt(NOTIF_EXTRA_HEADS_UP_TIMEOUT,
                                ls.getHeadsUpTimeout());
                    }
                    // active screen mode
                    if (mActiveScreenEnabled &&
                            ls.getActiveScreenMode() != ActiveScreenMode.DISABLED && 
                            !(ls.getActiveScreenIgnoreUpdate() && oldN != null) &&
                            n.priority > Notification.PRIORITY_MIN &&
                            ls.getVisibilityLs() != VisibilityLs.CLEARABLE &&
                            ls.getVisibilityLs() != VisibilityLs.ALL &&
                            !qhActiveIncludingActiveScreen && !isOngoing &&
                            !userPresent) {
                        n.extras.putBoolean(NOTIF_EXTRA_ACTIVE_SCREEN, true);
                        n.extras.putString(NOTIF_EXTRA_ACTIVE_SCREEN_MODE,
                                ls.getActiveScreenMode().toString());
                    }
                    // visibility
                    if (ls.getVisibility() != Visibility.DEFAULT) {
                        n.visibility = ls.getVisibility().getValue();
                    }
                }

                if (DEBUG) log("Notification info: defaults=" + n.defaults + "; flags=" + n.flags);
            } catch (Throwable t) {
                GravityBox.log(TAG, t);
            }
        }
    };

    private static PowerManager getPowerManager() {
        if (mPm == null) {
            mPm = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
        }
        return mPm;
    }

    private static KeyguardManager getKeyguardManager() {
        if (mKm == null) {
            mKm = (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        }
        return mKm;
    }

    private static TelephonyManager getTelephonyManager() {
        if (mTelephonyManager == null) {
            mTelephonyManager = (TelephonyManager)
                mContext.getSystemService(Context.TELEPHONY_SERVICE);
        }
        return mTelephonyManager;
    }

    private static boolean isUserPresent() {
        try {
            final boolean interactive =
                    getPowerManager().isInteractive() &&
                    !getKeyguardManager().isKeyguardLocked();
            final int callState = getTelephonyManager().getCallState();
            if (DEBUG) log("isUserPresent: interactive=" + interactive +
                    "; call state=" + callState);
            return (interactive || callState == TelephonyManager.CALL_STATE_OFFHOOK);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return false;
        }
    }

    private static Object getOldNotificationRecord(Object pkg, Object tag, Object id, Object userId) {
        Object oldNotifRecord = null;
        try {
            ArrayList<?> notifList = (ArrayList<?>) XposedHelpers.getObjectField(
                    mNotifManagerService, "mNotificationList");
            synchronized (notifList) {
                int index = (Integer) XposedHelpers.callMethod(
                        mNotifManagerService, "indexOfNotificationLocked",
                        pkg, tag, id, userId);
                if (index >= 0) {
                    oldNotifRecord = notifList.get(index);
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error in getOldNotificationRecord: ", t);
        }
        if (DEBUG) log("getOldNotificationRecord: has old record: " + (oldNotifRecord != null));
        return oldNotifRecord;
    }

    private static Notification getNotificationFromRecord(Object record) {
        Notification notif = null;
        if (record != null) {
            try {
                notif = (Notification) XposedHelpers.callMethod(record, "getNotification");
            } catch (Throwable t) {
                GravityBox.log(TAG, "Error in getNotificationFromRecord: ", t);
            }
        }
        return notif;
    }

    private static boolean notificationRecordHasLight(Object record) {
        boolean hasLight = false;
        if (record != null) {
            try {
                String key = (String) XposedHelpers.callMethod(record, "getKey");
                List<?> lights = (List<?>) XposedHelpers.getObjectField(
                        mNotifManagerService, "mLights");
                hasLight = lights.contains(key);
            } catch (Throwable t) {
                GravityBox.log(TAG, "Error in notificationRecordHasLight: ", t);
            }
        }
        if (DEBUG) log("notificationRecordHasLight: " + hasLight);
        return hasLight;
    }

    private static boolean shouldIgnoreUpdatedNotificationLight(Object record, boolean ignore) {
        boolean shouldIgnore = (ignore && record != null && !notificationRecordHasLight(record));
        if (DEBUG) log("shouldIgnoreUpdatedNotificationLight: " + shouldIgnore);
        return shouldIgnore;
    }

    private static int getDefaultNotificationLedColor() {
        if (mDefaultNotificationLedColor == null) {
            mDefaultNotificationLedColor = getDefaultNotificationProp(
                    "config_defaultNotificationColor", "color", 0xff000080);
        }
        return mDefaultNotificationLedColor;
    }

    private static int getDefaultNotificationLedOn() {
        if (mDefaultNotificationLedOn == null) {
            mDefaultNotificationLedOn = getDefaultNotificationProp(
                    "config_defaultNotificationLedOn", "integer", 500);
        }
        return mDefaultNotificationLedOn;
    }

    private static int getDefaultNotificationLedOff() {
        if (mDefaultNotificationLedOff == null) {
            mDefaultNotificationLedOff = getDefaultNotificationProp(
                    "config_defaultNotificationLedOff", "integer", 0);
        }
        return mDefaultNotificationLedOff;
    }

    private static int getDefaultNotificationProp(String resName, String resType, int defVal) {
        int val = defVal;
        try {
            Context ctx = (Context) XposedHelpers.callMethod(
                    mNotifManagerService, "getContext");
            Resources res = ctx.getResources();
            int resId = res.getIdentifier(resName, resType, "android");
            if (resId != 0) {
                switch (resType) {
                    case "color": val = ctx.getColor(resId); break;
                    case "integer": val = res.getInteger(resId); break;
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t); 
        }
        return val;
    }

    private static XC_MethodHook applyZenModeHook = new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(final MethodHookParam param) throws Throwable {
            try {
                Notification n = (Notification) XposedHelpers.callMethod(param.args[0], "getNotification");
                if (!mActiveScreenEnabled ||
                        !n.extras.containsKey(NOTIF_EXTRA_ACTIVE_SCREEN) ||
                        !n.extras.containsKey(NOTIF_EXTRA_ACTIVE_SCREEN_MODE) ||
                        isUserPresent()) {
                    n.extras.remove(NOTIF_EXTRA_ACTIVE_SCREEN);
                    return;
                }
                n.extras.remove(NOTIF_EXTRA_ACTIVE_SCREEN);

                // check if intercepted by Zen
                if (!mUncPrefs.getBoolean(LedSettings.PREF_KEY_ACTIVE_SCREEN_IGNORE_QUIET_HOURS, false) &&
                        (boolean) XposedHelpers.callMethod(param.args[0], "isIntercepted")) {
                    if (DEBUG) log("Active screen: intercepted by Zen - ignoring");
                    n.extras.remove(NOTIF_EXTRA_ACTIVE_SCREEN_MODE);
                    return;
                }

                // set additional params
                final ActiveScreenMode asMode = ActiveScreenMode.valueOf(
                        n.extras.getString(NOTIF_EXTRA_ACTIVE_SCREEN_MODE));
                n.extras.putBoolean(NOTIF_EXTRA_ACTIVE_SCREEN_POCKET_MODE, !mProximityWakeUpEnabled &&
                        mUncPrefs.getBoolean(LedSettings.PREF_KEY_ACTIVE_SCREEN_POCKET_MODE, true));

                if (DEBUG) log("Performing Active Screen with mode " + asMode.toString());

                if (mSm != null && mProxSensor != null &&
                        n.extras.getBoolean(NOTIF_EXTRA_ACTIVE_SCREEN_POCKET_MODE)) {
                    mSm.registerListener(mProxSensorEventListener, mProxSensor, SensorManager.SENSOR_DELAY_FASTEST);
                    if (DEBUG) log("Performing active screen using proximity sensor");
                } else {
                    performActiveScreen();
                }
            } catch (Throwable t) {
                GravityBox.log(TAG, t);
            }
        }
    };

    private static XC_MethodHook updateLightsLockedHook = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
            if (mScreenOnDueToActiveScreen) {
                try {
                    XposedHelpers.setBooleanField(param.thisObject, "mScreenOn", false);
                    if (DEBUG) log("updateLightsLocked: Screen on due to active screen - pretending it's off");
                } catch (Throwable t) {
                    GravityBox.log(TAG, t);
                }
            }
        }
    };

    private static XC_MethodHook startVibrationHook = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
            if (mQuietHours.quietHoursActive() && (mQuietHours.shouldMuteSystemVibe() ||
                    mQuietHours.mode == QuietHours.Mode.WEAR)) {
                if (DEBUG) log("startVibrationLocked: system level vibration suppressed");
                param.setResult(null);
            }
        }
    };

    private static void hookNotificationDelegate() {
        try {
            Object notifDel = XposedHelpers.getObjectField(mNotifManagerService, "mNotificationDelegate");
            XposedHelpers.findAndHookMethod(notifDel.getClass(), "clearEffects", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
                    if (mScreenOnDueToActiveScreen) {
                        if (DEBUG) log("clearEffects: suppressed due to ActiveScreen");
                        param.setResult(null);
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static boolean isRingerModeVibrate() {
        try {
            if (mAudioManager == null) {
                mAudioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            }
            return (mAudioManager.getRingerMode() == AudioManager.RINGER_MODE_VIBRATE);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return false;
        }
    }

    private static boolean currentZenModeDisallowsLed(String dnd) {
        if (dnd == null || dnd.isEmpty())
            return false;

        try {
            int zenMode = Settings.Global.getInt(mContext.getContentResolver(),
                    SETTING_ZEN_MODE, 0);
            List<String> dndList = Arrays.asList(dnd.split(","));
            return dndList.contains(Integer.toString(zenMode));
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return false;
        }
    }

    private static void updateActiveScreenFeature() {
        try {
            mActiveScreenEnabled = !mUncPrefs.getBoolean(LedSettings.PREF_KEY_LOCKED, false) && 
                    mUncPrefs.getBoolean(LedSettings.PREF_KEY_ACTIVE_SCREEN_ENABLED, false); 
            if (mActiveScreenEnabled && mSm == null) {
                mSm = (SensorManager) mContext.getSystemService(Context.SENSOR_SERVICE);
                mProxSensor = mSm.getDefaultSensor(Sensor.TYPE_PROXIMITY);
            } else if (!mActiveScreenEnabled) {
                mProxSensor = null;
                mSm = null;
            }
            if (DEBUG) log("Active screen feature: " + mActiveScreenEnabled);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static void performActiveScreen() {
        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                long ident = Binder.clearCallingIdentity();
                try {
                    XposedHelpers.callMethod(getPowerManager(), "wakeUp", SystemClock.uptimeMillis());
                    mScreenOnDueToActiveScreen = true;
                } finally {
                    Binder.restoreCallingIdentity(ident);
                }
            }
        }, 1000);
    }

    private static void clearNotifications() {
        try {
            if (mNotifManagerService != null) {
                XposedHelpers.callMethod(mNotifManagerService, "cancelAllLocked",
                        android.os.Process.myUid(), android.os.Process.myPid(),
                        XposedHelpers.callStaticMethod(ActivityManager.class, "getCurrentUser"),
                        3, (Object)null, true);
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    // SystemUI package
    private static Object mStatusBar;
    private static XSharedPreferences mSysUiPrefs;
    private static XSharedPreferences mSysUiUncPrefs;

    private static BroadcastReceiver mSystemUiBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent.getAction().equals(GravityBoxSettings.ACTION_HEADS_UP_SETTINGS_CHANGED)) {
                mSysUiPrefs.reload();
            }
        }
    };

    public static void init(final XSharedPreferences prefs, final ClassLoader classLoader) {
        try {
            XposedBridge.hookAllMethods(
                    XposedHelpers.findClass(CLASS_NOTIF_DATA, classLoader),
                    "shouldFilterOut", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    StatusBarNotification sbn = (StatusBarNotification)param.args[0];
                    Notification n = sbn.getNotification();

                    // whether to hide persistent everywhere
                    if (!sbn.isClearable() && n.extras.getBoolean(NOTIF_EXTRA_HIDE_PERSISTENT)) {
                        param.setResult(true);
                        return;
                    }

                    // whether to hide during keyguard
                    if (ModStatusBar.getStatusBarState() != StatusBarState.SHADE) {
                        VisibilityLs vls = n.extras.containsKey(NOTIF_EXTRA_VISIBILITY_LS) ?
                                VisibilityLs.valueOf(n.extras.getString(NOTIF_EXTRA_VISIBILITY_LS)) :
                                    VisibilityLs.DEFAULT;
                        switch (vls) {
                            case CLEARABLE:
                                param.setResult(sbn.isClearable());
                                break;
                            case PERSISTENT:
                                param.setResult(!sbn.isClearable());
                                break;
                            case ALL:
                                param.setResult(true);
                                break;
                            case DEFAULT:
                            default: return;
                        }
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    public static void initHeadsUp(final XSharedPreferences prefs, final XSharedPreferences uncPrefs,
            final ClassLoader classLoader) {
        try {
            mSysUiPrefs = prefs;
            mSysUiUncPrefs = uncPrefs;

            XposedHelpers.findAndHookMethod(CLASS_PHONE_STATUSBAR, classLoader, "start", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    mStatusBar = param.thisObject;
                    Context context = (Context) XposedHelpers.getObjectField(mStatusBar, "mContext");
                    IntentFilter intentFilter = new IntentFilter();
                    intentFilter.addAction(GravityBoxSettings.ACTION_HEADS_UP_SETTINGS_CHANGED);
                    context.registerReceiver(mSystemUiBroadcastReceiver, intentFilter);
                }
            });

            XposedHelpers.findAndHookMethod(CLASS_BASE_STATUSBAR, classLoader, "shouldPeek",
                    CLASS_NOTIF_DATA_ENTRY, StatusBarNotification.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // disable heads up if notification is for different user in multi-user environment
                    if (!(Boolean)XposedHelpers.callMethod(param.thisObject, "isNotificationForCurrentProfiles",
                            param.args[1])) {
                        if (DEBUG) log("HeadsUp: Notification is not for current user");
                        return;
                    }

                    StatusBarNotification sbn = (StatusBarNotification) param.args[1];
                    Context context = (Context) XposedHelpers.getObjectField(param.thisObject, "mContext");
                    Notification n = sbn.getNotification();
                    int statusBarWindowState = XposedHelpers.getIntField(param.thisObject, "mStatusBarWindowState");

                    boolean showHeadsUp = false;

                    // no heads up if app with DND enabled is in the foreground
                    if (shouldNotDisturb(context)) {
                        if (DEBUG) log("shouldInterrupt: NO due to DND app in the foreground");
                        showHeadsUp = false;
                    // get desired mode set by UNC or use default
                    } else {
                        HeadsUpMode mode = n.extras.containsKey(NOTIF_EXTRA_HEADS_UP_MODE) ?
                                HeadsUpMode.valueOf(n.extras.getString(NOTIF_EXTRA_HEADS_UP_MODE)) :
                                    HeadsUpMode.DEFAULT;
                        if (DEBUG) log("Heads up mode: " + mode.toString());
    
                        switch (mode) {
                            default:
                            case DEFAULT:
                                showHeadsUp = (Boolean) param.getResult();
                                break;
                            case ALWAYS: 
                                showHeadsUp = isHeadsUpAllowed(param.args[0], sbn, context);
                                break;
                            case OFF: 
                                showHeadsUp = false; 
                                break;
                            case IMMERSIVE:
                                showHeadsUp = isStatusBarHidden(statusBarWindowState) &&
                                                isHeadsUpAllowed(param.args[0], sbn, context);
                                break;
                        }
                    }

                    param.setResult(showHeadsUp);
                }
            });

            XposedHelpers.findAndHookMethod(CLASS_HEADS_UP_MANAGER_ENTRY, classLoader, "updateEntry",
                    new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object huMgr = XposedHelpers.getSurroundingThis(param.thisObject);
                    Object entry = XposedHelpers.getObjectField(param.thisObject, "entry");
                    if (entry == null ||
                            (boolean)XposedHelpers.callMethod(huMgr, "hasFullScreenIntent", entry)) 
                        return;

                    XposedHelpers.callMethod(param.thisObject, "removeAutoRemovalCallbacks");
                    StatusBarNotification sbNotif = (StatusBarNotification)
                            XposedHelpers.getObjectField(entry, "notification");
                    Notification n = sbNotif.getNotification();
                    int timeout = n.extras.containsKey(NOTIF_EXTRA_HEADS_UP_TIMEOUT) ?
                            n.extras.getInt(NOTIF_EXTRA_HEADS_UP_TIMEOUT) * 1000 :
                                mSysUiPrefs.getInt(GravityBoxSettings.PREF_KEY_HEADS_UP_TIMEOUT, 5) * 1000;
                    if (timeout > 0) {
                        Handler H = (Handler) XposedHelpers.getObjectField(huMgr, "mHandler");
                        H.postDelayed((Runnable)XposedHelpers.getObjectField(
                                param.thisObject, "mRemoveHeadsUpRunnable"), timeout);
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static boolean keyguardAllowsHeadsUp(StatusBarNotification sbn) {
        if (sbn.getNotification().fullScreenIntent == null) {
            return true;
        } else {
            boolean isShowingAndNotOccluded;
            Object kgViewManager = XposedHelpers.getObjectField(mStatusBar, "mStatusBarKeyguardViewManager");
            isShowingAndNotOccluded = ((boolean)XposedHelpers.callMethod(kgViewManager, "isShowing") &&
                    !(boolean)XposedHelpers.callMethod(kgViewManager, "isOccluded"));
            return !isShowingAndNotOccluded;
        }
    }

    private static boolean isDeviceInVrMode() {
        try {
            return (boolean) XposedHelpers.callMethod(mStatusBar, "isDeviceInVrMode");
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error in isDeviceInVrMode()", t);
            return false;
        }
    }

    private static boolean isFilteredNotification(StatusBarNotification sbn) {
        try {
            Object notifData = XposedHelpers.getObjectField(mStatusBar, "mNotificationData");
            return (boolean) XposedHelpers.callMethod(notifData, "shouldFilterOut", sbn);
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error in isFilteredNotification()", t);
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private static boolean isDeviceInUse(Context ctx) {
        PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
        boolean inUse = pm.isScreenOn();
        try {
            Object dm = XposedHelpers.getObjectField(mStatusBar, "mDreamManager");
            inUse &= !(boolean)XposedHelpers.callMethod(dm, "isDreaming");
        } catch (Throwable t) { /* ignore */ }
        return inUse;
    }

    private static boolean hasJustLaunchedFullScreenIntent(Object entry) {
        try {
            return (boolean) XposedHelpers.callMethod(entry, "hasJustLaunchedFullScreenIntent");
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error in hasJustLaunchedFullScreenIntent()", t);
            return false;
        }
    }

    private static boolean isSnoozedPackage(StatusBarNotification sbn) {
        try {
            return (boolean) XposedHelpers.callMethod(mStatusBar, "isSnoozedPackage", sbn);
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error in isSnoozedPackage()", t);
            return false;
        }
    }

    private static boolean isHeadsUpAllowed(Object entry, StatusBarNotification sbn, Context context) {
        if (entry == null || sbn == null || context == null) return false;

        return (!sbn.isOngoing() &&
                !isDeviceInVrMode() &&
                !isFilteredNotification(sbn) &&
                isDeviceInUse(context) &&
                !hasJustLaunchedFullScreenIntent(entry) &&
                !isSnoozedPackage(sbn) &&
                keyguardAllowsHeadsUp(sbn));
    }

    private static boolean isStatusBarHidden(int statusBarWindowState) {
        return (statusBarWindowState != 0);
    }

    @SuppressWarnings("deprecation")
    private static String getTopLevelPackageName(Context context) {
        try {
            final ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            List<ActivityManager.RunningTaskInfo> taskInfo = am.getRunningTasks(1);
            ComponentName cn = taskInfo.get(0).topActivity;
            return cn.getPackageName();
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error getting top level package: ", t);
            return null;
        }
    }

    private static boolean shouldNotDisturb(Context context) {
        String pkgName = getTopLevelPackageName(context);
        mSysUiUncPrefs.reload();
        if(!mSysUiUncPrefs.getBoolean(LedSettings.PREF_KEY_LOCKED, false) && pkgName != null) {
            LedSettings ls = LedSettings.deserialize(mSysUiUncPrefs.getStringSet(pkgName, null));
            return (ls.getEnabled() && ls.getHeadsUpDnd());
        } else {
            return false;
        }
    }
}

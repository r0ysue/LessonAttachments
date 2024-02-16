/*
 * Copyright (C) 2016 Peter Gregus for GravityBox Project (C3C076@xda)
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

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class SystemIconController implements BroadcastSubReceiver {
    private static final String TAG = "GB:SystemIconController";
    private static final boolean DEBUG = false;

    private static final String CLASS_PHONE_STATUSBAR_POLICY = 
            "com.android.systemui.statusbar.phone.PhoneStatusBarPolicy";

    private enum BtMode { DEFAULT, CONNECTED, HIDDEN }

    private Object mSbPolicy;
    private Object mIconCtrl;
    private Context mContext;
    private BtMode mBtMode;
    private boolean mHideVibrateIcon;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    public SystemIconController(ClassLoader classLoader, XSharedPreferences prefs) {
        mBtMode = BtMode.valueOf(prefs.getString(
                GravityBoxSettings.PREF_KEY_STATUSBAR_BT_VISIBILITY, "DEFAULT"));
        mHideVibrateIcon = prefs.getBoolean(
                GravityBoxSettings.PREF_KEY_STATUSBAR_HIDE_VIBRATE_ICON, false);

        createHooks(classLoader);
    }

    private void createHooks(ClassLoader classLoader) {
        try {
            XposedBridge.hookAllConstructors(XposedHelpers.findClass(
                    CLASS_PHONE_STATUSBAR_POLICY, classLoader), new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    mSbPolicy = param.thisObject;
                    mIconCtrl = XposedHelpers.getObjectField(param.thisObject, "mIconController");
                    mContext = (Context) XposedHelpers.getObjectField(param.thisObject, "mContext");
                    if (DEBUG) log ("Phone statusbar policy created");
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }

        try {
            XposedHelpers.findAndHookMethod(CLASS_PHONE_STATUSBAR_POLICY, classLoader, 
                    "updateBluetooth", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (mBtMode != BtMode.DEFAULT) {
                        updateBtIconVisibility();
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }

        try {
            XposedHelpers.findAndHookMethod(CLASS_PHONE_STATUSBAR_POLICY, classLoader, 
                    "updateVolumeZen", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    updateVibrateIcon();
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    @SuppressLint("MissingPermission")
    private void updateBtIconVisibility() {
        if (mIconCtrl == null || mBtMode == null) return;

        try {
            BluetoothAdapter btAdapter = BluetoothAdapter.getDefaultAdapter();
            if (btAdapter != null) {
                boolean enabled = btAdapter.getState() == BluetoothAdapter.STATE_ON;
                boolean connected = (Integer) XposedHelpers.callMethod(btAdapter, "getConnectionState") ==
                        BluetoothAdapter.STATE_CONNECTED;
                boolean visible;
                switch (mBtMode) {
                    default:
                    case DEFAULT: visible = enabled; break;
                    case CONNECTED: visible = connected; break;
                    case HIDDEN: visible = false; break;
                }
                if (DEBUG) log("updateBtIconVisibility: enabled=" + enabled + "; connected=" + connected +
                        "; visible=" + visible);
                XposedHelpers.callMethod(mIconCtrl, "setIconVisibility", "bluetooth", visible);
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private void updateVibrateIcon() {
        if (mIconCtrl == null || mContext == null) return;
        try {
            AudioManager am = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            if (Utils.isOxygenOsRom()) {
                final boolean zenVibrateShowing = XposedHelpers.getIntField(mSbPolicy, "mZen") == 3 &&
                        XposedHelpers.getIntField(mSbPolicy, "mVibrateWhenMute") == 1;
                final boolean hideZen = XposedHelpers.getIntField(mSbPolicy, "mZen") == 0 ||
                        (mHideVibrateIcon && zenVibrateShowing);
                XposedHelpers.callMethod(mIconCtrl, "setIconVisibility",
                        XposedHelpers.getObjectField(mSbPolicy, "mSlotZen"), !hideZen);
                final boolean showNative = !zenVibrateShowing && !mHideVibrateIcon &&
                        am.getRingerMode() == AudioManager.RINGER_MODE_VIBRATE;
                XposedHelpers.callMethod(mIconCtrl, "setIconVisibility", "volume", showNative);
            } else {
                if (am.getRingerMode() == AudioManager.RINGER_MODE_VIBRATE) {
                    XposedHelpers.callMethod(mIconCtrl, "setIconVisibility", "volume", !mHideVibrateIcon);
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private void updateVolumeZen() {
        if (mSbPolicy == null) return;
        try {
            XposedHelpers.callMethod(mSbPolicy, "updateVolumeZen");
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_SYSTEM_ICON_CHANGED)) {
            if (intent.hasExtra(GravityBoxSettings.EXTRA_SB_BT_VISIBILITY)) {
                try {
                    mBtMode = BtMode.valueOf(intent.getStringExtra(GravityBoxSettings.EXTRA_SB_BT_VISIBILITY));
                } catch (Throwable t) { 
                    GravityBox.log(TAG, "Invalid Mode value: ", t);
                }
                updateBtIconVisibility();
            }
            if (intent.hasExtra(GravityBoxSettings.EXTRA_SB_HIDE_VIBRATE_ICON)) {
                mHideVibrateIcon = intent.getBooleanExtra(
                        GravityBoxSettings.EXTRA_SB_HIDE_VIBRATE_ICON, false);
                updateVolumeZen();
            }
        }
    }
}

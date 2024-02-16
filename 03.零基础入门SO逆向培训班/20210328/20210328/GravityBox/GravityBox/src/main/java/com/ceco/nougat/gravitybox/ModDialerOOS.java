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

package com.ceco.nougat.gravitybox;

import android.content.Context;
import android.os.SystemClock;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class ModDialerOOS {
    public static final String PACKAGE_NAME_IN_CALL_UI = "com.android.incallui";
    private static final String TAG = "GB:ModDialerOOS";
    private static final boolean DEBUG = false;

    private static final String CLASS_PHONE_UTILS = "com.android.incallui.oneplus.OPPhoneUtils";

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    private static long mLastPrefReloadMs;

    public static void initInCallUi(final XSharedPreferences prefs, final ClassLoader classLoader) {
        if (DEBUG) log("initInCallUi");
        try {
            XposedHelpers.findAndHookMethod(CLASS_PHONE_UTILS, classLoader,
                    "isSupportCallRecorder", Context.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    reloadPrefsIfExpired(prefs);
                    if (prefs.getBoolean(GravityBoxSettings.PREF_KEY_OOS_CALL_RECORDING, false)) {
                        param.setResult(true);
                        if (DEBUG) log("isSupportCallRecorder: forced to return true");
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static void reloadPrefsIfExpired(final XSharedPreferences prefs) {
        if (SystemClock.uptimeMillis() - mLastPrefReloadMs > 10000) {
            mLastPrefReloadMs = SystemClock.uptimeMillis();
            prefs.reload();
            if (DEBUG) log("Expired prefs reloaded");
        }
    }
}

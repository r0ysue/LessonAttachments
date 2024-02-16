/*
 * Copyright (C) 2015 Peter Gregus for GravityBox Project (C3C076@xda)
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

import com.ceco.nougat.gravitybox.telecom.CallFeatures;
import com.ceco.nougat.gravitybox.telecom.MissedCallNotifier;

import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;

public class ModTelecom {
    public static final String PACKAGE_NAME = "com.android.server.telecom";
    private static final String TAG = "GB:ModTelecom";
    private static final boolean DEBUG = false;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    public static void init(final XSharedPreferences prefs, final ClassLoader classLoader) {
        if (DEBUG) log("init");

        try {
            MissedCallNotifier.init(classLoader);
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error initializing MissedCallNotifier: ", t);
        }

        try {
            CallFeatures.init(prefs, classLoader);
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error initializing CallFeatures: ", t);
        }
    }
}

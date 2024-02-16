/*
 * Copyright (C) 2017 Peter Gregus for GravityBox Project (C3C076@xda)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ceco.nougat.gravitybox;

import android.content.Context;
import android.content.Intent;
import android.util.SparseArray;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class ModDownloadProvider {
    private static final String TAG = "GB:ModDownloadProvider";
    public static final String PACKAGE_NAME = "com.android.providers.downloads";

    private static final String CLASS_DOWNLOAD_JOB_SERVICE = "com.android.providers.downloads.DownloadJobService";
    private static final boolean DEBUG = false;

    public static final String ACTION_DOWNLOAD_STATE_CHANGED = "gravitybox.intent.action.DOWNLOAD_STATE_CHANGED";
    public static final String EXTRA_ACTIVE = "isActive";

    private static boolean mIsActive;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    public static void init(final XSharedPreferences prefs, final ClassLoader classLoader) {
        try {
            final Class<?> classDownloadJobService = XposedHelpers.findClass(CLASS_DOWNLOAD_JOB_SERVICE, classLoader);

            XC_MethodHook jobStartStopHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    SparseArray<?> activeThreads = (SparseArray<?>) XposedHelpers.getObjectField(
                            param.thisObject, "mActiveThreads");
                    final boolean isActive = activeThreads.size() > 0;
                    if (mIsActive != isActive) { 
                        mIsActive = isActive;
                        if (DEBUG) log("Download state changed; active=" + mIsActive);
                        final Context context = (Context) param.thisObject;
                        Intent intent = new Intent(ACTION_DOWNLOAD_STATE_CHANGED);
                        intent.putExtra(EXTRA_ACTIVE, mIsActive);
                        context.sendBroadcast(intent);
                    }
                }
            };
            XposedBridge.hookAllMethods(classDownloadJobService, "onStartJob", jobStartStopHook);
            XposedBridge.hookAllMethods(classDownloadJobService, "onStopJob", jobStartStopHook);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }
}

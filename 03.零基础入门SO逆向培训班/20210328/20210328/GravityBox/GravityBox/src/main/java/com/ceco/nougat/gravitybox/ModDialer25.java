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

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import com.ceco.nougat.gravitybox.ledcontrol.QuietHours;

import android.app.Activity;
import android.app.Fragment;
import android.content.Intent;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class ModDialer25 {
    private static final String TAG = "GB:ModDialer25";

    private static final String CLASS_DIALTACTS_ACTIVITY = "com.android.dialer.app.DialtactsActivity";
    private static final String CLASS_DIALTACTS_ACTIVITY_GOOGLE = 
            "com.google.android.apps.dialer.extensions.GoogleDialtactsActivity";
    private static final boolean DEBUG = false;

    private static QuietHours mQuietHours;
    private static long mPrefsReloadedTstamp;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    static class ClassInfo {
        Class<?> clazz;
        Map<String,String> methods;
        Object extra;
        ClassInfo(Class<?> cls) {
            clazz = cls;
            methods = new HashMap<>();
        }
    }

    private static ClassInfo resolveDialtactsActivity(ClassLoader cl) {
        ClassInfo info = null;
        String[] CLASS_NAMES = new String[] { CLASS_DIALTACTS_ACTIVITY };
        String[] METHOD_NAMES = new String[] { "displayFragment" };
        for (String className : CLASS_NAMES) {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
            if (clazz == null || !Activity.class.isAssignableFrom(clazz))
                continue;
            info = new ClassInfo(clazz);
            for (String methodName : METHOD_NAMES) {
                if (methodName.equals("displayFragment")) {
                    for (String realMethodName : new String[] { methodName, "c", "b", "a" }) {
                        Method m = XposedHelpers.findMethodExactIfExists(clazz, realMethodName,
                            Intent.class);
                        if (m != null) {
                            info.methods.put(methodName, realMethodName);
                            if (realMethodName.equals(methodName)) {
                                info.extra = "showDialpadFragment";
                            } else if (realMethodName.equals("c")) {
                                info.extra = "b";
                            } else if (realMethodName.equals("b")) {
                                info.extra = "c";
                            } else if (realMethodName.equals("a")) {
                                info.extra = "d";
                            }
                            break;
                        }
                    }
                }
            }
        }
        return info;
    }

    private static ClassInfo resolveDialpadFragment(ClassLoader cl) {
        ClassInfo info = null;
        String[] CLASS_NAMES = new String[] {
                "com.android.dialer.app.dialpad.DialpadFragment",
                "com.android.dialer.dialpadview.DialpadFragment"
        };
        String[] METHOD_NAMES = new String[] { "onResume", "playTone" };
        for (String className : CLASS_NAMES) {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
            if (clazz == null || !Fragment.class.isAssignableFrom(clazz))
                continue;
            info = new ClassInfo(clazz);
            for (String methodName : METHOD_NAMES) {
                Method m = null;
                if (methodName.equals("onResume")) {
                    m = XposedHelpers.findMethodExactIfExists(clazz, methodName);
                } else if (methodName.equals("playTone")) {
                    for (String realMethodName : new String[] { methodName, "a" }) {
                        m = XposedHelpers.findMethodExactIfExists(clazz, realMethodName,
                            int.class, int.class);
                        if (m != null) break;
                    }
                }
                if (m != null) {
                    info.methods.put(methodName, m.getName());
                }
            }
        }
        return info;
    }

    private static void reloadPrefs(XSharedPreferences prefs) {
        if ((System.currentTimeMillis() - mPrefsReloadedTstamp) > 10000) {
            if (DEBUG) log("Reloading preferences");
            prefs.reload();
            mPrefsReloadedTstamp = System.currentTimeMillis();
        }
    }

    public static void init(final XSharedPreferences prefs, final XSharedPreferences qhPrefs,
            final ClassLoader classLoader, final String packageName) {
        try {
            final ClassInfo classInfoDialtactsActivity = resolveDialtactsActivity(classLoader);

            XposedHelpers.findAndHookMethod(classInfoDialtactsActivity.clazz,
                    classInfoDialtactsActivity.methods.get("displayFragment"),
                    Intent.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    reloadPrefs(prefs);
                    if (!prefs.getBoolean(GravityBoxSettings.PREF_KEY_DIALER_SHOW_DIALPAD, false)) return;

                    final String realClassName = param.thisObject.getClass().getName();
                    if (realClassName.equals(CLASS_DIALTACTS_ACTIVITY)) {
                        XposedHelpers.callMethod(param.thisObject,
                                classInfoDialtactsActivity.extra.toString(), false);
                        if (DEBUG) log("showDialpadFragment() called within " + realClassName);
                    } else if (realClassName.equals(CLASS_DIALTACTS_ACTIVITY_GOOGLE)) {
                        final Class<?> superc = param.thisObject.getClass().getSuperclass();
                        Method m = XposedHelpers.findMethodExact(superc,
                                classInfoDialtactsActivity.extra.toString(), boolean.class);
                        m.invoke(param.thisObject, false);
                        if (DEBUG) log("showDialpadFragment() called within " + realClassName);
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, "DialtactsActivity: incompatible version of Dialer app", t);
        }

        try {
            final ClassInfo classInfoDialpadFragment = resolveDialpadFragment(classLoader);

            XposedHelpers.findAndHookMethod(classInfoDialpadFragment.clazz,
                    classInfoDialpadFragment.methods.get("onResume"), new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param2) throws Throwable {
                    qhPrefs.reload();
                    mQuietHours = new QuietHours(qhPrefs);
                }
            });

            XposedHelpers.findAndHookMethod(classInfoDialpadFragment.clazz,
                    classInfoDialpadFragment.methods.get("playTone"),
                    int.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (mQuietHours.isSystemSoundMuted(QuietHours.SystemSound.DIALPAD)) {
                        param.setResult(null);
                    }
                }
            });
        } catch (Throwable t) {
            GravityBox.log(TAG, "DialpadFragment: incompatible version of Dialer app", t);
        }
    }
}

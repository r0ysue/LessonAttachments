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

import java.io.File;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Message;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.SparseArray;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.Space;
import android.widget.ImageView.ScaleType;

import com.ceco.nougat.gravitybox.R;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class ModNavigationBar {
    public static final String PACKAGE_NAME = "com.android.systemui";
    private static final String TAG = "GB:ModNavigationBar";
    private static final boolean DEBUG = false;

    private static final String CLASS_NAVBAR_VIEW = "com.android.systemui.statusbar.phone.NavigationBarView";
    private static final String CLASS_KEY_BUTTON_VIEW = "com.android.systemui.statusbar.policy.KeyButtonView";
    private static final String CLASS_KEY_BUTTON_RIPPLE = "com.android.systemui.statusbar.policy.KeyButtonRipple";
    private static final String CLASS_NAVBAR_TRANSITIONS = 
            "com.android.systemui.statusbar.phone.NavigationBarTransitions";
    private static final String CLASS_PHONE_STATUSBAR = "com.android.systemui.statusbar.phone.PhoneStatusBar";
    private static final String CLASS_NAVBAR_INFLATER_VIEW = "com.android.systemui.statusbar.phone.NavigationBarInflaterView";

    @SuppressWarnings("unused")
    private static final int MODE_OPAQUE = 0;
    private static final int MODE_LIGHTS_OUT = 3;
    private static final int MODE_LIGHTS_OUT_TRANSPARENT = 6;
    private static final int MSG_LIGHTS_OUT = 1;

    private static final int NAVIGATION_HINT_BACK_ALT = 1 << 0;
    private static final int STATUS_BAR_DISABLE_RECENT = 0x01000000;

    private static boolean mAlwaysShowMenukey;
    private static View mNavigationBarView;
    private static ModHwKeys.HwKeyAction mRecentsSingletapAction = new ModHwKeys.HwKeyAction(0, null);
    private static ModHwKeys.HwKeyAction mRecentsLongpressAction = new ModHwKeys.HwKeyAction(0, null);
    private static ModHwKeys.HwKeyAction mRecentsDoubletapAction = new ModHwKeys.HwKeyAction(0, null);
    private static int mHomeLongpressAction = 0;
    private static boolean mHwKeysEnabled;
    private static boolean mCursorControlEnabled;
    private static boolean mDpadKeysVisible;
    private static boolean mHideImeSwitcher;
    private static PowerManager mPm;
    private static long mLastTouchMs;
    private static int mBarModeOriginal;
    private static int mAutofadeTimeoutMs;
    private static String mAutofadeShowKeysPolicy;
    private static boolean mUpdateDisabledFlags;
    private static boolean mUpdateIconHints;

    // Navbar dimensions
    private static int mNavbarHeight;
    private static int mNavbarWidth;

    // Custom key
    private enum CustomKeyIconStyle { SIX_DOT, THREE_DOT, TRANSPARENT, CUSTOM }
    private static boolean mCustomKeyEnabled;
    private static Resources mResources;
    private static Context mGbContext;
    private static NavbarViewInfo[] mNavbarViewInfo = new NavbarViewInfo[2];
    private static boolean mCustomKeySwapEnabled;
    private static CustomKeyIconStyle mCustomKeyIconStyle;

    // Colors
    private static boolean mNavbarColorsEnabled;
    private static int mKeyDefaultColor = 0xe8ffffff;
    private static int mKeyDefaultGlowColor = 0x33ffffff;
    private static int mKeyColor;
    private static int mKeyGlowColor;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    static class NavbarViewInfo {
        ViewGroup navButtons;
        ViewGroup endsGroup;
        ViewGroup centerGroup;
        KeyButtonView customKey;
        View customKeyPlaceHolder;
        ViewGroup customKeyParent;
        boolean customKeyVisible;
        KeyButtonView dpadLeft;
        KeyButtonView dpadRight;
        boolean menuCustomSwapped;
        ViewGroup menuImeGroup;
        View imeSwitcher;
        View menuKey;
        View backKey;
        View recentsKey;
        SparseArray<ScaleType> originalScaleType = new SparseArray<ScaleType>();
    }

    private static BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (DEBUG) log("Broadcast received: " + intent.toString());
            if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_NAVBAR_CHANGED)) {
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_MENUKEY)) {
                    mAlwaysShowMenukey = intent.getBooleanExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_MENUKEY, false);
                    if (DEBUG) log("mAlwaysShowMenukey = " + mAlwaysShowMenukey);
                    setMenuKeyVisibility();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_CUSTOM_KEY_ENABLE)) {
                    mCustomKeyEnabled = intent.getBooleanExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_CUSTOM_KEY_ENABLE, false);
                    setCustomKeyVisibility();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_KEY_COLOR)) {
                    mKeyColor = intent.getIntExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_KEY_COLOR, mKeyDefaultColor);
                    setKeyColor();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_KEY_GLOW_COLOR)) {
                    mKeyGlowColor = intent.getIntExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_KEY_GLOW_COLOR, mKeyDefaultGlowColor);
                    setKeyColor();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_COLOR_ENABLE)) {
                    mNavbarColorsEnabled = intent.getBooleanExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_COLOR_ENABLE, false);
                    setKeyColor();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_CURSOR_CONTROL)) {
                    mCursorControlEnabled = intent.getBooleanExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_CURSOR_CONTROL, false);
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_CUSTOM_KEY_SWAP)) {
                    mCustomKeySwapEnabled = intent.getBooleanExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_CUSTOM_KEY_SWAP, false);
                    setCustomKeyVisibility();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_CUSTOM_KEY_ICON_STYLE)) {
                    mCustomKeyIconStyle = CustomKeyIconStyle.valueOf(intent.getStringExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_CUSTOM_KEY_ICON_STYLE));
                    updateCustomKeyIcon();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_HIDE_IME)) {
                    mHideImeSwitcher = intent.getBooleanExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_HIDE_IME, false);
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_HEIGHT)) {
                    mNavbarHeight = intent.getIntExtra(GravityBoxSettings.EXTRA_NAVBAR_HEIGHT, 100);
                    updateIconScaleType();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_WIDTH)) {
                    mNavbarWidth = intent.getIntExtra(GravityBoxSettings.EXTRA_NAVBAR_WIDTH, 100);
                    updateIconScaleType();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_AUTOFADE_KEYS)) {
                    mAutofadeTimeoutMs = intent.getIntExtra(GravityBoxSettings.EXTRA_NAVBAR_AUTOFADE_KEYS, 0) * 1000;
                    mBarModeHandler.removeMessages(MSG_LIGHTS_OUT);
                    if (mAutofadeTimeoutMs == 0) {
                        setBarMode(mBarModeOriginal);
                    } else {
                        mBarModeHandler.sendEmptyMessageDelayed(MSG_LIGHTS_OUT, mAutofadeTimeoutMs);
                    }
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_NAVBAR_AUTOFADE_SHOW_KEYS)) {
                    mAutofadeShowKeysPolicy = intent.getStringExtra(
                            GravityBoxSettings.EXTRA_NAVBAR_AUTOFADE_SHOW_KEYS);
                }
            } else if (intent.getAction().equals(
                    GravityBoxSettings.ACTION_PREF_HWKEY_CHANGED) && 
                    GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_SINGLETAP.equals(intent.getStringExtra(
                            GravityBoxSettings.EXTRA_HWKEY_KEY))) {
                mRecentsSingletapAction.actionId = intent.getIntExtra(GravityBoxSettings.EXTRA_HWKEY_VALUE, 0);
                mRecentsSingletapAction.customApp = intent.getStringExtra(GravityBoxSettings.EXTRA_HWKEY_CUSTOM_APP);
                updateRecentsKeyCode();
            } else if (intent.getAction().equals(
                    GravityBoxSettings.ACTION_PREF_HWKEY_CHANGED) &&
                    GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_LONGPRESS.equals(intent.getStringExtra(
                            GravityBoxSettings.EXTRA_HWKEY_KEY))) {
                mRecentsLongpressAction.actionId = intent.getIntExtra(GravityBoxSettings.EXTRA_HWKEY_VALUE, 0);
                mRecentsLongpressAction.customApp = intent.getStringExtra(GravityBoxSettings.EXTRA_HWKEY_CUSTOM_APP);
                updateRecentsKeyCode();
            } else if (intent.getAction().equals(
                    GravityBoxSettings.ACTION_PREF_HWKEY_CHANGED) &&
                    GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_DOUBLETAP.equals(intent.getStringExtra(
                            GravityBoxSettings.EXTRA_HWKEY_KEY))) {
                mRecentsDoubletapAction.actionId = intent.getIntExtra(GravityBoxSettings.EXTRA_HWKEY_VALUE, 0);
                mRecentsDoubletapAction.customApp = intent.getStringExtra(GravityBoxSettings.EXTRA_HWKEY_CUSTOM_APP);
                updateRecentsKeyCode();
            } else if (intent.getAction().equals(
                    GravityBoxSettings.ACTION_PREF_HWKEY_CHANGED) &&
                    GravityBoxSettings.PREF_KEY_HWKEY_HOME_LONGPRESS.equals(intent.getStringExtra(
                            GravityBoxSettings.EXTRA_HWKEY_KEY))) {
                mHomeLongpressAction = intent.getIntExtra(GravityBoxSettings.EXTRA_HWKEY_VALUE, 0);
            } else if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_PIE_CHANGED) && 
                    intent.hasExtra(GravityBoxSettings.EXTRA_PIE_HWKEYS_DISABLE)) {
                mHwKeysEnabled = !intent.getBooleanExtra(GravityBoxSettings.EXTRA_PIE_HWKEYS_DISABLE, false);
                updateRecentsKeyCode();
            } else if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_NAVBAR_SWAP_KEYS)) {
                swapBackAndRecents();
            }
        }
    };

    public static void init(final XSharedPreferences prefs, final ClassLoader classLoader) {
        try {
            final Class<?> navbarViewClass = XposedHelpers.findClass(CLASS_NAVBAR_VIEW, classLoader);
            final Class<?> navbarTransitionsClass = XposedHelpers.findClass(CLASS_NAVBAR_TRANSITIONS, classLoader);

            mAlwaysShowMenukey = prefs.getBoolean(GravityBoxSettings.PREF_KEY_NAVBAR_MENUKEY, false);

            try {
                mRecentsSingletapAction = new ModHwKeys.HwKeyAction(Integer.valueOf(
                        prefs.getString(GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_SINGLETAP, "0")),
                        prefs.getString(GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_SINGLETAP+"_custom", null));
                mRecentsLongpressAction = new ModHwKeys.HwKeyAction(0, null);
                mRecentsLongpressAction = new ModHwKeys.HwKeyAction(Integer.valueOf(
                        prefs.getString(GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_LONGPRESS, "0")),
                        prefs.getString(GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_LONGPRESS+"_custom", null));
                mRecentsDoubletapAction = new ModHwKeys.HwKeyAction(Integer.valueOf(
                        prefs.getString(GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_DOUBLETAP, "0")),
                        prefs.getString(GravityBoxSettings.PREF_KEY_HWKEY_RECENTS_DOUBLETAP+"_custom", null));
                mHomeLongpressAction = Integer.valueOf(
                        prefs.getString(GravityBoxSettings.PREF_KEY_HWKEY_HOME_LONGPRESS, "0"));
            } catch (NumberFormatException nfe) {
                GravityBox.log(TAG, nfe);
            }

            mCustomKeyEnabled = prefs.getBoolean(
                    GravityBoxSettings.PREF_KEY_NAVBAR_CUSTOM_KEY_ENABLE, false);
            mHwKeysEnabled = !prefs.getBoolean(GravityBoxSettings.PREF_KEY_HWKEYS_DISABLE, false);
            mCursorControlEnabled = prefs.getBoolean(
                    GravityBoxSettings.PREF_KEY_NAVBAR_CURSOR_CONTROL, false);
            mCustomKeySwapEnabled = prefs.getBoolean(
                    GravityBoxSettings.PREF_KEY_NAVBAR_CUSTOM_KEY_SWAP, false);
            mHideImeSwitcher = prefs.getBoolean(GravityBoxSettings.PREF_KEY_NAVBAR_HIDE_IME, false);

            mNavbarHeight = prefs.getInt(GravityBoxSettings.PREF_KEY_NAVBAR_HEIGHT, 100);
            mNavbarWidth = prefs.getInt(GravityBoxSettings.PREF_KEY_NAVBAR_WIDTH, 100);
            mAutofadeTimeoutMs = prefs.getInt(GravityBoxSettings.PREF_KEY_NAVBAR_AUTOFADE_KEYS, 0) * 1000;
            mAutofadeShowKeysPolicy = prefs.getString(GravityBoxSettings.PREF_KEY_NAVBAR_AUTOFADE_SHOW_KEYS, "NAVBAR");

            // for HTC GPE devices having capacitive keys
            if (prefs.getBoolean(GravityBoxSettings.PREF_KEY_NAVBAR_ENABLE, false)) {
                try {
                    Class<?> sbFlagClass = XposedHelpers.findClass(
                            "com.android.systemui.statusbar.StatusBarFlag", classLoader);
                    XposedHelpers.setStaticBooleanField(sbFlagClass, "supportHWNav", false);
                } catch (Throwable ignored) { }
            }

            XposedBridge.hookAllConstructors(navbarViewClass, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Context context = (Context) param.args[0];
                    if (context == null) return;

                    mResources = context.getResources();

                    mGbContext = Utils.getGbContext(context);
                    mNavbarColorsEnabled = prefs.getBoolean(GravityBoxSettings.PREF_KEY_NAVBAR_COLOR_ENABLE, false);
                    mKeyDefaultColor = mGbContext.getColor(R.color.navbar_key_color);
                    mKeyColor = prefs.getInt(GravityBoxSettings.PREF_KEY_NAVBAR_KEY_COLOR, mKeyDefaultColor);
                    mKeyDefaultGlowColor = mGbContext.getColor(R.color.navbar_key_glow_color);
                    mKeyGlowColor = prefs.getInt(
                            GravityBoxSettings.PREF_KEY_NAVBAR_KEY_GLOW_COLOR, mKeyDefaultGlowColor);
                    mCustomKeyIconStyle = CustomKeyIconStyle.valueOf(prefs.getString(
                            GravityBoxSettings.PREF_KEY_NAVBAR_CUSTOM_KEY_ICON_STYLE, "SIX_DOT"));

                    mNavigationBarView = (View) param.thisObject;
                    IntentFilter intentFilter = new IntentFilter();
                    intentFilter.addAction(GravityBoxSettings.ACTION_PREF_NAVBAR_CHANGED);
                    intentFilter.addAction(GravityBoxSettings.ACTION_PREF_HWKEY_CHANGED);
                    intentFilter.addAction(GravityBoxSettings.ACTION_PREF_PIE_CHANGED);
                    intentFilter.addAction(GravityBoxSettings.ACTION_PREF_NAVBAR_SWAP_KEYS);
                    context.registerReceiver(mBroadcastReceiver, intentFilter);
                    if (DEBUG) log("NavigationBarView constructed; Broadcast receiver registered");
                }
            });

            XposedHelpers.findAndHookMethod(navbarViewClass, "setMenuVisibility",
                    boolean.class, boolean.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    setMenuKeyVisibility();
                }
            });

            XposedHelpers.findAndHookMethod(CLASS_NAVBAR_INFLATER_VIEW, classLoader, "inflateLayout",
                    String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    final Context context = ((View) param.thisObject).getContext();

                    // prepare app, dpad left, dpad right keys
                    ViewGroup vRot, navButtons;

                    // prepare keys for rot0 view
                    vRot = (ViewGroup) XposedHelpers.getObjectField(param.thisObject, "mRot0");
                    if (vRot != null) {
                        ScaleType scaleType = getIconScaleType(0, View.NO_ID);
                        KeyButtonView appKey = new KeyButtonView(context);
                        appKey.setScaleType(scaleType);
                        appKey.setClickable(true);
                        appKey.setImageDrawable(getCustomKeyIconDrawable());
                        appKey.setKeyCode(KeyEvent.KEYCODE_SOFT_LEFT);

                        KeyButtonView dpadLeft = new KeyButtonView(context);
                        dpadLeft.setScaleType(scaleType);
                        dpadLeft.setClickable(true);
                        dpadLeft.setImageDrawable(mGbContext.getDrawable(R.drawable.ic_sysbar_ime_left));
                        dpadLeft.setVisibility(View.GONE);
                        dpadLeft.setKeyCode(KeyEvent.KEYCODE_DPAD_LEFT);

                        KeyButtonView dpadRight = new KeyButtonView(context);
                        dpadRight.setScaleType(scaleType);
                        dpadRight.setClickable(true);
                        dpadRight.setImageDrawable(mGbContext.getDrawable(R.drawable.ic_sysbar_ime_right));
                        dpadRight.setVisibility(View.GONE);
                        dpadRight.setKeyCode(KeyEvent.KEYCODE_DPAD_RIGHT);

                        navButtons = (ViewGroup) vRot.findViewById(
                                mResources.getIdentifier("nav_buttons", "id", PACKAGE_NAME));
                        prepareNavbarViewInfo(navButtons, 0, appKey, dpadLeft, dpadRight);
                    }

                    // prepare keys for rot90 view
                    vRot = (ViewGroup) XposedHelpers.getObjectField(param.thisObject, "mRot90");
                    if (vRot != null) {
                        ScaleType scaleType = getIconScaleType(1, View.NO_ID);
                        KeyButtonView appKey = new KeyButtonView(context);
                        appKey.setScaleType(scaleType);
                        appKey.setClickable(true);
                        appKey.setImageDrawable(getCustomKeyIconDrawable());
                        appKey.setKeyCode(KeyEvent.KEYCODE_SOFT_LEFT);

                        KeyButtonView dpadLeft = new KeyButtonView(context);
                        dpadLeft.setScaleType(scaleType);
                        dpadLeft.setClickable(true);
                        dpadLeft.setImageDrawable(mGbContext.getDrawable(R.drawable.ic_sysbar_ime_left));
                        dpadLeft.setVisibility(View.GONE);
                        dpadLeft.setKeyCode(KeyEvent.KEYCODE_DPAD_LEFT);

                        KeyButtonView dpadRight = new KeyButtonView(context);
                        dpadRight.setScaleType(scaleType);
                        dpadRight.setClickable(true);
                        dpadRight.setImageDrawable(mGbContext.getDrawable(R.drawable.ic_sysbar_ime_right));
                        dpadRight.setVisibility(View.GONE);
                        dpadRight.setKeyCode(KeyEvent.KEYCODE_DPAD_RIGHT);

                        navButtons = (ViewGroup) vRot.findViewById(
                                mResources.getIdentifier("nav_buttons", "id", PACKAGE_NAME));
                        prepareNavbarViewInfo(navButtons, 1, appKey, dpadLeft, dpadRight);
                    }

                    updateRecentsKeyCode();

                    if (prefs.getBoolean(GravityBoxSettings.PREF_KEY_NAVBAR_SWAP_KEYS, false)) {
                        swapBackAndRecents();
                    }

                    updateIconScaleType();
                }
            });

            XposedHelpers.findAndHookMethod(navbarViewClass, "setDisabledFlags",
                    int.class, boolean.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    mUpdateDisabledFlags = (boolean)param.args[1] ||
                            XposedHelpers.getIntField(param.thisObject, "mDisabledFlags") !=
                                (int)param.args[0];
                }
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (mUpdateDisabledFlags) {
                        mUpdateDisabledFlags = false;
                        setDpadKeyVisibility();
                        setCustomKeyVisibility();
                        setMenuKeyVisibility();
                        if (mNavbarColorsEnabled) {
                            setKeyColor();
                        }
                    }
                }
            });

            XposedHelpers.findAndHookMethod(navbarViewClass, "setNavigationIconHints",
                    int.class, boolean.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    mUpdateIconHints = (boolean)param.args[1] ||
                            XposedHelpers.getIntField(param.thisObject, "mNavigationIconHints") !=
                            (int)param.args[0];
                }
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (mUpdateIconHints) {
                        mUpdateIconHints = false;
                        if (mHideImeSwitcher) {
                            hideImeSwitcher();
                        }
                        setDpadKeyVisibility();
                    }
                }
            });

            XposedHelpers.findAndHookMethod(navbarTransitionsClass, "applyMode",
                    int.class, boolean.class, boolean.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    int barMode = (int)param.args[0];
                    if (barMode != MODE_LIGHTS_OUT_TRANSPARENT) {
                        mBarModeOriginal = barMode;
                    }
                    if (mAutofadeTimeoutMs > 0 &&
                            SystemClock.uptimeMillis() - mLastTouchMs >= mAutofadeTimeoutMs &&
                                barMode != MODE_LIGHTS_OUT &&
                                barMode != MODE_LIGHTS_OUT_TRANSPARENT) {
                        param.args[0] = MODE_LIGHTS_OUT_TRANSPARENT;
                    }
                }
            });

            XposedHelpers.findAndHookMethod(CLASS_KEY_BUTTON_RIPPLE, classLoader,
                    "getRipplePaint", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (mNavbarColorsEnabled) {
                        ((Paint)param.getResult()).setColor(mKeyGlowColor);
                    }
                }
            });

            XposedHelpers.findAndHookMethod(CLASS_KEY_BUTTON_VIEW, classLoader,
                    "sendEvent", int.class, int.class, long.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (mPm == null) {
                        mPm = (PowerManager) ((View) param.thisObject).getContext()
                            .getSystemService(Context.POWER_SERVICE);
                    }
                    if (mPm != null && !mPm.isInteractive()) {
                        int keyCode = XposedHelpers.getIntField(param.thisObject, "mCode");
                        if (keyCode != KeyEvent.KEYCODE_HOME) {
                            if (DEBUG) log("key button sendEvent: ignoring since not interactive");
                            param.setResult(null);
                        }
                    }
                }
            });

            XposedHelpers.findAndHookMethod(CLASS_PHONE_STATUSBAR, classLoader,
                    "shouldDisableNavbarGestures", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (mHomeLongpressAction != 0) {
                        param.setResult(true);
                    }
                }
            });

            XC_MethodHook touchEventHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (mAutofadeTimeoutMs == 0) return;

                    int action = ((MotionEvent)param.args[0]).getAction();
                    if (action == MotionEvent.ACTION_DOWN ||
                            (action == MotionEvent.ACTION_OUTSIDE &&
                                 "SCREEN".equals(mAutofadeShowKeysPolicy))) {
                        mLastTouchMs = SystemClock.uptimeMillis();
                        if (mBarModeHandler.hasMessages(MSG_LIGHTS_OUT)) {
                            mBarModeHandler.removeMessages(MSG_LIGHTS_OUT);
                        } else {
                            setBarMode(mBarModeOriginal);
                        }
                        mBarModeHandler.sendEmptyMessageDelayed(MSG_LIGHTS_OUT, mAutofadeTimeoutMs);
                    }
                }
            };
            XposedHelpers.findAndHookMethod(CLASS_NAVBAR_VIEW, classLoader,
                    "onInterceptTouchEvent", MotionEvent.class, touchEventHook);
            XposedHelpers.findAndHookMethod(CLASS_NAVBAR_VIEW, classLoader,
                    "onTouchEvent", MotionEvent.class, touchEventHook);

            XposedHelpers.findAndHookMethod(CLASS_PHONE_STATUSBAR, classLoader,
                    "toggleSplitScreenMode", int.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (mRecentsLongpressAction.actionId != 0 &&
                            (int)param.args[0] != -1 && (int)param.args[1] != -1) {
                        param.setResult(null);
                    }
                }
            });
        } catch(Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    @SuppressLint("HandlerLeak")
    private static Handler mBarModeHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            if (msg.what == MSG_LIGHTS_OUT) {
                setBarMode(MODE_LIGHTS_OUT_TRANSPARENT);
            }
        }
    };

    private static void setBarMode(int mode) {
        try {
            Object bt = XposedHelpers.callMethod(mNavigationBarView, "getBarTransitions");
            XposedHelpers.callMethod(bt, "applyMode", mode, true, true);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static void prepareNavbarViewInfo(ViewGroup navButtons, int index, 
            KeyButtonView appView, KeyButtonView dpadLeft, KeyButtonView dpadRight) {
        try {
            mNavbarViewInfo[index] = new NavbarViewInfo();
            mNavbarViewInfo[index].navButtons = navButtons;
            mNavbarViewInfo[index].customKey = appView;
            mNavbarViewInfo[index].dpadLeft = dpadLeft;
            mNavbarViewInfo[index].dpadRight = dpadRight;

            // ends group
            int resId = mResources.getIdentifier("ends_group", "id", PACKAGE_NAME);
            ViewGroup endsGroup = (ViewGroup) mNavbarViewInfo[index]
                    .navButtons.findViewById(resId);
            mNavbarViewInfo[index].endsGroup = endsGroup;

            // center group
            resId = mResources.getIdentifier("center_group", "id", PACKAGE_NAME);
            mNavbarViewInfo[index].centerGroup = (ViewGroup) mNavbarViewInfo[index]
                    .navButtons.findViewById(resId);

            // find ime switcher, menu group
            resId = mResources.getIdentifier("ime_switcher", "id", PACKAGE_NAME);
            if (resId != 0) {
                View v = mNavbarViewInfo[index].endsGroup.findViewById(resId);
                if (v != null) {
                    mNavbarViewInfo[index].imeSwitcher = v;
                    mNavbarViewInfo[index].menuImeGroup = (ViewGroup) v.getParent();
                }
            }

            // find potential placeholder for custom key
            mNavbarViewInfo[index].customKeyParent = endsGroup;
            int pos1 = 0;
            int pos2 = endsGroup.getChildCount()-1;
            if (endsGroup.getChildAt(pos1) instanceof Space) {
                mNavbarViewInfo[index].customKeyPlaceHolder = endsGroup.getChildAt(pos1);
            } else if (endsGroup.getChildAt(pos2) instanceof Space) {
                mNavbarViewInfo[index].customKeyPlaceHolder = endsGroup.getChildAt(pos2);
            } else if (endsGroup.getChildAt(pos1) instanceof ViewGroup &&
                    endsGroup.getChildAt(pos1) != mNavbarViewInfo[index].menuImeGroup) {
                mNavbarViewInfo[index].customKeyParent = (ViewGroup) endsGroup.getChildAt(pos1);
            } else if (endsGroup.getChildAt(pos2) instanceof ViewGroup &&
                    endsGroup.getChildAt(pos2) != mNavbarViewInfo[index].menuImeGroup) {
                mNavbarViewInfo[index].customKeyParent = (ViewGroup) endsGroup.getChildAt(pos2);
            }
            if (DEBUG) log("customKeyPlaceHolder=" + mNavbarViewInfo[index].customKeyPlaceHolder);

            // Add cursor control keys
            mNavbarViewInfo[index].endsGroup.addView(dpadLeft, 0);
            mNavbarViewInfo[index].endsGroup.addView(dpadRight, mNavbarViewInfo[index].endsGroup.getChildCount());

            // find menu key
            resId = mResources.getIdentifier("menu", "id", PACKAGE_NAME);
            if (resId != 0) {
                mNavbarViewInfo[index].menuKey = mNavbarViewInfo[index].endsGroup.findViewById(resId);
            }

            // find back key
            resId = mResources.getIdentifier("back", "id", PACKAGE_NAME);
            if (resId != 0) {
                mNavbarViewInfo[index].backKey = mNavbarViewInfo[index].endsGroup.findViewById(resId);
            }

            // find recent apps key
            resId = mResources.getIdentifier("recent_apps", "id", PACKAGE_NAME);
            if (resId != 0) {
                mNavbarViewInfo[index].recentsKey = mNavbarViewInfo[index].endsGroup.findViewById(resId);
            }

            // determine custom key layout
            Resources res = navButtons.getResources();
            boolean hasVerticalNavbar = mGbContext.getResources().getBoolean(R.bool.hasVerticalNavbar);
            final int sizeResId = res.getIdentifier(hasVerticalNavbar ?
                    "navigation_side_padding" : "navigation_extra_key_width", "dimen", PACKAGE_NAME);
            final int size = sizeResId == 0 ? 
                    (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
                    50, res.getDisplayMetrics()) :
                        res.getDimensionPixelSize(sizeResId);
            if (DEBUG) log("App key view minimum size=" + size);
            ViewGroup.LayoutParams lp;
            int w = (index == 1 && hasVerticalNavbar) ? ViewGroup.LayoutParams.MATCH_PARENT : size;
            int h = (index == 1 && hasVerticalNavbar) ? size : ViewGroup.LayoutParams.MATCH_PARENT;
            if (endsGroup instanceof RelativeLayout)
                lp = new RelativeLayout.LayoutParams(w, h);
            else if (endsGroup instanceof FrameLayout)
                lp = new FrameLayout.LayoutParams(w, h);
            else
                lp = new LinearLayout.LayoutParams(w, h, 0);
            if (DEBUG) log("appView: lpWidth=" + lp.width + "; lpHeight=" + lp.height);
            mNavbarViewInfo[index].customKey.setLayoutParams(lp);
            mNavbarViewInfo[index].dpadLeft.setLayoutParams(lp);
            mNavbarViewInfo[index].dpadRight.setLayoutParams(lp);
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error preparing NavbarViewInfo: ", t);
        }
    }

    private static void setCustomKeyVisibility() {
        try {
            final int disabledFlags = XposedHelpers.getIntField(mNavigationBarView, "mDisabledFlags");
            final boolean visible = mCustomKeyEnabled &&
                    !((disabledFlags & STATUS_BAR_DISABLE_RECENT) != 0);
            for (int i = 0; i < mNavbarViewInfo.length; i++) {
                if (mNavbarViewInfo[i] == null) continue;

                if (mNavbarViewInfo[i].customKeyVisible != visible) {
                    if (mNavbarViewInfo[i].customKeyPlaceHolder != null) {
                        int position = mNavbarViewInfo[i].customKeyParent.indexOfChild(
                                visible ? mNavbarViewInfo[i].customKeyPlaceHolder :
                                    mNavbarViewInfo[i].customKey);
                        mNavbarViewInfo[i].customKeyParent.removeViewAt(position);
                        mNavbarViewInfo[i].customKeyParent.addView(visible ?
                                mNavbarViewInfo[i].customKey : mNavbarViewInfo[i].customKeyPlaceHolder,
                                position);
                    } else {
                        if (visible) {
                            mNavbarViewInfo[i].customKeyParent.addView(mNavbarViewInfo[i].customKey, 0);
                        } else {
                            mNavbarViewInfo[i].customKeyParent.removeView(mNavbarViewInfo[i].customKey);
                        }
                    }
                    mNavbarViewInfo[i].customKeyVisible = visible;
                    if (DEBUG) log("setAppKeyVisibility: visible=" + visible);
                }

                // swap / unswap with menu key if necessary
                if ((!mCustomKeyEnabled || !mCustomKeySwapEnabled) && 
                        mNavbarViewInfo[i].menuCustomSwapped) {
                    swapMenuAndCustom(mNavbarViewInfo[i]);
                } else if (mCustomKeyEnabled && mCustomKeySwapEnabled && 
                        !mNavbarViewInfo[i].menuCustomSwapped) {
                    swapMenuAndCustom(mNavbarViewInfo[i]);
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error setting app key visibility: ", t);
        }
    }

    private static void setMenuKeyVisibility() {
        try {
            final boolean showMenu = XposedHelpers.getBooleanField(mNavigationBarView, "mShowMenu");
            final int disabledFlags = XposedHelpers.getIntField(mNavigationBarView, "mDisabledFlags");
            final boolean visible = (showMenu || mAlwaysShowMenukey) &&
                    !((disabledFlags & STATUS_BAR_DISABLE_RECENT) != 0);
            for (int i = 0; i < mNavbarViewInfo.length; i++) {
                if (mNavbarViewInfo[i] == null || mNavbarViewInfo[i].menuKey == null) continue;

                boolean isImeSwitcherVisible = mNavbarViewInfo[i].imeSwitcher != null &&
                        mNavbarViewInfo[i].imeSwitcher.getVisibility() == View.VISIBLE;
                mNavbarViewInfo[i].menuKey.setVisibility(
                        mDpadKeysVisible || isImeSwitcherVisible ? View.GONE :
                        visible ? View.VISIBLE : View.INVISIBLE);
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error setting menu key visibility:", t);
        }
    }

    private static void hideImeSwitcher() {
        for (int i = 0; i < mNavbarViewInfo.length; i++) {
            if (mNavbarViewInfo[i].imeSwitcher != null) {
                mNavbarViewInfo[i].imeSwitcher.setVisibility(View.GONE);
            }
        }
    }

    private static void setDpadKeyVisibility() {
        if (!mCursorControlEnabled) return;
        try {
            final int iconHints = XposedHelpers.getIntField(mNavigationBarView, "mNavigationIconHints");
            final int disabledFlags = XposedHelpers.getIntField(mNavigationBarView, "mDisabledFlags");
            final boolean visible = !((disabledFlags & STATUS_BAR_DISABLE_RECENT) != 0) && 
                    (iconHints & NAVIGATION_HINT_BACK_ALT) != 0;
            if (visible == mDpadKeysVisible)
                return;
            mDpadKeysVisible = visible;

            for (int i = 0; i < mNavbarViewInfo.length; i++) {
                // hide/unhide app key or whatever view at that position
                if (mNavbarViewInfo[i].customKeyParent != mNavbarViewInfo[i].endsGroup) {
                    mNavbarViewInfo[i].customKeyParent.setVisibility(
                            mDpadKeysVisible ? View.GONE : View.VISIBLE);
                } else {
                    int position = mNavbarViewInfo[i].customKeyParent.indexOfChild(
                            mNavbarViewInfo[i].customKey);
                    if (position == -1 && mNavbarViewInfo[i].customKeyPlaceHolder != null) {
                        position = mNavbarViewInfo[i].customKeyParent.indexOfChild(
                                mNavbarViewInfo[i].customKeyPlaceHolder);
                    }
                    if (position != -1) {
                        mNavbarViewInfo[i].customKeyParent.getChildAt(position).setVisibility(
                                mDpadKeysVisible ? View.GONE : View.VISIBLE);
                    }
                }
                // hide/unhide menu key
                if (mNavbarViewInfo[i].menuKey != null) {
                    if (mDpadKeysVisible) {
                        mNavbarViewInfo[i].menuKey .setVisibility(View.GONE);
                    } else {
                        setMenuKeyVisibility();
                    }
                }
                // Hide view group holding menu/customkey and ime switcher
                if (mNavbarViewInfo[i].menuImeGroup != null) {
                    mNavbarViewInfo[i].menuImeGroup.setVisibility(
                            mDpadKeysVisible ? View.GONE : View.VISIBLE);
                }
                mNavbarViewInfo[i].dpadLeft.setVisibility(mDpadKeysVisible ? View.VISIBLE : View.GONE);
                mNavbarViewInfo[i].dpadRight.setVisibility(mDpadKeysVisible ? View.VISIBLE : View.GONE);
                if (DEBUG) log("setDpadKeyVisibility: visible=" + mDpadKeysVisible);
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, "Error setting dpad key visibility: ", t);
        }
    }

    private static void updateRecentsKeyCode() {
        if (mNavbarViewInfo == null || Utils.isParanoidRom()) return;

        try {
            final boolean hasAction = recentsKeyHasAction();
            for (int i = 0; i < mNavbarViewInfo.length; i++) {
                if (mNavbarViewInfo[i].recentsKey != null) {
                    XposedHelpers.setIntField(mNavbarViewInfo[i].recentsKey,
                            "mCode", hasAction ? KeyEvent.KEYCODE_APP_SWITCH : 0);
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static boolean recentsKeyHasAction() {
        return (mRecentsSingletapAction.actionId != 0 ||
                mRecentsLongpressAction.actionId != 0 ||
                mRecentsDoubletapAction.actionId != 0 ||
                !mHwKeysEnabled);
    }

    private static void setKeyColor() {
        try {
            View v = (View) XposedHelpers.getObjectField(mNavigationBarView, "mCurrentView");
            ViewGroup navButtons = (ViewGroup) v.findViewById(
                    mResources.getIdentifier("nav_buttons", "id", PACKAGE_NAME));
            setKeyColorRecursive(navButtons);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static void setKeyColorRecursive(ViewGroup vg) {
        if (vg == null) return;
        final int childCount = vg.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = vg.getChildAt(i);
            if (child instanceof ViewGroup) {
                setKeyColorRecursive((ViewGroup) child);
            } else if (child instanceof ImageView) {
                ImageView imgv = (ImageView)vg.getChildAt(i);
                if (mNavbarColorsEnabled) {
                    imgv.setColorFilter(mKeyColor, PorterDuff.Mode.SRC_ATOP);
                } else {
                    imgv.clearColorFilter();
                }
                if (imgv.getClass().getName().equals(CLASS_KEY_BUTTON_VIEW) &&
                    !mNavbarColorsEnabled) {
                    Drawable ripple = imgv.getBackground();
                    if (ripple != null && 
                            ripple.getClass().getName().equals(CLASS_KEY_BUTTON_RIPPLE)) {
                        Paint paint = (Paint)XposedHelpers.getObjectField(ripple, "mRipplePaint");
                        if (paint != null) {
                            paint.setColor(0xffffffff);
                        }
                    }
                } else if (imgv instanceof KeyButtonView) {
                    ((KeyButtonView) imgv).setGlowColor(mNavbarColorsEnabled ?
                            mKeyGlowColor : mKeyDefaultGlowColor);
                }
            }
        }
    }

    private static void swapBackAndRecents() {
        try {
            for (int i = 0; i < mNavbarViewInfo.length; i++) {
                if (mNavbarViewInfo[i].endsGroup == null ||
                        mNavbarViewInfo[i].recentsKey == null ||
                        mNavbarViewInfo[i].backKey == null) continue;

                View backKey = mNavbarViewInfo[i].backKey;
                View recentsKey = mNavbarViewInfo[i].recentsKey;
                int backPos = mNavbarViewInfo[i].endsGroup.indexOfChild(backKey);
                int recentsPos = mNavbarViewInfo[i].endsGroup.indexOfChild(recentsKey);
                mNavbarViewInfo[i].endsGroup.removeView(backKey);
                mNavbarViewInfo[i].endsGroup.removeView(recentsKey);
                if (backPos < recentsPos) {
                    mNavbarViewInfo[i].endsGroup.addView(recentsKey, backPos);
                    mNavbarViewInfo[i].endsGroup.addView(backKey, recentsPos);
                } else {
                    mNavbarViewInfo[i].endsGroup.addView(backKey, recentsPos);
                    mNavbarViewInfo[i].endsGroup.addView(recentsKey, backPos);
                }
            }
        }
        catch (Throwable t) {
            GravityBox.log(TAG, "Error swapping back and recents key: ", t);
        }
    }

    private static void swapMenuAndCustom(NavbarViewInfo nvi) {
        if (!nvi.customKey.isAttachedToWindow() || nvi.menuImeGroup == null) return;

        try {
            View menuImeGroup = nvi.menuImeGroup;
            View customKey = (nvi.endsGroup != nvi.customKeyParent) ? nvi.customKeyParent : nvi.customKey;
            int menuImePos = nvi.endsGroup.indexOfChild(menuImeGroup);
            int customKeyPos = nvi.endsGroup.indexOfChild(customKey);
            nvi.endsGroup.removeView(menuImeGroup);
            nvi.endsGroup.removeView(customKey);
            if (menuImePos < customKeyPos) {
                nvi.endsGroup.addView(customKey, menuImePos);
                nvi.endsGroup.addView(menuImeGroup, customKeyPos);
            } else {
                nvi.endsGroup.addView(menuImeGroup, customKeyPos);
                nvi.endsGroup.addView(customKey, menuImePos);
            }
            nvi.menuCustomSwapped = !nvi.menuCustomSwapped;
            if (DEBUG) log("swapMenuAndCustom: swapped=" + nvi.menuCustomSwapped);
        }
        catch (Throwable t) {
            GravityBox.log(TAG, "Error swapping menu and custom key: ", t);
        }
    }

    private static void updateCustomKeyIcon() {
        try {
            for (NavbarViewInfo nvi : mNavbarViewInfo) {
                nvi.customKey.setImageDrawable(getCustomKeyIconDrawable());
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static Drawable getCustomKeyIconDrawable() {
        switch (mCustomKeyIconStyle) {
            case CUSTOM:
                File f = new File(mGbContext.getFilesDir() + "/navbar_custom_key_image");
                if (f.exists() && f.canRead()) {
                    Bitmap b = BitmapFactory.decodeFile(f.getAbsolutePath());
                    if (b != null) {
                        return new BitmapDrawable(mResources, b);
                    }
                }
                // fall through to transparent if custom not available
            case TRANSPARENT:
                Drawable d = mGbContext.getDrawable(R.drawable.ic_sysbar_apps);
                Drawable transD = new ColorDrawable(Color.TRANSPARENT);
                transD.setBounds(0, 0, d.getMinimumWidth(), d.getMinimumHeight());
                return transD;
            case THREE_DOT: 
                return mGbContext.getDrawable(R.drawable.ic_sysbar_apps2);
            case SIX_DOT:
            default:
                return mGbContext.getDrawable(R.drawable.ic_sysbar_apps);
        }
    }

    private static ScaleType getIconScaleType(int index, int keyId) {
        ScaleType origScaleType = mNavbarViewInfo[index] == null ? ScaleType.CENTER :
                mNavbarViewInfo[index].originalScaleType.get(keyId, ScaleType.CENTER);
        if (index == 0) {
            return (mNavbarHeight < 75 ? ScaleType.CENTER_INSIDE : origScaleType);
        } else {
            boolean hasVerticalNavbar = mGbContext.getResources().getBoolean(R.bool.hasVerticalNavbar);
            return (mNavbarWidth < 75 && hasVerticalNavbar ? ScaleType.CENTER_INSIDE :
                origScaleType);
        }
    }

    private static int[] getIconPaddingPx(int index) {
        int[] p = new int[] { 0, 0, 0, 0 };
        int paddingPx = Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 5,
                mResources.getDisplayMetrics()));
        boolean hasVerticalNavbar = mGbContext.getResources().getBoolean(R.bool.hasVerticalNavbar);
        if (index == 0 && mNavbarHeight < 75) {
            p[1] = paddingPx;
            p[3] = paddingPx;
        }
        if (index == 1 && hasVerticalNavbar && mNavbarWidth < 75) {
            p[0] = paddingPx;
            p[2] = paddingPx;
        }
        return p;
    }

    private static void updateIconScaleType() {
        try {
            for (int i = 0; i < mNavbarViewInfo.length; i++) {
                int [] paddingPx = getIconPaddingPx(i);
                ViewGroup[] groups =  mNavbarViewInfo[i].endsGroup == mNavbarViewInfo[i].customKeyParent ?
                        new ViewGroup[] {
                                mNavbarViewInfo[i].endsGroup,
                                mNavbarViewInfo[i].centerGroup,
                                mNavbarViewInfo[i].menuImeGroup } :
                        new ViewGroup[] {
                                mNavbarViewInfo[i].endsGroup,
                                mNavbarViewInfo[i].centerGroup,
                                mNavbarViewInfo[i].menuImeGroup,
                                mNavbarViewInfo[i].customKeyParent };
                for (ViewGroup group : groups) {
                    if (group == null) continue;
                    int childCount = group.getChildCount();
                    for (int j = 0; j < childCount; j++) {
                        View child = group.getChildAt(j);
                        if (child.getClass().getName().equals(CLASS_KEY_BUTTON_VIEW) ||
                                child instanceof KeyButtonView) {
                            ImageView iv = (ImageView) child;
                            if (iv.getId() != View.NO_ID &&
                                    mNavbarViewInfo[i].originalScaleType.get(iv.getId()) == null) {
                                mNavbarViewInfo[i].originalScaleType.put(iv.getId(),
                                        iv.getScaleType());
                            }
                            iv.setScaleType(getIconScaleType(i, iv.getId()));
                            if (!Utils.isXperiaDevice()) {
                                iv.setPadding(paddingPx[0], paddingPx[1], paddingPx[2], paddingPx[3]);
                            }
                        }
                    }
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, "updateIconScaleType: ", t);
        }
    }
}

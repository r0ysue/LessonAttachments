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

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Handler;
import android.text.format.Formatter;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.ceco.nougat.gravitybox.R;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodHook.Unhook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class ModClearAllRecents {
    private static final String TAG = "GB:ModClearAllRecents";
    public static final String PACKAGE_NAME = "com.android.systemui";
    public static final String CLASS_RECENT_VIEW = "com.android.systemui.recents.views.RecentsView";
    public static final String CLASS_RECENT_ACTIVITY = "com.android.systemui.recents.RecentsActivity";
    public static final String CLASS_TASK_STACK = "com.android.systemui.recents.model.TaskStack";
    public static final String CLASS_TASK_STACK_VIEW = "com.android.systemui.recents.views.TaskStackView";
    public static final String CLASS_ANIMATION_PROPS = "com.android.systemui.recents.views.AnimationProps";
    public static final String CLASS_EVENT_BUS = "com.android.systemui.recents.events.EventBus";
    public static final String CLASS_SHOW_STACK_ACTION_BUTTON_EVENT = "com.android.systemui.recents.events.activity.ShowStackActionButtonEvent";

    private static final boolean DEBUG = false;

    private static int mMarginTopPx;
    private static int mMarginBottomPx;
    private static ViewGroup mRecentsView;
    private static Interpolator mExitAnimInterpolator;
    private static int mExitAnimDuration;
    private static Activity mRecentsActivity;
    private static boolean mClearAlwaysVisible;
    private static Unhook mEventBusSendHook;

    // RAM bar
    private static TextView mBackgroundProcessText;
    private static TextView mForegroundProcessText;
    private static ActivityManager mAm;
    private static MemInfoReader mMemInfoReader;
    private static Context mGbContext;
    private static LinearColorBar mRamUsageBar;
    private static int mRamBarGravity;
    private static Handler mHandler;
    private static int[] mRamUsageBarPaddings;
    private static int mRamUsageBarVerticalMargin;
    private static int mRamUsageBarHorizontalMargin;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    private static BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (DEBUG) log("Broadcast received: " + intent.toString());
            if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_RECENTS_CHANGED)) {
                if (intent.hasExtra(GravityBoxSettings.EXTRA_RECENTS_CLEAR_ALWAYS_VISIBLE)) {
                    mClearAlwaysVisible = intent.getBooleanExtra(
                            GravityBoxSettings.EXTRA_RECENTS_CLEAR_ALWAYS_VISIBLE, false);
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_RECENTS_RAMBAR)) {
                    mRamBarGravity = intent.getIntExtra(GravityBoxSettings.EXTRA_RECENTS_RAMBAR, 0);
                    updateRamBarLayout();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_RECENTS_MARGIN_TOP)) {
                    mMarginTopPx = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
                            intent.getIntExtra(GravityBoxSettings.EXTRA_RECENTS_MARGIN_TOP, 77),
                            context.getResources().getDisplayMetrics());
                    updateRamBarLayout();
                }
                if (intent.hasExtra(GravityBoxSettings.EXTRA_RECENTS_MARGIN_BOTTOM)) {
                    mMarginBottomPx = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
                            intent.getIntExtra(GravityBoxSettings.EXTRA_RECENTS_MARGIN_BOTTOM, 50),
                            context.getResources().getDisplayMetrics());
                    updateRamBarLayout();
                }
            }
        }
    };

    public static void init(final XSharedPreferences prefs, final ClassLoader classLoader) {
        try {
            Class<?> recentActivityClass = XposedHelpers.findClass(CLASS_RECENT_ACTIVITY, classLoader);

            mRamBarGravity = Integer.valueOf(prefs.getString(GravityBoxSettings.PREF_KEY_RAMBAR, "0"));
            mMemInfoReader = new MemInfoReader();

            XposedHelpers.findAndHookMethod(recentActivityClass, "onCreate", Bundle.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(final MethodHookParam param) throws Throwable {
                    mRecentsActivity = (Activity) param.thisObject;
                    mGbContext = Utils.getGbContext(mRecentsActivity);
                    mHandler = new Handler();
                    mAm = (ActivityManager) mRecentsActivity.getSystemService(Context.ACTIVITY_SERVICE);
                    mRecentsView = (ViewGroup) XposedHelpers.getObjectField(param.thisObject, "mRecentsView");

                    final Resources res = mRecentsActivity.getResources();

                    mClearAlwaysVisible = prefs.getBoolean(
                            GravityBoxSettings.PREF_KEY_RECENT_CLEAR_ALWAYS_VISIBLE, false);

                    mMarginTopPx = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 
                            prefs.getInt(GravityBoxSettings.PREF_KEY_RECENTS_CLEAR_MARGIN_TOP, 77), 
                            res.getDisplayMetrics());
                    mMarginBottomPx = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 
                            prefs.getInt(GravityBoxSettings.PREF_KEY_RECENTS_CLEAR_MARGIN_BOTTOM, 50), 
                            res.getDisplayMetrics());

                    mRamUsageBarPaddings = new int[4];
                    mRamUsageBarPaddings[0] = mRamUsageBarPaddings[2] = (int) TypedValue.applyDimension(
                            TypedValue.COMPLEX_UNIT_DIP, 4, res.getDisplayMetrics());
                    mRamUsageBarPaddings[1] = mRamUsageBarPaddings[3] = (int) TypedValue.applyDimension(
                            TypedValue.COMPLEX_UNIT_DIP, 1, res.getDisplayMetrics());
                    mRamUsageBarVerticalMargin = (int) TypedValue.applyDimension(
                            TypedValue.COMPLEX_UNIT_DIP, 15, res.getDisplayMetrics());
                    mRamUsageBarHorizontalMargin = (int) TypedValue.applyDimension(
                            TypedValue.COMPLEX_UNIT_DIP, 10, res.getDisplayMetrics());

                    FrameLayout vg = (FrameLayout) mRecentsActivity.getWindow().getDecorView()
                            .findViewById(android.R.id.content);

                    // create and inject RAM bar
                    mRamUsageBar = new LinearColorBar(vg.getContext(), null);
                    mRamUsageBar.setOrientation(LinearLayout.HORIZONTAL);
                    mRamUsageBar.setClipChildren(false);
                    mRamUsageBar.setClipToPadding(false);
                    mRamUsageBar.setPadding(mRamUsageBarPaddings[0], mRamUsageBarPaddings[1],
                            mRamUsageBarPaddings[2], mRamUsageBarPaddings[3]);
                    FrameLayout.LayoutParams flp = new FrameLayout.LayoutParams(
                            FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT);
                    mRamUsageBar.setLayoutParams(flp);
                    LayoutInflater inflater = LayoutInflater.from(mGbContext);
                    inflater.inflate(R.layout.linear_color_bar, mRamUsageBar, true);
                    vg.addView(mRamUsageBar);
                    mForegroundProcessText = (TextView) mRamUsageBar.findViewById(R.id.foregroundText);
                    mBackgroundProcessText = (TextView) mRamUsageBar.findViewById(R.id.backgroundText);
                    mRamUsageBar.setVisibility(View.GONE);
                    updateRamBarLayout();
                    if (DEBUG) log("RAM bar injected");

                    IntentFilter intentFilter = new IntentFilter();
                    intentFilter.addAction(GravityBoxSettings.ACTION_PREF_RECENTS_CHANGED);
                    mRecentsActivity.registerReceiver(mBroadcastReceiver, intentFilter);
                    if (DEBUG) log("Recents panel view constructed");
                }
            });

            XposedHelpers.findAndHookMethod(recentActivityClass, "onDestroy", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
                    ((Activity)param.thisObject).unregisterReceiver(mBroadcastReceiver);
                }
            });

            XposedHelpers.findAndHookMethod(Activity.class, "onResume", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(final MethodHookParam param) throws Throwable {
                    if (param.thisObject != mRecentsActivity) return;

                    if (mRamUsageBar != null) {
                        if (mRamBarGravity != 0) {
                            mRamUsageBar.setVisibility(View.VISIBLE);
                            updateRamBarLayout();
                            updateRamBarMemoryUsage();
                        } else {
                            mRamUsageBar.setVisibility(View.GONE);
                        }
                    }
                }
            });

            // When to update RAM bar values
            XposedBridge.hookAllMethods(XposedHelpers.findClass(CLASS_TASK_STACK, classLoader),
                    "removeTaskImpl", updateRambarHook);

            XposedHelpers.findAndHookMethod(recentActivityClass, "dismissRecentsToHome",
                    boolean.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
                    if ((boolean)param.args[0] && mRamUsageBar != null &&
                            mRamUsageBar.getVisibility() == View.VISIBLE) {
                        performExitAnimation(mRamUsageBar);
                    }
                }
            });

            if (!Utils.isOxygenOsRom()) {
                XposedHelpers.findAndHookMethod(CLASS_TASK_STACK_VIEW, classLoader,
                        "onFirstLayout", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
                        if (mClearAlwaysVisible && getTaskCount(param.thisObject) > 0) {
                            mEventBusSendHook = XposedHelpers.findAndHookMethod(CLASS_EVENT_BUS, classLoader,
                                    "send", CLASS_EVENT_BUS+".Event", new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(final MethodHookParam param2) throws Throwable {
                                    if (param2.args[0] != null && param2.args[0].getClass().getName().endsWith(
                                            "StackActionButtonEvent")) {
                                        param2.setResult(null);
                                    }
                                }
                            });
                        }
                    }
                    @Override
                    protected void afterHookedMethod(final MethodHookParam param) throws Throwable {
                        if (mEventBusSendHook != null) {
                            mEventBusSendHook.unhook();
                            mEventBusSendHook = null;
                            sendShowActionButtonEvent(classLoader);
                        }
                    }
                });
                XposedHelpers.findAndHookMethod(CLASS_TASK_STACK_VIEW, classLoader,
                        "onStackScrollChanged", float.class, float.class,
                        CLASS_ANIMATION_PROPS, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(final MethodHookParam param) throws Throwable {
                        if (mClearAlwaysVisible) {
                            Object uiDozeTrigger = XposedHelpers.getObjectField(param.thisObject, "mUIDozeTrigger");
                            XposedHelpers.callMethod(uiDozeTrigger, "poke");
                            if (param.args[2] != null) {
                                XposedHelpers.callMethod(param.thisObject,
                                        "relayoutTaskViewsOnNextFrame", param.args[2]);
                            }
                            param.setResult(null);
                        }
                    }
                });
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    private static int getTaskCount(Object taskView) throws Throwable {
        final Object stack = XposedHelpers.getObjectField(taskView, "mStack");
        return (int) XposedHelpers.callMethod(stack, "getTaskCount");
    }

    private static void sendShowActionButtonEvent(ClassLoader cl) throws Throwable {
        final Object eb = XposedHelpers.callStaticMethod(XposedHelpers.findClass(
                CLASS_EVENT_BUS, cl), "getDefault");
        XposedHelpers.callMethod(eb, "send",
                XposedHelpers.findConstructorExact(CLASS_SHOW_STACK_ACTION_BUTTON_EVENT,
                        cl, boolean.class).newInstance(true));
    }

    private static void performExitAnimation(final View view) {
        try {
            if (mExitAnimInterpolator == null) {
                Object config = XposedHelpers.getObjectField(mRecentsView, "mConfig");
                mExitAnimInterpolator = (Interpolator) XposedHelpers.getObjectField(
                        config, "fastOutSlowInInterpolator");
                mExitAnimDuration = XposedHelpers.getIntField(config, "taskViewRemoveAnimDuration");
            }
            view.animate()
            .alpha(0f)
            .setInterpolator(mExitAnimInterpolator)
            .setDuration(mExitAnimDuration)
            .withEndAction(new Runnable() {
                @Override
                public void run() {
                    view.setVisibility(View.GONE);
                    view.setAlpha(1f);
                }
            })
            .start();
        } catch (Throwable t) {
            // don't need to be loud about it
        }
    }

    private static XC_MethodHook updateRambarHook = new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(final MethodHookParam param) throws Throwable {
            updateRamBarMemoryUsage();
        }
    };

    @SuppressLint("RtlHardcoded")
    private static void updateRamBarLayout() {
        if (mRamUsageBar == null || mRamBarGravity == 0) return;

        final Context context = mRamUsageBar.getContext();
        final Resources res = mRamUsageBar.getResources();
        final int orientation = res.getConfiguration().orientation;
        final boolean rbOnTop = (mRamBarGravity == Gravity.TOP);
        final int marginTop = rbOnTop ? mMarginTopPx : 0;
        final int marginBottom = (!rbOnTop && (orientation == Configuration.ORIENTATION_PORTRAIT ||
                                                !Utils.isPhoneUI(context))) ? mMarginBottomPx : 0;
        final int marginLeft = orientation == Configuration.ORIENTATION_LANDSCAPE && 
                Utils.isPhoneUI(context) ? mMarginBottomPx : 0;
        final int marginRight = orientation == Configuration.ORIENTATION_LANDSCAPE && 
                Utils.isPhoneUI(context) ? mMarginBottomPx : 0;

        FrameLayout.LayoutParams flp = (FrameLayout.LayoutParams) mRamUsageBar.getLayoutParams();
        flp.gravity = mRamBarGravity;
        flp.setMargins(mRamUsageBarHorizontalMargin + marginLeft, 
            rbOnTop ? (mRamUsageBarVerticalMargin + marginTop) : 0, 
            mRamUsageBarHorizontalMargin + marginRight, 
            rbOnTop ? 0 : (mRamUsageBarVerticalMargin + marginBottom)
        );
        mRamUsageBar.setLayoutParams(flp);
        if (DEBUG) log("RAM bar layout updated");
    }

    private static void updateRamBarMemoryUsage() {
        if (mRamUsageBar != null && mRamBarGravity != 0 && mHandler != null) {
            mHandler.post(updateRamBarTask);
        }
    }

    private static final Runnable updateRamBarTask = new Runnable() {
        @Override
        public void run() {
            if (mRamUsageBar == null || mRamUsageBar.getVisibility() == View.GONE) {
                return;
            }

            ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
            mAm.getMemoryInfo(memInfo);
            long secServerMem = 0;//XposedHelpers.getLongField(memInfo, "secondaryServerThreshold");
            mMemInfoReader.readMemInfo();
            long availMem = mMemInfoReader.getFreeSize() + mMemInfoReader.getCachedSize() -
                    secServerMem;
            long totalMem = mMemInfoReader.getTotalSize();

            String sizeStr = Formatter.formatShortFileSize(mGbContext, totalMem-availMem);
            mForegroundProcessText.setText(mGbContext.getResources().getString(
                    R.string.service_foreground_processes, sizeStr));
            sizeStr = Formatter.formatShortFileSize(mGbContext, availMem);
            mBackgroundProcessText.setText(mGbContext.getResources().getString(
                    R.string.service_background_processes, sizeStr));

            float fTotalMem = totalMem;
            float fAvailMem = availMem;
            mRamUsageBar.setRatios((fTotalMem - fAvailMem) / fTotalMem, 0, 0);
            if (DEBUG) log("RAM bar values updated");
        }
    };
}

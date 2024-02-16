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

package com.ceco.nougat.gravitybox.pie;

import java.util.HashMap;
import java.util.Map;

import com.ceco.nougat.gravitybox.GravityBox;
import com.ceco.nougat.gravitybox.GravityBoxSettings;
import com.ceco.nougat.gravitybox.ModHwKeys;
import com.ceco.nougat.gravitybox.ModLauncher;
import com.ceco.nougat.gravitybox.ModStatusBar;
import com.ceco.nougat.gravitybox.ScreenRecordingService;
import com.ceco.nougat.gravitybox.managers.SysUiManagers;
import com.ceco.nougat.gravitybox.pie.PieController.ButtonType;
import com.ceco.nougat.gravitybox.shortcuts.AShortcut;

import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.view.HapticFeedbackConstants;

public class PieLongPressHandler implements PieItem.PieOnLongPressListener {
    private static final String TAG = "GB:PieLongPressHandler";
    private static final boolean DEBUG = false;

    private Context mContext;
    private Map<ButtonType,ModHwKeys.HwKeyAction> mActions;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    public PieLongPressHandler(Context context, XSharedPreferences prefs) {
        mContext = context;

        mActions = new HashMap<ButtonType, ModHwKeys.HwKeyAction>();
        mActions.put(ButtonType.BACK, new ModHwKeys.HwKeyAction(Integer.valueOf(
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_BACK_LONGPRESS, "0")),
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_BACK_LONGPRESS+"_custom", null)));
        mActions.put(ButtonType.HOME, new ModHwKeys.HwKeyAction(Integer.valueOf(
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_HOME_LONGPRESS, "0")),
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_HOME_LONGPRESS+"_custom", null)));
        mActions.put(ButtonType.RECENT, new ModHwKeys.HwKeyAction(Integer.valueOf(
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_RECENTS_LONGPRESS, "0")),
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_RECENTS_LONGPRESS+"_custom", null)));
        mActions.put(ButtonType.SEARCH, new ModHwKeys.HwKeyAction(Integer.valueOf(
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_SEARCH_LONGPRESS, "0")),
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_SEARCH_LONGPRESS+"_custom", null)));
        mActions.put(ButtonType.MENU, new ModHwKeys.HwKeyAction(Integer.valueOf(
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_MENU_LONGPRESS, "0")),
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_MENU_LONGPRESS+"_custom", null)));
        mActions.put(ButtonType.APP_LAUNCHER, new ModHwKeys.HwKeyAction(Integer.valueOf(
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_APP_LONGPRESS, "0")),
                prefs.getString(GravityBoxSettings.PREF_KEY_PIE_APP_LONGPRESS+"_custom", null)));
    }

    @Override
    public boolean onLongPress(PieItem item) {
        if (DEBUG) log("onLongPress: " + ((ButtonType) item.tag));
        if (performActionFor((ButtonType)item.tag)) {
            item.getLayout().performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
            return true;
        }
        return false;
    }

    protected void setLongPressAction(String button, int action, String customApp) {
        if (button == null) return;

        ButtonType btnType = ButtonType.valueOf(button);
        if (btnType != null && mActions.containsKey(btnType)) {
            mActions.get(btnType).actionId = action;
            mActions.get(btnType).customApp = customApp;
            if (DEBUG) log("Action for " + btnType + ": " + action);
        }
    }

    protected ModHwKeys.HwKeyAction getLongPressAction(ButtonType buttonType) {
        if (buttonType == null) return new ModHwKeys.HwKeyAction(0, null);

        if (mActions.containsKey(buttonType)) {
            return mActions.get(buttonType);
        }
        return new ModHwKeys.HwKeyAction(0, null);
    }

    private boolean performActionFor(ButtonType btnType) {
        if (btnType == ButtonType.BACK && isTaskLocked()) {
            unlockTask();
            return true;
        }

        Intent intent = null;
        switch(mActions.get(btnType).actionId) {
            case GravityBoxSettings.HWKEY_ACTION_SEARCH:
                intent = new Intent(ModHwKeys.ACTION_SEARCH); 
                break;
            case GravityBoxSettings.HWKEY_ACTION_VOICE_SEARCH:
                intent = new Intent(ModHwKeys.ACTION_VOICE_SEARCH);
                break;
            case GravityBoxSettings.HWKEY_ACTION_PREV_APP:
                intent = new Intent(ModHwKeys.ACTION_SWITCH_PREVIOUS_APP);
                break;
            case GravityBoxSettings.HWKEY_ACTION_KILL:
                intent = new Intent(ModHwKeys.ACTION_KILL_FOREGROUND_APP);
                break;
            case GravityBoxSettings.HWKEY_ACTION_SLEEP:
                intent = new Intent(ModHwKeys.ACTION_SLEEP);
                break;
            case GravityBoxSettings.HWKEY_ACTION_APP_LAUNCHER:
                if (SysUiManagers.AppLauncher != null) {
                    SysUiManagers.AppLauncher.showDialog();
                }
                break;
            case GravityBoxSettings.HWKEY_ACTION_CUSTOM_APP:
                intent = new Intent(ModHwKeys.ACTION_LAUNCH_APP);
                intent.putExtra(GravityBoxSettings.EXTRA_HWKEY_CUSTOM_APP, mActions.get(btnType).customApp);
                break;
            case GravityBoxSettings.HWKEY_ACTION_EXPANDED_DESKTOP:
                intent = new Intent(ModHwKeys.ACTION_TOGGLE_EXPANDED_DESKTOP);
                break;
            case GravityBoxSettings.HWKEY_ACTION_TORCH:
                intent = new Intent(ModHwKeys.ACTION_TOGGLE_TORCH);
                break;
            case GravityBoxSettings.HWKEY_ACTION_SCREEN_RECORDING:
                intent = new Intent(ScreenRecordingService.ACTION_TOGGLE_SCREEN_RECORDING);
                break;
            case GravityBoxSettings.HWKEY_ACTION_AUTO_ROTATION:
                intent = new Intent(ModHwKeys.ACTION_TOGGLE_ROTATION_LOCK);
                break;
            case GravityBoxSettings.HWKEY_ACTION_SHOW_POWER_MENU:
                intent = new Intent(ModHwKeys.ACTION_SHOW_POWER_MENU);
                break;
            case GravityBoxSettings.HWKEY_ACTION_EXPAND_NOTIFICATIONS:
                intent = new Intent(ModStatusBar.ACTION_EXPAND_NOTIFICATIONS);
                intent.putExtra(AShortcut.EXTRA_ENABLE, true);
                break;
            case GravityBoxSettings.HWKEY_ACTION_EXPAND_QUICKSETTINGS:
                intent = new Intent(ModStatusBar.ACTION_EXPAND_QUICKSETTINGS);
                intent.putExtra(AShortcut.EXTRA_ENABLE, true);
                break;
            case GravityBoxSettings.HWKEY_ACTION_SCREENSHOT:
                intent = new Intent(ModHwKeys.ACTION_SCREENSHOT);
                break;
            case GravityBoxSettings.HWKEY_ACTION_VOLUME_PANEL:
                intent = new Intent(ModHwKeys.ACTION_SHOW_VOLUME_PANEL);
                break;
            case GravityBoxSettings.HWKEY_ACTION_LAUNCHER_DRAWER:
                intent = new Intent(ModLauncher.ACTION_SHOW_APP_DRAWER);
                break;
            case GravityBoxSettings.HWKEY_ACTION_INAPP_SEARCH:
                intent = new Intent(ModHwKeys.ACTION_INAPP_SEARCH);
                break;
            case GravityBoxSettings.HWKEY_ACTION_SPLIT_SCREEN:
                intent = new Intent(ModHwKeys.ACTION_TOGGLE_SPLIT_SCREEN);
                break;
            case GravityBoxSettings.HWKEY_ACTION_DEFAULT:
            default: return false;
        }

        if (intent != null) {
            if (DEBUG) log("Sending broadcast: " + intent);
            mContext.sendBroadcast(intent);
        }

        return true;
    }

    private boolean isTaskLocked() {
        ActivityManager am = (ActivityManager) mContext.getSystemService(Context.ACTIVITY_SERVICE);
        return (am.getLockTaskModeState() != ActivityManager.LOCK_TASK_MODE_NONE);
    }

    private void unlockTask() {
        try {
            Class<?> amnClass = XposedHelpers.findClass("android.app.ActivityManagerNative",
                    mContext.getClassLoader());
            Object amn = XposedHelpers.callStaticMethod(amnClass, "getDefault");
            XposedHelpers.callMethod(amn, "stopLockTaskMode");
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }
}

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

import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedHelpers;

import com.ceco.nougat.gravitybox.GravityBoxSettings;
import com.ceco.nougat.gravitybox.managers.SysUiManagers;
import com.ceco.nougat.gravitybox.managers.BatteryInfoManager.BatteryData;
import com.ceco.nougat.gravitybox.managers.BatteryInfoManager.BatteryStatusListener;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;

public class BatteryTile extends AospTile {
    public static final String AOSP_KEY = "battery";

    private boolean mIsReceiving;
    private BatteryData mBatteryData;
    private String mTempUnit;
    private boolean mShowTemp;
    private boolean mShowVoltage;

    public BatteryTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);
    }

    private BatteryStatusListener mBatteryStatusListener = new BatteryStatusListener() {
        @Override
        public void onBatteryStatusChanged(BatteryData batteryData) {
            mBatteryData = batteryData;
            if (DEBUG) log("mBatteryData=" + mBatteryData.toString());
            refreshState();
        }
    };

    private void registerReceiver() {
        if (mIsReceiving) return;
        if (SysUiManagers.BatteryInfoManager != null) {
            SysUiManagers.BatteryInfoManager.registerListener(mBatteryStatusListener);
            if (DEBUG) log(getKey() + ": registerReceiver: battery status listener registered");
        }
        mIsReceiving = true;
    }

    private void unregisterReceiver() {
        if (mIsReceiving) {
            if (SysUiManagers.BatteryInfoManager != null) {
                SysUiManagers.BatteryInfoManager.unregisterListener(mBatteryStatusListener);
                if (DEBUG) log(getKey() + ": unregisterReceiver: battery status listener unregistered");
            }
            mIsReceiving = false;
        }
    }

    @Override
    public String getSettingsKey() {
        return "aosp_tile_battery";
    }

    @Override
    protected void initPreferences() {
        super.initPreferences();

        mTempUnit = mPrefs.getString(GravityBoxSettings.PREF_KEY_BATTERY_TILE_TEMP_UNIT, "C");
        mShowTemp = mPrefs.getBoolean(GravityBoxSettings.PREF_KEY_BATTERY_TILE_TEMP, true);
        mShowVoltage = mPrefs.getBoolean(GravityBoxSettings.PREF_KEY_BATTERY_TILE_VOLTAGE, true);
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        super.onBroadcastReceived(context, intent);

        if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_QUICKSETTINGS_CHANGED)) {
            if (intent.hasExtra(GravityBoxSettings.EXTRA_BATTERY_TILE_TEMP_UNIT)) {
                mTempUnit = intent.getStringExtra(
                        GravityBoxSettings.EXTRA_BATTERY_TILE_TEMP_UNIT);
            }
            if (intent.hasExtra(GravityBoxSettings.EXTRA_BATTERY_TILE_TEMP)) {
                mShowTemp = intent.getBooleanExtra(
                        GravityBoxSettings.EXTRA_BATTERY_TILE_TEMP, true);
            }
            if (intent.hasExtra(GravityBoxSettings.EXTRA_BATTERY_TILE_VOLTAGE)) {
                mShowVoltage = intent.getBooleanExtra(
                        GravityBoxSettings.EXTRA_BATTERY_TILE_VOLTAGE, true);
            }
        }
    }

    @Override
    public boolean supportsHideOnChange() {
        return false;
    }

    @Override
    public void setListening(boolean listening) {
        if (listening) {
            registerReceiver();
        } else {
            unregisterReceiver();
        }
    }

    @SuppressLint("DefaultLocale")
    @Override
    public void handleUpdateState(Object state, Object arg) {
        String label = (String) XposedHelpers.getObjectField(state, "label");
        if (label == null)
            return;

        if (mBatteryData == null) {
            if (DEBUG) log(getKey() + ": handleUpdateState: battery data is null");
        } else {
            if (mShowTemp && mShowVoltage) {
                label = String.format("%s, %.1f\u00b0%s, %dmV", label,
                        mBatteryData.getTemp(mTempUnit), mTempUnit, mBatteryData.voltage);
            } else if (mShowTemp) {
                label = String.format("%s, %.1f\u00b0%s", label,
                        mBatteryData.getTemp(mTempUnit), mTempUnit);
            } else if (mShowVoltage) {
                label = String.format("%s, %dmV", label, mBatteryData.voltage);
            }
        }
        XposedHelpers.setObjectField(state, "label", label);
        super.handleUpdateState(state, arg);
    }

    @Override
    public void handleDestroy() {
        super.handleDestroy();
        mBatteryStatusListener = null;
        mBatteryData = null;
    }
}

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

import com.ceco.nougat.gravitybox.GravityBoxSettings;
import android.content.Context;
import android.content.Intent;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedHelpers;

public class WifiTile extends AospTile {
    public static final String AOSP_KEY = "wifi";

    private boolean mQuickMode;
    private boolean mClickOverrideBlocked;

    protected WifiTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);
    }

    @Override
    public void initPreferences() {
        mQuickMode = mPrefs.getBoolean(GravityBoxSettings.PREF_KEY_WIFI_TILE_QUICK_MODE, false);
        super.initPreferences();
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_QUICKSETTINGS_CHANGED)) {
            if (intent.hasExtra(GravityBoxSettings.EXTRA_WIFI_TILE_QUICK_MODE)) {
                mQuickMode = intent.getBooleanExtra(GravityBoxSettings.EXTRA_WIFI_TILE_QUICK_MODE, false);
            }
        }
        super.onBroadcastReceived(context, intent);
    }

    @Override
    public boolean supportsHideOnChange() {
        return mQuickMode;
    }

    @Override
    public String getSettingsKey() {
        return "aosp_tile_wifi";
    }

    @Override
    protected boolean onBeforeHandleClick() {
        if (isLocked()) {
            return true;
        } else if (!mQuickMode) {
            return false;
        } else if (mClickOverrideBlocked) {
            mClickOverrideBlocked = false;
            return false;
        }

        XposedHelpers.callMethod(mTile, "handleSecondaryClick");
        return true;
    }

    @Override
    public boolean handleLongClick() {
        if (mQuickMode && !isLocked()) {
            mClickOverrideBlocked = true;
            XposedHelpers.callMethod(mTile, "handleClick");
            return true;
        }
        return false;
    }
}

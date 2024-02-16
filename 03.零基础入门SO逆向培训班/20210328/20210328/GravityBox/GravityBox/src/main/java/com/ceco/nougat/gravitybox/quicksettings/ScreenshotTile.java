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

import com.ceco.nougat.gravitybox.ModHwKeys;
import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.ScreenRecordingService;

import de.robv.android.xposed.XSharedPreferences;
import android.content.Intent;

public class ScreenshotTile extends QsTile {
    public static final class Service extends QsTileServiceBase {
        static final String KEY = ScreenshotTile.class.getSimpleName()+"$Service";
    }

    public ScreenshotTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);

        mState.label = mGbContext.getString(R.string.qs_tile_screenshot);
    }

    @Override
    public String getSettingsKey() {
        return "gb_tile_screenshot";
    }

    @Override
    public boolean supportsHideOnChange() {
        // we collapse panels ourselves
        return false;
    }

    @Override
    public void handleUpdateState(Object state, Object arg) {
        mState.icon = iconFromResId(R.drawable.ic_qs_screenshot);
        super.handleUpdateState(state, arg);
    }

    @Override
    public void handleClick() {
        collapsePanels();
        Intent intent = new Intent(ModHwKeys.ACTION_SCREENSHOT);
        intent.putExtra(ModHwKeys.EXTRA_SCREENSHOT_DELAY_MS, 1000L);
        mContext.sendBroadcast(intent);
        super.handleClick();
    }

    @Override
    public boolean handleLongClick() {
        if (!isLocked()) {
            collapsePanels();
            try {
                Intent intent = new Intent(mGbContext, ScreenRecordingService.class);
                intent.setAction(ScreenRecordingService.ACTION_TOGGLE_SCREEN_RECORDING);
                mGbContext.startService(intent);
            } catch (Throwable t) {
                log(getKey() + ": Error toggling screen recording: " + t.getMessage());
            }
        }
        return true;
    }
}

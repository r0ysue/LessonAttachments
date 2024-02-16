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

import com.ceco.nougat.gravitybox.R;

import de.robv.android.xposed.XSharedPreferences;
import android.content.Context;
import android.media.AudioManager;

public class VolumeTile extends QsTile {
    public static final class Service extends QsTileServiceBase {
        static final String KEY = VolumeTile.class.getSimpleName()+"$Service";
    }

    public VolumeTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);

        mState.label = mGbContext.getString(R.string.qs_tile_volume);
    }

    @Override
    public String getSettingsKey() {
        return "gb_tile_volume";
    }

    @Override
    public void handleUpdateState(Object state, Object arg) {
        mState.icon = iconFromResId(R.drawable.ic_qs_volume);
        super.handleUpdateState(state, arg);
    }

    @Override
    public boolean supportsHideOnChange() {
        // we collapse panels ourselves
        return false;
    }

    @Override
    public void handleClick() {
        collapsePanels();
        AudioManager am = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
        am.adjustVolume(AudioManager.ADJUST_SAME, AudioManager.FLAG_SHOW_UI);
        super.handleClick();
    }

    @Override
    public boolean handleLongClick() {
        startSettingsActivity(android.provider.Settings.ACTION_SOUND_SETTINGS);
        return true;
    }
}

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

import com.ceco.nougat.gravitybox.GravityBox;
import com.ceco.nougat.gravitybox.GravityBoxSettings;
import com.ceco.nougat.gravitybox.R;

import de.robv.android.xposed.XSharedPreferences;
import android.content.Intent;

public class GravityBoxTile extends QsTile {
    public static final class Service extends QsTileServiceBase {
        static final String KEY = GravityBoxTile.class.getSimpleName()+"$Service";
    }

    public GravityBoxTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);

        mState.label = "GravityBox";
    }

    @Override
    public String getSettingsKey() {
        return "gb_tile_gravitybox";
    }

    @Override
    public boolean supportsHideOnChange() {
        // starting activity collapses panel anyway
        return false;
    }

    @Override
    public void handleUpdateState(Object state, Object arg) {
        mState.icon = iconFromResId(R.drawable.ic_qs_gravitybox);
        super.handleUpdateState(state, arg);
    }

    @Override
    public void handleClick() {
        Intent i = new Intent();
        i.setClassName(GravityBox.PACKAGE_NAME, GravityBoxSettings.class.getName());
        startSettingsActivity(i);
        super.handleClick();
    }

    @Override
    public boolean handleLongClick() {
        Intent i = new Intent();
        i.setClassName(GravityBox.PACKAGE_NAME, TileOrderActivity.class.getName());
        startSettingsActivity(i);
        return true;
    }
}

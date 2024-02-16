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
import com.ceco.nougat.gravitybox.managers.GpsStatusMonitor;
import com.ceco.nougat.gravitybox.managers.SysUiManagers;

import de.robv.android.xposed.XSharedPreferences;
import android.provider.Settings;

public class GpsTile extends QsTile implements GpsStatusMonitor.Listener {
    public static final class Service extends QsTileServiceBase {
        static final String KEY = GpsTile.class.getSimpleName()+"$Service";
    }

    private boolean mGpsEnabled;
    private boolean mGpsFixed;

    public GpsTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);
    }

    private void registerListener() {
        if (SysUiManagers.GpsMonitor != null) {
            mGpsEnabled = SysUiManagers.GpsMonitor.isGpsEnabled();
            mGpsFixed = SysUiManagers.GpsMonitor.isGpsFixed();
            SysUiManagers.GpsMonitor.registerListener(this);
        }
    }

    private void unregisterListener() {
        if (SysUiManagers.GpsMonitor != null) {
            SysUiManagers.GpsMonitor.unregisterListener(this);
        }
    }

    @Override
    public String getSettingsKey() {
        return "gb_tile_gps_alt";
    }

    @Override
    public void onLocationModeChanged(int mode) { }

    @Override
    public void onGpsEnabledChanged(boolean gpsEnabled) {
        mGpsEnabled = gpsEnabled;
        refreshState();
    }

    @Override
    public void onGpsFixChanged(boolean gpsFixed) {
        mGpsFixed = gpsFixed;
        refreshState();
    }

    @Override
    public void setListening(boolean listening) {
        if (listening) {
            registerListener();
        } else {
            unregisterListener();
        }
    }

    @Override
    public void handleUpdateState(Object state, Object arg) {
        mState.booleanValue = mGpsEnabled;
        if (mGpsEnabled) {
            mState.label = mGpsFixed ? mGbContext.getString(R.string.qs_tile_gps_locked) :
                    mGbContext.getString(R.string.qs_tile_gps_enabled);
            mState.icon = mGpsFixed ? iconFromResId(R.drawable.ic_qs_gps_locked) :
                iconFromResId(R.drawable.ic_qs_gps_enable);
        } else {
            mState.label = mGbContext.getString(R.string.qs_tile_gps_disabled);
            mState.icon = iconFromResId(supportsIconTinting() ?
                    R.drawable.ic_qs_gps_enable : R.drawable.ic_qs_gps_disable);
        }

        super.handleUpdateState(state, arg);
    }

    @Override
    public void handleClick() {
        if (SysUiManagers.GpsMonitor != null) {
            SysUiManagers.GpsMonitor.setGpsEnabled(!mGpsEnabled);
        }
        super.handleClick();
    }

    @Override
    public boolean handleLongClick() {
        startSettingsActivity(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
        return true;
    }
}

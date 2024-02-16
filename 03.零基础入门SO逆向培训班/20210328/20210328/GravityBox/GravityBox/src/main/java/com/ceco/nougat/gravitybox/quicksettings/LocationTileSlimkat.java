/*
 * Copyright (C) 2017 The SlimRoms Project
 * Copyright (C) 2018 Peter Gregus for GravityBox Project (C3C076@xda)
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

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.AdapterView;
import android.widget.ListView;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.ceco.nougat.gravitybox.GravityBoxSettings;
import com.ceco.nougat.gravitybox.ModStatusBar;
import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.managers.GpsStatusMonitor;
import com.ceco.nougat.gravitybox.managers.SysUiManagers;

import de.robv.android.xposed.XSharedPreferences;

public class LocationTileSlimkat extends QsTile implements GpsStatusMonitor.Listener {
    public static final class Service extends QsTileServiceBase {
        static final String KEY = LocationTileSlimkat.class.getSimpleName()+"$Service";
    }

    private static final Intent LOCATION_SETTINGS_INTENT = 
            new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);

    public static final Integer[] LOCATION_SETTINGS = new Integer[] {
        Settings.Secure.LOCATION_MODE_BATTERY_SAVING,
        Settings.Secure.LOCATION_MODE_SENSORS_ONLY,
        Settings.Secure.LOCATION_MODE_HIGH_ACCURACY
    };

    private int mLastActiveMode;
    private QsDetailAdapterProxy mDetailAdapter;
    private List<Integer> mLocationList = new ArrayList<Integer>();
    private boolean mQuickMode;

    public LocationTileSlimkat(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);

        mLastActiveMode = getLocationMode();
        if(mLastActiveMode == Settings.Secure.LOCATION_MODE_OFF) {
            mLastActiveMode = Settings.Secure.LOCATION_MODE_HIGH_ACCURACY;
        }
    }

    @Override
    public String getSettingsKey() {
        return "gb_tile_gps_slimkat";
    }

    @Override
    public void initPreferences() {
        mQuickMode = mPrefs.getBoolean(GravityBoxSettings.PREF_KEY_LOCATION_TILE_QUICK_MODE, false);

        super.initPreferences();
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_QUICKSETTINGS_CHANGED)) {
            if (intent.hasExtra(GravityBoxSettings.EXTRA_LOCATION_TILE_QUICK_MODE)) {
                mQuickMode = intent.getBooleanExtra(GravityBoxSettings.EXTRA_LOCATION_TILE_QUICK_MODE, false);
            }
        }

        super.onBroadcastReceived(context, intent);
    }

    private void registerListener() {
        if (SysUiManagers.GpsMonitor != null) {
            SysUiManagers.GpsMonitor.registerListener(this);
            if (DEBUG) log(getKey() + ": Location Status Listener registered");
        }
    }

    private void unregisterListener() {
        if (SysUiManagers.GpsMonitor != null) {
            SysUiManagers.GpsMonitor.unregisterListener(this);
            if (DEBUG) log(getKey() + ": Location Status Listener unregistered");
        }
    }

    @Override
    public void setListening(boolean listening) {
        if (listening) {
            registerListener();
        } else {
            unregisterListener();
        }
    }

    private boolean isLocationEnabled() {
        return (getLocationMode() != Settings.Secure.LOCATION_MODE_OFF);
    }

    private int getLocationMode() {
        return (SysUiManagers.GpsMonitor == null ? 0 :
            SysUiManagers.GpsMonitor.getLocationMode());
    }

    private void setLocationMode(int mode) {
        if (SysUiManagers.GpsMonitor != null) {
            SysUiManagers.GpsMonitor.setLocationMode(mode);
        }
    }

    private void switchLocationMode() {
        int currentMode = getLocationMode();
        switch (currentMode) {
            case Settings.Secure.LOCATION_MODE_OFF:
                setLocationMode(Settings.Secure.LOCATION_MODE_BATTERY_SAVING);
                break;
            case Settings.Secure.LOCATION_MODE_BATTERY_SAVING:
                setLocationMode(Settings.Secure.LOCATION_MODE_SENSORS_ONLY);
                break;
            case Settings.Secure.LOCATION_MODE_SENSORS_ONLY:
                setLocationMode(Settings.Secure.LOCATION_MODE_HIGH_ACCURACY);
                break;
            case Settings.Secure.LOCATION_MODE_HIGH_ACCURACY:
                setLocationMode(Settings.Secure.LOCATION_MODE_OFF);
                break;
        }
    }

    private void setLocationEnabled(boolean enabled) {
        if (SysUiManagers.GpsMonitor != null) {
            // Store last active mode if we are switching off
            // so we can restore it at the next enable
            if(!enabled) {
                mLastActiveMode = getLocationMode();
            }
            final int mode = enabled ? mLastActiveMode : Settings.Secure.LOCATION_MODE_OFF;
            SysUiManagers.GpsMonitor.setLocationMode(mode);
        }
    }

    @Override
    public void onLocationModeChanged(int mode) {
        if (DEBUG) log(getKey() + ": onLocationModeChanged: mode=" + mode);
        refreshState();
    }

    @Override
    public void onGpsEnabledChanged(boolean gpsEnabled) { }

    @Override
    public void onGpsFixChanged(boolean gpsFixed) { }

    @Override
    public void handleUpdateState(Object state, Object arg) {
        mState.booleanValue = true;
        int locationMode = getLocationMode();
        switch (locationMode) {
            case Settings.Secure.LOCATION_MODE_SENSORS_ONLY:
                mState.icon = iconFromResId(R.drawable.ic_qs_location_on);
                break;
            case Settings.Secure.LOCATION_MODE_BATTERY_SAVING:
                mState.icon = iconFromResId(R.drawable.ic_qs_location_battery_saving);
                break;
            case Settings.Secure.LOCATION_MODE_HIGH_ACCURACY:
                mState.icon = iconFromResId(R.drawable.ic_qs_location_on);
                break;
            case Settings.Secure.LOCATION_MODE_OFF:
                mState.booleanValue = false;
                mState.icon = iconFromResId(supportsIconTinting() ?
                        R.drawable.ic_qs_location_on : R.drawable.ic_qs_location_off);
                break;
        }
        mState.label = GpsStatusMonitor.getModeLabel(mContext, locationMode);

        super.handleUpdateState(state, arg);
    }

    @Override
    public void handleClick() {
        if (mQuickMode) {
            switchLocationMode();
        } else {
            showDetail(true);
        }
        super.handleClick();
    }

    @Override
    public boolean handleLongClick() {
        if (!isLocked()) {
            if (mQuickMode) {
                showDetail(true);
            } else {
                setLocationEnabled(!isLocationEnabled());
            }
        } else {
            startSettingsActivity(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
        }
        return true;
    }

    @Override
    public boolean supportsHideOnChange() {
        return mQuickMode;
    }

    @Override
    public void handleDestroy() {
        if (mDetailAdapter != null) {
            mDetailAdapter.destroy();
            mDetailAdapter = null;
        }
        mLocationList.clear();
        mLocationList = null;
        super.handleDestroy();
    }

    @Override
    public Object getDetailAdapter() {
        if (mDetailAdapter == null) {
            mDetailAdapter = QsDetailAdapterProxy.create(
                    mContext.getClassLoader(), new LocationDetailAdapter());
        }
        return mDetailAdapter.getProxy();
    }

    private class LocationDetailAdapter implements QsDetailAdapterProxy.Callback, AdapterView.OnItemClickListener {

        private QsDetailItemsListAdapter<Integer> mAdapter;
        private QsDetailItemsList mDetails;

        @Override
        public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
            setLocationMode((Integer) parent.getItemAtPosition(position));
            showDetail(false);
        }

        @Override
        public CharSequence getTitle() {
            return mContext.getString(mContext.getResources().getIdentifier("quick_settings_location_label",
                    "string", ModStatusBar.PACKAGE_NAME));
        }

        @Override
        public boolean getToggleEnabled() {
            return true;
        }

        @Override
        public Boolean getToggleState() {
            return isLocationEnabled();
        }

        @Override
        public View createDetailView(final Context context, View convertView, ViewGroup parent) throws Throwable {
            mAdapter = new QsDetailItemsListAdapter<Integer>(context, mLocationList) {
                @Override
                protected CharSequence getListItemText(Integer item) {
                    return GpsStatusMonitor.getModeLabel(context, item);
                }
            };
            mDetails = QsDetailItemsList.create(context, parent);
            mDetails.setEmptyState(R.drawable.ic_qs_location_off,
                    GpsStatusMonitor.getModeLabel(context, Settings.Secure.LOCATION_MODE_OFF));
            mDetails.setAdapter(mAdapter);

            final ListView list = mDetails.getListView();
            list.setChoiceMode(AbsListView.CHOICE_MODE_SINGLE);
            list.setOnItemClickListener(this);

            rebuildLocationList(isLocationEnabled());
            return mDetails.getView();
        }

        @Override
        public Intent getSettingsIntent() {
            return LOCATION_SETTINGS_INTENT;
        }

        @Override
        public void setToggleState(boolean state) {
            setLocationEnabled(state);
            showDetail(false);
        }

        private void rebuildLocationList(boolean populate) {
            mLocationList.clear();
            if (populate) {
                mLocationList.addAll(Arrays.asList(LOCATION_SETTINGS));
                mDetails.getListView().setItemChecked(mAdapter.getPosition(
                        getLocationMode()), true);
            }
            mAdapter.notifyDataSetChanged();
        }
    }
}

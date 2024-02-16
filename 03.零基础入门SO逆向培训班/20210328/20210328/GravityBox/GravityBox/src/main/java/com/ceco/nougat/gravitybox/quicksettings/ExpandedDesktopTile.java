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
import com.ceco.nougat.gravitybox.ModExpandedDesktop;
import com.ceco.nougat.gravitybox.R;

import de.robv.android.xposed.XSharedPreferences;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.database.ContentObserver;
import android.os.Handler;
import android.provider.Settings;

public class ExpandedDesktopTile extends QsTile {
    public static final class Service extends QsTileServiceBase {
        static final String KEY = ExpandedDesktopTile.class.getSimpleName()+"$Service";
    }

    private int mMode;
    private boolean mExpanded;
    private Handler mHandler;
    private SettingsObserver mSettingsObserver;

    public ExpandedDesktopTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);

        mHandler = new Handler();
        mSettingsObserver = new SettingsObserver(mHandler);
    }

    class SettingsObserver extends ContentObserver {
        public SettingsObserver(Handler handler) {
            super(handler);
        }

        public void observe() {
            ContentResolver cr = mContext.getContentResolver();
            cr.registerContentObserver(Settings.Global.getUriFor(
                   ModExpandedDesktop.SETTING_EXPANDED_DESKTOP_STATE), false, this);
        }

        public void unobserve() {
            ContentResolver cr = mContext.getContentResolver();
            cr.unregisterContentObserver(this);
        }

        @Override 
        public void onChange(boolean selfChange) {
            refreshState();
        }
    }

    @Override
    public String getSettingsKey() {
        return "gb_tile_expanded_desktop";
    }

    @Override
    public void initPreferences() {
        super.initPreferences();
        mMode = GravityBoxSettings.ED_DISABLED;
        try {
            mMode = Integer.valueOf(mPrefs.getString(GravityBoxSettings.PREF_KEY_EXPANDED_DESKTOP, "0"));
        } catch (NumberFormatException nfe) {
            log(getKey() + ": Invalid value for PREF_KEY_EXPANDED_DESKTOP preference");
        }
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        super.onBroadcastReceived(context, intent);

        if (intent.getAction().equals(GravityBoxSettings.ACTION_PREF_EXPANDED_DESKTOP_MODE_CHANGED) &&
                intent.hasExtra(GravityBoxSettings.EXTRA_ED_MODE)) {
            mMode = intent.getIntExtra(GravityBoxSettings.EXTRA_ED_MODE, GravityBoxSettings.ED_DISABLED);
        }
    }

    @Override
    public void setListening(boolean listening) {
        if (listening) {
            mExpanded = (Settings.Global.getInt(mContext.getContentResolver(),
                    ModExpandedDesktop.SETTING_EXPANDED_DESKTOP_STATE, 0) == 1)
                    && (mMode > 0);
            if (DEBUG) log(getKey() + ": mExpanded=" + mExpanded);
            mSettingsObserver.observe();
        } else {
            mSettingsObserver.unobserve();
        }
    }

    @Override
    public void handleUpdateState(Object state, Object arg) {
        mState.booleanValue = mExpanded;
        if (mExpanded) {
            mState.label = mGbContext.getString(R.string.quick_settings_expanded_desktop_expanded);
            mState.icon = iconFromResId(R.drawable.ic_qs_expanded_desktop_on);
        } else {
            mState.label = (mMode == GravityBoxSettings.ED_DISABLED) ? 
                    mGbContext.getString(R.string.quick_settings_expanded_desktop_disabled) :
                        mGbContext.getString(R.string.quick_settings_expanded_desktop_normal);
            mState.icon = iconFromResId(supportsIconTinting() ?
                    R.drawable.ic_qs_expanded_desktop_on : R.drawable.ic_qs_expanded_desktop_off);
        }

        super.handleUpdateState(state, arg);
    }

    @Override
    public void handleClick() {
        if (mMode != GravityBoxSettings.ED_DISABLED) {
            collapsePanels();
            // give panels chance to collapse before changing expanded desktop state
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    Settings.Global.putInt(mContext.getContentResolver(),
                            ModExpandedDesktop.SETTING_EXPANDED_DESKTOP_STATE,
                            (mExpanded ? 0 : 1));
                }
            }, 800);
        }
        super.handleClick();
    }

    @Override
    public void handleDestroy() {
        super.handleDestroy();
        mSettingsObserver = null;
        mHandler = null;
    }
}

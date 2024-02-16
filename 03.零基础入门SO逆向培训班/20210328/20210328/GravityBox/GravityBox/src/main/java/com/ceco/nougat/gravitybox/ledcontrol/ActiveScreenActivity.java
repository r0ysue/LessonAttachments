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

package com.ceco.nougat.gravitybox.ledcontrol;

import com.ceco.nougat.gravitybox.GravityBoxActivity;
import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.SettingsManager;
import com.ceco.nougat.gravitybox.Utils;
import com.ceco.nougat.gravitybox.WorldReadablePrefs;
import com.ceco.nougat.gravitybox.WorldReadablePrefs.OnSharedPreferenceChangeCommitedListener;

import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.os.Bundle;
import android.preference.CheckBoxPreference;
import android.preference.PreferenceFragment;
import android.util.Log;

public class ActiveScreenActivity extends GravityBoxActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.active_screen_activity);
    }

    public static class PrefsFragment extends PreferenceFragment implements
                OnSharedPreferenceChangeListener, OnSharedPreferenceChangeCommitedListener {
        private WorldReadablePrefs mPrefs;
        private CheckBoxPreference mPrefPocketMode;

        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);

            getPreferenceManager().setSharedPreferencesName("ledcontrol");
            if (Utils.USE_DEVICE_PROTECTED_STORAGE) {
                getPreferenceManager().setStorageDeviceProtected();
            }
            mPrefs = SettingsManager.getInstance(getActivity()).getLedControlPrefs();
            addPreferencesFromResource(R.xml.led_control_active_screen_settings);

            mPrefPocketMode = (CheckBoxPreference) findPreference(
                    LedSettings.PREF_KEY_ACTIVE_SCREEN_POCKET_MODE);

            if (LedSettings.isProximityWakeUpEnabled(getActivity())) {
                mPrefPocketMode.setSummary(R.string.pref_unc_as_pocket_mode_summary_overriden);
                mPrefPocketMode.setEnabled(false);
            }
        }

        @Override
        public void onResume() {
            super.onResume();
            mPrefs.registerOnSharedPreferenceChangeListener(this);
            mPrefs.setOnSharedPreferenceChangeCommitedListener(this);
            updateSummaries();
        }

        @Override
        public void onPause() {
            mPrefs.unregisterOnSharedPreferenceChangeListener(this);
            mPrefs.setOnSharedPreferenceChangeCommitedListener(null);
            super.onPause();
        }

        @Override
        public void onSharedPreferenceChanged(SharedPreferences prefs, String key) {
            updateSummaries();
        }

        private void updateSummaries() {
        }

        @Override
        public void onSharedPreferenceChangeCommited() {
            if (WorldReadablePrefs.DEBUG)
                Log.d("GravityBox", "ActiveScreenActivity: onSharedPreferenceChangeCommited");
            Intent intent = new Intent(LedSettings.ACTION_UNC_SETTINGS_CHANGED);
            getActivity().sendBroadcast(intent);
        }
    }
}

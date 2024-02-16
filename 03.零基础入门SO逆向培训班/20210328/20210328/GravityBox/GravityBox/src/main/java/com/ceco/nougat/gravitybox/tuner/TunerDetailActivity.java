/*
 * Copyright (C) 2019 Peter Gregus for GravityBox Project (C3C076@xda)
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
package com.ceco.nougat.gravitybox.tuner;

import android.app.Activity;
import android.os.Bundle;
import android.preference.CheckBoxPreference;
import android.preference.EditTextPreference;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.preference.SwitchPreference;
import android.widget.TextView;
import android.widget.Toast;

import com.ceco.nougat.gravitybox.GravityBoxActivity;
import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.SettingsManager;
import com.ceco.nougat.gravitybox.Utils;

import java.util.Locale;

public class TunerDetailActivity extends GravityBoxActivity {

    public static final String EXTRA_TUNEABLE_ITEM = "tuneableItem";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        final TuneableItem item;
        if (getIntent() != null && getIntent().hasExtra(EXTRA_TUNEABLE_ITEM)) {
            item = getIntent().getParcelableExtra(EXTRA_TUNEABLE_ITEM);
        } else {
            finish();
            return;
        }

        setContentView(R.layout.tuner_detail_activity);

        ((TextView)findViewById(R.id.name)).setText(item.getKey());
        ((TextView)findViewById(R.id.info)).setText(getDocumentation(item.getKey()));
        ((TextView)findViewById(R.id.value)).setText(
                String.format(Locale.getDefault(), "%s: %s",
                        getString(R.string.tuneable_current_value),
                        String.valueOf(item.getValue())));

        findViewById(R.id.btnCancel).setOnClickListener((v) -> {
            setResult(Activity.RESULT_CANCELED);
            finish();
        });

        findViewById(R.id.btnSave).setOnClickListener((v) -> {
            item.saveUserSettings(SettingsManager.getInstance(
                    TunerDetailActivity.this).getTunerPrefs());
            setResult(Activity.RESULT_OK);
            finish();
        });

        getFragment().setItem(item);
    }

    private PrefsFragment getFragment() {
        return (PrefsFragment) getFragmentManager()
                .findFragmentById(R.id.prefs_fragment);
    }

    private String getDocumentation(String key) {
        int resId = getResources().getIdentifier(key, "string",
                getApplication().getPackageName());
        return resId == 0 ? getString(R.string.tuner_no_documentation) : getString(resId);
    }

    public static class PrefsFragment extends PreferenceFragment implements Preference.OnPreferenceChangeListener {
        protected static final String PREF_KEY_OVERRIDE = "pref_tuneable_override";
        protected static final String PREF_KEY_VALUE_BOOL = "pref_tuneable_value_bool";
        protected static final String PREF_KEY_VALUE_INTEGER = "pref_tuneable_value_integer";

        private SwitchPreference mPrefOverridden;
        private CheckBoxPreference mPrefValueBool;
        private EditTextPreference mPrefValueInteger;
        private TuneableItem mItem;

        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);

            getPreferenceManager().setSharedPreferencesName("tuner");
            if (Utils.USE_DEVICE_PROTECTED_STORAGE) {
                getPreferenceManager().setStorageDeviceProtected();
            }

            addPreferencesFromResource(R.xml.tuner_detail_activity_prefs);
            mPrefOverridden = (SwitchPreference) findPreference(PREF_KEY_OVERRIDE);
            mPrefOverridden.setOnPreferenceChangeListener(this);
            mPrefValueBool = (CheckBoxPreference) findPreference(PREF_KEY_VALUE_BOOL);
            mPrefValueBool.setOnPreferenceChangeListener(this);
            mPrefValueInteger = (EditTextPreference) findPreference(PREF_KEY_VALUE_INTEGER);
            mPrefValueInteger.setOnPreferenceChangeListener(this);
        }

        protected void setItem(TuneableItem item) {
            mItem = item;
            mItem.loadUserSettings(SettingsManager.getInstance(getContext()).getTunerPrefs());

            mPrefOverridden.setChecked(mItem.isOverridden());

            if (mItem.getType() != Boolean.class) {
                getPreferenceScreen().removePreference(mPrefValueBool);
            } else {
                mPrefValueBool.setChecked((Boolean) mItem.getUserValue());
            }

            if (mItem.getType() != Integer.class) {
                getPreferenceScreen().removePreference(mPrefValueInteger);
            } else {
                mPrefValueInteger.setText(String.valueOf(mItem.getUserValue()));
                mPrefValueInteger.setSummary(mPrefValueInteger.getText());
            }
        }

        @Override
        public boolean onPreferenceChange(Preference preference, Object newValue) {
            if (preference == mPrefOverridden) {
                mItem.setOverriden((Boolean) newValue);
                if (!mItem.isOverridden()) {
                    mItem.setUserValue(mItem.getValue());
                    if (mItem.getType() == Boolean.class) {
                        mPrefValueBool.setChecked((Boolean) mItem.getValue());
                    } else if (mItem.getType() == Integer.class) {
                        mPrefValueInteger.setText(String.valueOf(mItem.getValue()));
                        mPrefValueInteger.setSummary(mPrefValueInteger.getText());
                    }
                }
            } else if (preference == mPrefValueBool) {
                mItem.setUserValue(newValue);
            } else if (preference == mPrefValueInteger) {
                try {
                    int value = Integer.valueOf((String)newValue);
                    mItem.setUserValue(value);
                    mPrefValueInteger.setSummary(String.valueOf(value));
                } catch(NumberFormatException e) {
                    Toast.makeText(getContext(), R.string.pref_tuneable_value_int_error,
                            Toast.LENGTH_SHORT).show();
                    return false;
                }
            }
            return true;
        }
    }
}

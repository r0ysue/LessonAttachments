/*
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
package com.ceco.nougat.gravitybox.preference;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import android.content.Context;
import android.content.res.TypedArray;
import android.preference.DialogPreference;
import android.text.format.DateFormat;
import android.util.AttributeSet;
import android.view.View;
import android.widget.TimePicker;

public class TimePreference extends DialogPreference {
    private TimePicker mPicker = null;
    private int mValue;
    private boolean mTimerMode;
    private String mDefaultSummaryText;
    private String mSummarySuffix;

    public TimePreference(Context context) {
        this(context, null);
    }

    public TimePreference(Context ctxt, AttributeSet attrs) {
        super(ctxt, attrs);

        mDefaultSummaryText = (String) super.getSummary();
        if (attrs != null) {
            mTimerMode = attrs.getAttributeBooleanValue(null, "timerMode", false);
        }

        setPositiveButtonText(android.R.string.ok);
        setNegativeButtonText(android.R.string.cancel);
    }

    @Override
    protected View onCreateDialogView() {
        mPicker = new TimePicker(getContext());
        mPicker.setIs24HourView(mTimerMode || DateFormat.is24HourFormat(getContext()));
        return mPicker;
    }

    @Override
    protected void onBindDialogView(View v) {
        super.onBindDialogView(v);
        int hours = (int) (mValue / 60);
        int minutes = mValue - hours*60;
        mPicker.setHour(hours);
        mPicker.setMinute(minutes);
    }

    @Override
    protected void onDialogClosed(boolean positiveResult) {
        super.onDialogClosed(positiveResult);

        if (positiveResult) {
            mValue = mPicker.getHour() * 60 + mPicker.getMinute();
            setSummary(getSummary());
            if (callChangeListener(mValue)) {
                if (shouldPersist()) {
                    persistInt(mValue);
                }
                notifyChanged();
            }
        }
    }

    @Override
    protected Object onGetDefaultValue(TypedArray a, int index) {
        return a.getString(index);
    }

    @Override
    protected void onSetInitialValue(boolean restoreValue, Object defaultValue) {
        if (restoreValue) {
            mValue = getPersistedInt(0);
        } else {
            mValue = defaultValue == null ? 0 : Integer.parseInt((String) defaultValue);
            if (shouldPersist()) {
                persistInt(mValue);
            }
        }
        setSummary(getSummary());
    }

    @Override
    public CharSequence getSummary() {
        if (mDefaultSummaryText != null) {
            return mDefaultSummaryText;
        } else {
            int hours = (int) (mValue / 60);
            int minutes = mValue - hours*60;
            String time = String.format(Locale.getDefault(), "%02d:%02d", hours, minutes);
            if (!(mTimerMode || DateFormat.is24HourFormat(getContext()))) {
                SimpleDateFormat sdf = new SimpleDateFormat("HH:mm", Locale.getDefault());
                try {
                    Date dateObj = sdf.parse(time);
                    time = new SimpleDateFormat("hh:mm aa", Locale.getDefault()).format(dateObj);
                } catch (ParseException ignored) { }
            }
            if (mSummarySuffix != null) {
                time = String.format("%s %s", time, mSummarySuffix);
            }
            return time;
        }
    }

    public int getValue() {
        return mValue;
    }

    public void setValue(int value){
        mValue = value;
        if (shouldPersist()) {
            persistInt(mValue);
        }
        setSummary(getSummary());
    }

    public void setSummarySuffix(String suffix) {
        mSummarySuffix = suffix;
    }
}

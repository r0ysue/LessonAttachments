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

import android.annotation.SuppressLint;
import android.content.SharedPreferences;
import android.os.Parcel;
import android.os.Parcelable;

import com.ceco.nougat.gravitybox.managers.TunerManager;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class TuneableItem implements Parcelable {

    private Class<?> mType;
    private TunerManager.Category mCategory;
    private String mKey;
    private Object mValue;
    private Object mUserValue;
    private boolean mOverridden;

    public TuneableItem(Class<?> type, TunerManager.Category category, String key, Object value) {
        mType = type;
        mCategory = category;
        mKey = key;
        mValue = value;
        mUserValue = value;
    }

    private TuneableItem(Class<?> type, TunerManager.Category category, String key) {
        mType = type;
        mCategory = category;
        mKey = key;
    }

    private TuneableItem(Parcel in) {
        try {
            mType = Class.forName(in.readString());
            mCategory = TunerManager.Category.valueOf(in.readString());
            mKey = in.readString();
            mValue = in.readValue(mType.getClassLoader());
            mUserValue = in.readValue(mType.getClassLoader());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static final Creator<TuneableItem> CREATOR = new Creator<TuneableItem>() {
        @Override
        public TuneableItem createFromParcel(Parcel in) {
            return new TuneableItem(in);
        }

        @Override
        public TuneableItem[] newArray(int size) {
            return new TuneableItem[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(mType.getName());
        dest.writeString(mCategory.toString());
        dest.writeString(mKey);
        dest.writeValue(mValue);
        dest.writeValue(mUserValue);
    }

    public Class<?> getType() {
        return mType;
    }

    public TunerManager.Category getCategory() {
        return mCategory;
    }

    public String getKey() {
        return  mKey;
    }

    public Object getValue() {
        return mValue;
    }

    public Object getUserValue() {
        return mUserValue;
    }

    public boolean isOverridden() {
        return mOverridden;
    }

    private String getPrefKey() {
        return String.format(Locale.US, "%s:%s", mCategory.toString(), mKey);
    }

    public String getResourceType() {
        if (mType == Boolean.class) {
            return "bool";
        } else if (mType == Integer.class) {
            return "integer";
        }
        return null;
    }

    /* package */
    void loadUserSettings(SharedPreferences prefs) {
        Set<String> dataSet = prefs.getStringSet(getPrefKey(), null);
        applyUserSettings(dataSet);
    }

    private void applyUserSettings(Set<String> dataSet) {
        if (dataSet != null) {
            for (String val : dataSet) {
                String[] data = val.split(":", 2);
                if (data[0].equals("overridden")) {
                    mOverridden = Boolean.valueOf(data[1]);
                } else if (data[0].equals("value")) {
                    if (mType == Boolean.class) {
                        mUserValue = Boolean.valueOf(data[1]);
                    } else if (mType == Integer.class) {
                        mUserValue = Integer.valueOf(data[1]);
                    }
                }
            }
        }
    }

    /* package */
    void setOverriden(boolean value) {
        mOverridden = value;
    }

    /* package */
    void setUserValue(Object value) {
        mUserValue = value;
    }

    /* package */
    @SuppressLint("ApplySharedPref")
    void saveUserSettings(SharedPreferences prefs) {
        Set<String> dataSet = new HashSet<>();
        dataSet.add("category:" + mCategory.toString());
        dataSet.add("key:" + mKey);
        dataSet.add("type:" + mUserValue.getClass().getName());
        dataSet.add("overridden:" + mOverridden);
        dataSet.add("value:" + mUserValue);
        prefs.edit().putStringSet(getPrefKey(), dataSet).commit();
    }

    public static TuneableItem createUserInstance(String prefKey, SharedPreferences prefs) {
        Set<String> dataSet = prefs.getStringSet(prefKey, null);
        if (dataSet != null) {
            TunerManager.Category category = null;
            String key = null;
            String type = null;
            for (String val : dataSet) {
                String[] data = val.split(":", 2);
                switch (data[0]) {
                    case "category":
                        category = TunerManager.Category.valueOf(data[1]);
                        break;
                    case "key":
                        key = data[1];
                        break;
                    case "type":
                        type = data[1];
                        break;
                }
            }
            if (category != null && key != null && type != null) {
                try {
                    Class<?> clazz = Class.forName(type);
                    TuneableItem item = new TuneableItem(clazz, category, key);
                    item.applyUserSettings(dataSet);
                    return item;
                } catch (ClassNotFoundException ignore) { }
            }
        }
        return null;
    }
}

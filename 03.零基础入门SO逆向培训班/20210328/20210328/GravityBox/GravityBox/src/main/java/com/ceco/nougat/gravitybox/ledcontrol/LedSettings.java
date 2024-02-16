/*
 * Copyright (C) 2015 Peter Gregus for GravityBox Project (C3C076@xda)
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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import com.ceco.nougat.gravitybox.GravityBoxSettings;
import com.ceco.nougat.gravitybox.SettingsManager;
import com.ceco.nougat.gravitybox.Utils;
import com.ceco.nougat.gravitybox.WorldReadablePrefs;
import com.ceco.nougat.gravitybox.WorldReadablePrefs.OnPreferencesCommitedListener;

import android.app.Notification;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.util.Log;

public class LedSettings {

    public static final String PREF_KEY_LOCKED = "uncLocked";
    public static final String PREF_KEY_ACTIVE_SCREEN_ENABLED = "activeScreenEnabled";
    public static final String PREF_KEY_ACTIVE_SCREEN_IGNORE_QUIET_HOURS = "pref_unc_as_ignore_quiet_hours";
    public static final String PREF_KEY_ACTIVE_SCREEN_POCKET_MODE = "pref_unc_as_pocket_mode";

    public static final String ACTION_UNC_SETTINGS_CHANGED = "gravitybox.intent.action.UNC_SETTINGS_CHANGED";
    public static final String EXTRA_UNC_PACKAGE_SETTINGS = "gravitybox.uncPackageSettings";

    public enum LedMode { ORIGINAL, OVERRIDE, OFF }
    public enum HeadsUpMode { DEFAULT, ALWAYS, IMMERSIVE, OFF }
    public enum ActiveScreenMode { DISABLED, DO_NOTHING }
    public enum Visibility {
        DEFAULT(-2),
        PRIVATE(Notification.VISIBILITY_PRIVATE),
        PUBLIC(Notification.VISIBILITY_PUBLIC),
        SECRET(Notification.VISIBILITY_SECRET);
        private int mValue;
        Visibility(int value) {
            mValue = value;
        }
        public int getValue() { return mValue; }
    }
    public enum VisibilityLs { DEFAULT, CLEARABLE, PERSISTENT, ALL }

    private Context mContext;
    private String mPackageName;
    private boolean mEnabled;
    private boolean mOngoing;
    private int mLedOnMs;
    private int mLedOffMs;
    private int mColor;
    private boolean mSoundOverride;
    private Uri mSoundUri;
    private boolean mSoundReplace;
    private boolean mSoundOnlyOnce;
    private long mSoundOnlyOnceTimeout;
    private boolean mInsistent;
    private boolean mVibrateOverride;
    private boolean mVibrateReplace;
    private String mVibratePatternStr;
    private long[] mVibratePattern;
    private ActiveScreenMode mActiveScreenMode;
    private boolean mActiveScreenIgnoreUpdate;
    private LedMode mLedMode;
    private boolean mQhIgnore;
    private String mQhIgnoreList;
    private boolean mQhIgnoreInteractive;
    private HeadsUpMode mHeadsUpMode;
    private boolean mHeadsUpDnd;
    private int mHeadsUpTimeout;
    private boolean mProgressTracking;
    private Visibility mVisibility;
    private VisibilityLs mVisibilityLs;
    private boolean mSoundToVibrateDisabled;
    private boolean mHidePersistent;
    private String mLedDnd;
    private boolean mLedIgnoreUpdate;

    protected static LedSettings deserialize(Context context, String packageName) {
        try {
            SharedPreferences prefs = SettingsManager.getInstance(context).getLedControlPrefs();
            Set<String> dataSet = prefs.getStringSet(packageName, null);
            if (dataSet == null) {
                if (packageName.equals("default")) {
                    return new LedSettings(context, packageName);
                } else {
                    LedSettings defLs = LedSettings.getDefault(context);
                    defLs.mPackageName = packageName;
                    defLs.mEnabled = false;
                    return defLs;
                }
            }
            return deserialize(context, packageName, dataSet);
        } catch (Throwable t) {
            t.printStackTrace();
            return new LedSettings(context, packageName);
        }
    }

    public static LedSettings deserialize(Set<String> dataSet) {
        return deserialize(null, null, dataSet);
    }

    public static LedSettings deserialize(String pkg, ArrayList<String> list) {
        return deserialize(null, pkg, new HashSet<String>(list));
    }

    private static LedSettings deserialize(Context context, String packageName, Set<String> dataSet) {
        LedSettings ls = new LedSettings(context, packageName);
        if (dataSet == null) {
            return ls;
        }
        for (String val : dataSet) {
            String[] data = val.split(":", 2);
            if (data[0].equals("enabled")) {
                ls.setEnabled(Boolean.valueOf(data[1]));
            } else if (data[0].equals("ongoing")) {
                ls.setOngoing(Boolean.valueOf(data[1]));
            } else if (data[0].equals("ledOnMs")) {
                ls.setLedOnMs(Integer.valueOf(data[1]));
            } else if (data[0].equals("ledOffMs")) {
                ls.setLedOffMs(Integer.valueOf(data[1]));
            } else if (data[0].equals("color")) {
                ls.setColor(Integer.valueOf(data[1]));
            } else if (data[0].equals("soundOverride")) {
                ls.setSoundOverride(Boolean.valueOf(data[1]));
            } else if (data[0].equals("sound")) {
                ls.setSoundUri(Uri.parse(data[1]));
            } else if (data[0].equals("soundOnlyOnce")) {
                ls.setSoundOnlyOnce(Boolean.valueOf(data[1]));
            } else if (data[0].equals("soundOnlyOnceTimeoutMs")) {
                ls.setSoundOnlyOnceTimeout(Long.valueOf(data[1]));
            } else if (data[0].equals("insistent")) {
                ls.setInsistent(Boolean.valueOf(data[1]));
            } else if (data[0].equals("vibrateOverride")) {
                ls.setVibrateOverride(Boolean.valueOf(data[1]));
            } else if (data[0].equals("vibratePattern")) {
                ls.setVibratePatternFromString(data[1]);
            } else if (data[0].equals("activeScreenMode")) {
                if ("HEADS_UP".equals(data[1])) data[1] = "DO_NOTHING";
                ls.setActiveScreenMode(ActiveScreenMode.valueOf(data[1]));
            } else if (data[0].equals("activeScreenIgnoreUpdate")) {
                ls.setActiveScreenIgnoreUpdate(Boolean.valueOf(data[1]));
            } else if (data[0].equals("ledMode")) {
                ls.setLedMode(LedMode.valueOf(data[1]));
            } else if (data[0].equals("qhIgnore")) {
                ls.setQhIgnore(Boolean.valueOf(data[1]));
            } else if (data[0].equals("qhIgnoreList")) {
                ls.setQhIgnoreList(data[1]);
            } else if (data[0].equals("qhIgnoreInteractive")) {
                ls.setQhIgnoreInteractive(Boolean.valueOf(data[1]));
            } else if (data[0].equals("headsUpMode")) {
                ls.setHeadsUpMode(data[1]);
            } else if (data[0].equals("headsUpDnd")) {
                ls.setHeadsUpDnd(Boolean.valueOf(data[1]));
            } else if (data[0].equals("headsUpTimeout")) {
                ls.setHeadsUpTimeout(Integer.valueOf(data[1]));
            } else if (data[0].equals("progressTracking")) {
                ls.setProgressTracking(Boolean.valueOf(data[1]));
            } else if (data[0].equals("visibility")) {
                ls.setVisibility(data[1]);
            } else if (data[0].equals("visibilityLs")) {
                ls.setVisibilityLs(data[1]);
            } else if (data[0].equals("soundToVibrateDisabled")) {
                ls.setSoundToVibrateDisabled(Boolean.valueOf(data[1]));
            } else if (data[0].equals("vibrateReplace")) {
                ls.setVibrateReplace(Boolean.valueOf(data[1]));
            } else if (data[0].equals("soundReplace")) {
                ls.setSoundReplace(Boolean.valueOf(data[1]));
            } else if (data[0].equals("hidePersistent")) {
                ls.setHidePersistent(Boolean.valueOf(data[1]));
            } else if (data[0].equals("ledDnd")) {
                ls.setLedDnd(data[1]);
            } else if (data[0].equals("ledIgnoreUpdate")) {
                ls.setLedIgnoreUpdate(Boolean.valueOf(data[1]));
            }
        }
        return ls;
    }

    private LedSettings(Context context, String packageName) {
        mContext = context;
        mPackageName = packageName;
        mEnabled = false;
        mOngoing = false;
        mLedOnMs = Utils.isVerneeDevice() ? 500 : 1000;
        mLedOffMs = Utils.isVerneeDevice() ? 0 : 5000;
        mColor = Utils.isVerneeDevice() ? 0xff201000 : 0xffffffff;
        mSoundOverride = false;
        mSoundUri = null;
        mSoundReplace = true;
        mSoundOnlyOnce = false;
        mSoundOnlyOnceTimeout = 0;
        mInsistent = false;
        mVibrateOverride = false;
        mVibratePatternStr = null;
        mVibratePattern = null;
        mVibrateReplace = true;
        mActiveScreenMode = ActiveScreenMode.DISABLED;
        mActiveScreenIgnoreUpdate = false;
        mLedMode = LedMode.OVERRIDE;
        mQhIgnore = false;
        mQhIgnoreList = null;
        mQhIgnoreInteractive = true;
        mHeadsUpMode = HeadsUpMode.DEFAULT;
        mHeadsUpDnd = false;
        mHeadsUpTimeout = 5;
        mProgressTracking = false;
        mVisibility = Visibility.DEFAULT;
        mVisibilityLs = VisibilityLs.DEFAULT;
        mSoundToVibrateDisabled = false;
        mHidePersistent = false;
        mLedDnd = "";
        mLedIgnoreUpdate = false;
    }

    protected static LedSettings getDefault(Context context) {
        return deserialize(context, "default");
    }

    protected static LedSettings createForPreview() {
        LedSettings settings = new LedSettings(null, "preview");
        settings.setEnabled(true);
        return settings;
    }

    protected static boolean isActiveScreenMasterEnabled(Context context) {
        try {
            SharedPreferences prefs = SettingsManager.getInstance(context).getLedControlPrefs();
            return prefs.getBoolean(PREF_KEY_ACTIVE_SCREEN_ENABLED, false);
        } catch (Throwable t) {
            t.printStackTrace();
            return false;
        }
    }

    protected static boolean isQuietHoursEnabled(Context context) {
        try {
            SharedPreferences prefs = SettingsManager.getInstance(context).getQuietHoursPrefs();
            return prefs.getBoolean(QuietHoursActivity.PREF_KEY_QH_ENABLED, false);
        } catch (Throwable t) {
            t.printStackTrace();
            return false;
        }
    }

    protected static boolean isHeadsUpEnabled(Context context) {
        try {
            SharedPreferences prefs = SettingsManager.getInstance(context).getMainPrefs();
            return prefs.getBoolean(GravityBoxSettings.PREF_KEY_HEADS_UP_MASTER_SWITCH, false);
        } catch (Throwable t) {
            t.printStackTrace();
            return false;
        }
    }

    protected static boolean isProximityWakeUpEnabled(Context context) {
        try {
            SharedPreferences prefs = SettingsManager.getInstance(context).getMainPrefs();
            return prefs.getBoolean(GravityBoxSettings.PREF_KEY_POWER_PROXIMITY_WAKE, false);
        } catch (Throwable t) {
            t.printStackTrace();
            return false;
        }
    }

    public static boolean isUncLocked(Context context) {
        try {
            SharedPreferences prefs = SettingsManager.getInstance(context).getLedControlPrefs();
            return prefs.getBoolean(PREF_KEY_LOCKED, false);
        } catch (Throwable t) {
            t.printStackTrace();
            return true;
        }
    }

    public static void lockUnc(final Context context, boolean lock) {
        try {
            WorldReadablePrefs prefs = SettingsManager.getInstance(context).getLedControlPrefs();
            prefs.edit().putBoolean(PREF_KEY_LOCKED, lock).commit(new OnPreferencesCommitedListener() {
                @Override
                public void onPreferencesCommited() {
                    if (WorldReadablePrefs.DEBUG)
                        Log.d("GravityBox", "LedSettings: lockUnc onPreferencesCommited UNC");
                    Intent intent = new Intent(ACTION_UNC_SETTINGS_CHANGED);
                    context.sendBroadcast(intent);
                }
            });
            prefs = SettingsManager.getInstance(context).getQuietHoursPrefs();
            prefs.edit().putBoolean(QuietHoursActivity.PREF_KEY_QH_LOCKED, lock).commit(
                    new OnPreferencesCommitedListener() {
                @Override
                public void onPreferencesCommited() {
                    if (WorldReadablePrefs.DEBUG)
                        Log.d("GravityBox", "LedSettings: lockUnc onPreferencesCommited QH");
                    Intent intent = new Intent(QuietHoursActivity.ACTION_QUIET_HOURS_CHANGED);
                    context.sendBroadcast(intent);
                }
            });
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    protected void setPackageName(String pkgName) {
        mPackageName = pkgName;
    }

    protected void setEnabled(boolean enabled) {
        mEnabled = enabled;
    }

    protected void setOngoing(boolean ongoing) {
        mOngoing = ongoing;
    }

    protected void setLedOnMs(int ms) {
        mLedOnMs = ms;
    }

    protected void setLedOffMs(int ms) {
        mLedOffMs = ms;
    }

    protected void setColor(int color) {
        mColor = color;
    }

    protected void setSoundOverride(boolean override) {
        mSoundOverride = override;
    }

    protected void setSoundUri(Uri soundUri) {
        mSoundUri = soundUri;
    }

    protected void setSoundReplace(boolean replace) {
        mSoundReplace = replace;
    }

    protected void setSoundOnlyOnce(boolean onlyOnce) {
        mSoundOnlyOnce = onlyOnce;
    }

    protected void setSoundOnlyOnceTimeout(long timeout) {
        mSoundOnlyOnceTimeout = timeout;
    }

    protected void setInsistent(boolean insistent) {
        mInsistent = insistent;
    }

    protected void setVibrateOverride(boolean override) {
        mVibrateOverride = override;
    }

    protected static long[] parseVibratePatternString(String patternStr) throws Exception {
        String[] vals = patternStr.split(",");
        long[] pattern = new long[vals.length];
        for (int i=0; i<pattern.length; i++) {
            pattern[i] = Long.valueOf(vals[i]);
        }
        return pattern;
    }

    protected void setVibratePatternFromString(String pattern) {
        mVibratePatternStr = pattern == null || pattern.isEmpty() ?
                null : pattern;
        mVibratePattern = null;
        if (mVibratePatternStr != null) {
            try {
                mVibratePattern = parseVibratePatternString(mVibratePatternStr);
            } catch (Exception e) {
                mVibratePatternStr = null;
            }
        }
    }

    protected void setVibrateReplace(boolean replace) {
        mVibrateReplace = replace;
    }

    protected void setActiveScreenMode(ActiveScreenMode mode) {
        mActiveScreenMode = mode;
    }

    protected void setActiveScreenIgnoreUpdate(boolean ignore) {
        mActiveScreenIgnoreUpdate = ignore;
    }

    protected void setLedMode(LedMode ledMode) {
        mLedMode = ledMode;
    }

    protected void setQhIgnore(boolean ignore) {
        mQhIgnore = ignore;
    }

    protected void setQhIgnoreList(String ignoreList) {
        mQhIgnoreList = ignoreList;
    }

    protected void setQhIgnoreInteractive (boolean ignore) {
        mQhIgnoreInteractive = ignore;
    }

    protected void setHeadsUpMode(HeadsUpMode mode) {
        mHeadsUpMode = mode;
    }

    protected void setHeadsUpMode(String mode) {
        try {
            setHeadsUpMode(HeadsUpMode.valueOf(mode));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void setHeadsUpDnd(boolean dnd) {
        mHeadsUpDnd = dnd;
    }

    protected void setHeadsUpTimeout(int timeout) {
        mHeadsUpTimeout = timeout;
    }

    protected void setProgressTracking(boolean tracking) {
        mProgressTracking = tracking;
    }

    protected void setVisibility(Visibility visibility) {
        mVisibility = visibility;
    }

    protected void setVisibility(String visibility) {
        try {
            setVisibility(Visibility.valueOf(visibility));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void setVisibilityLs(VisibilityLs visibilityLs) {
        mVisibilityLs = visibilityLs;
    }

    protected void setVisibilityLs(String visibilityLs) {
        try {
            setVisibilityLs(VisibilityLs.valueOf(visibilityLs));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void setSoundToVibrateDisabled(boolean disabled) {
        mSoundToVibrateDisabled = disabled;
    }

    protected void setHidePersistent(boolean hide) {
        mHidePersistent = hide;
    }

    protected void setLedDnd(String value) {
        mLedDnd = value;
    }

    protected void setLedIgnoreUpdate(boolean ignore) {
        mLedIgnoreUpdate = ignore;
    }

    public String getPackageName() {
        return mPackageName;
    }

    public boolean getEnabled() {
        return mEnabled;
    }

    public boolean getOngoing() {
        return mOngoing;
    }

    public int getLedOnMs() {
        return mLedOnMs;
    }

    public int getLedOffMs() {
        return mLedOffMs;
    }

    public int getColor() {
        return mColor;
    }

    public boolean getSoundOverride() {
        return mSoundOverride;
    }

    public Uri getSoundUri() {
        return mSoundUri;
    }

    public boolean getSoundReplace() {
        return mSoundReplace;
    }

    public boolean getSoundOnlyOnce() {
        return mSoundOnlyOnce;
    }

    public long getSoundOnlyOnceTimeout() {
        return mSoundOnlyOnceTimeout;
    }

    public boolean getInsistent() {
        return mInsistent;
    }

    public boolean getVibrateOverride() {
        return mVibrateOverride;
    }

    public String getVibratePatternAsString() {
        return mVibratePatternStr;
    }

    public long[] getVibratePattern() {
        return mVibratePattern;
    }

    public boolean getVibrateReplace() {
        return mVibrateReplace;
    }

    public ActiveScreenMode getActiveScreenMode() {
        return mActiveScreenMode;
    }

    public boolean getActiveScreenIgnoreUpdate() {
        return mActiveScreenIgnoreUpdate;
    }

    public LedMode getLedMode() {
        return mLedMode;
    }

    public boolean getQhIgnore() {
        return mQhIgnore;
    }

    public String getQhIgnoreList() {
        return mQhIgnoreList;
    }

    public boolean getQhIgnoreInteractive() {
        return mQhIgnoreInteractive;
    }

    public HeadsUpMode getHeadsUpMode() {
        return mHeadsUpMode;
    }

    public boolean getHeadsUpDnd() {
        return mHeadsUpDnd;
    }

    public int getHeadsUpTimeout() {
        return mHeadsUpTimeout;
    }

    public boolean getProgressTracking() {
        return mProgressTracking;
    }

    public Visibility getVisibility() {
        return mVisibility;
    }

    public VisibilityLs getVisibilityLs() {
        return mVisibilityLs;
    }

    public boolean getSoundToVibrateDisabled() {
        return mSoundToVibrateDisabled;
    }

    public boolean getHidePersistent() {
        return mHidePersistent;
    }

    public String getLedDnd() {
        return mLedDnd;
    }

    public boolean getLedIgnoreUpdate() {
        return mLedIgnoreUpdate;
    }

    private Set<String> createDataSet() {
        Set<String> dataSet = new HashSet<String>();

        dataSet.add("enabled:" + mEnabled);
        dataSet.add("ongoing:" + mOngoing);
        dataSet.add("ledOnMs:" + mLedOnMs);
        dataSet.add("ledOffMs:" + mLedOffMs);
        dataSet.add("color:" + mColor);
        dataSet.add("soundOverride:" + mSoundOverride);
        if (mSoundUri != null) {
            dataSet.add("sound:" + mSoundUri.toString());
        }
        dataSet.add("soundOnlyOnce:" + mSoundOnlyOnce);
        dataSet.add("soundOnlyOnceTimeoutMs:" + mSoundOnlyOnceTimeout);
        dataSet.add("insistent:" + mInsistent);
        dataSet.add("vibrateOverride:" + mVibrateOverride);
        if (mVibratePatternStr != null) {
            dataSet.add("vibratePattern:" + mVibratePatternStr);
        }
        dataSet.add("activeScreenMode:" + mActiveScreenMode);
        dataSet.add("activeScreenIgnoreUpdate:" + mActiveScreenIgnoreUpdate);
        dataSet.add("ledMode:" + mLedMode);
        dataSet.add("qhIgnore:" + mQhIgnore);
        if (mQhIgnoreList != null) {
            dataSet.add("qhIgnoreList:" + mQhIgnoreList);
        }
        dataSet.add("qhIgnoreInteractive:" + mQhIgnoreInteractive);
        dataSet.add("headsUpMode:" + mHeadsUpMode.toString());
        dataSet.add("headsUpDnd:" + mHeadsUpDnd);
        dataSet.add("headsUpTimeout:" + mHeadsUpTimeout);
        dataSet.add("progressTracking:" + mProgressTracking);
        dataSet.add("visibility:" + mVisibility.toString());
        dataSet.add("visibilityLs:" + mVisibilityLs.toString());
        dataSet.add("soundToVibrateDisabled:" + mSoundToVibrateDisabled);
        dataSet.add("vibrateReplace:" + mVibrateReplace);
        dataSet.add("soundReplace:" + mSoundReplace);
        dataSet.add("hidePersistent:" + mHidePersistent);
        dataSet.add("ledDnd:" + mLedDnd);
        dataSet.add("ledIgnoreUpdate:" + mLedIgnoreUpdate);

        return dataSet;
    }

    protected void serialize() {
        try {
            final Set<String> dataSet = createDataSet();
            WorldReadablePrefs prefs = SettingsManager.getInstance(mContext).getLedControlPrefs();
            prefs.edit().putStringSet(mPackageName, dataSet).commit(new OnPreferencesCommitedListener() {
                @Override
                public void onPreferencesCommited() {
                    if (WorldReadablePrefs.DEBUG)
                        Log.d("GravityBox", "LedSettings: serialize() onPreferencesCommited");
                    Intent intent = new Intent(ACTION_UNC_SETTINGS_CHANGED);
                    mContext.sendBroadcast(intent);
                }
            });
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    public ArrayList<String> toArrayList() {
        return new ArrayList<>(createDataSet());
    } 

    public String toString() {
        return "[" + mPackageName + "," + mEnabled + "," + mColor + "," + mLedOnMs +
                "," + mLedOffMs + "," + mOngoing + ";" + mSoundOverride + ";" +
                mSoundUri + ";" + mSoundOnlyOnce + ";" + mInsistent + "]";
    }
}

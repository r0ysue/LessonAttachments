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
package com.ceco.nougat.gravitybox.managers;

import java.util.ArrayList;
import java.util.List;

import com.ceco.nougat.gravitybox.BroadcastSubReceiver;
import com.ceco.nougat.gravitybox.GravityBox;
import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.Utils;

import android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.location.LocationManager;
import android.location.GnssStatus;
import android.os.UserManager;
import android.provider.Settings;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class GpsStatusMonitor implements BroadcastSubReceiver {
    public static final String TAG="GB:GpsStatusMonitor";
    private static boolean DEBUG = false;

    private static void log(String msg) {
        XposedBridge.log(TAG + ": " + msg);
    }

    public interface Listener {
        void onLocationModeChanged(int mode);
        void onGpsEnabledChanged(boolean gpsEnabled);
        void onGpsFixChanged(boolean gpsFixed);
    }

    private Context mContext;
    private int mLocationMode;
    private boolean mGpsEnabled;
    private boolean mGpsFixed;
    private boolean mGpsStatusTrackingActive;
    private LocationManager mLocMan;
    private final List<Listener> mListeners = new ArrayList<>();

    private GnssStatus.Callback mGnssStatusCallback = new GnssStatus.Callback() {
        @Override
        public void onStarted() {
            if (DEBUG) log("mGnssStatusCallback: onStarted()");
        }
        @Override
        public void onStopped() {
            if (DEBUG) log("mGnssStatusCallback: onStopped()");
            if (mGpsFixed) {
                mGpsFixed = false;
                notifyGpsFixChanged();
            }
        }
        @Override
        public void onFirstFix(int ttffMillis) {
            if (DEBUG) log("mGnssStatusCallback: onFirstFix(" + ttffMillis + ")");
            mGpsFixed = true;
            notifyGpsFixChanged();
        }
    };

    protected GpsStatusMonitor(Context context) {
        if (context == null)
            throw new IllegalArgumentException("Context cannot be null");

        mContext = context;
        mLocMan = (LocationManager) mContext.getSystemService(Context.LOCATION_SERVICE);

        mLocationMode = getLocationModeFromSettings();
        mGpsEnabled = (mLocationMode == Settings.Secure.LOCATION_MODE_HIGH_ACCURACY ||
                mLocationMode == Settings.Secure.LOCATION_MODE_SENSORS_ONLY);
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        if (intent.getAction().equals(LocationManager.MODE_CHANGED_ACTION)) {
            final boolean oldGpsEnabled = mGpsEnabled;
            final int oldLocationMode = mLocationMode;
            mLocationMode = getLocationModeFromSettings();
            if (mLocationMode != oldLocationMode) {
                notifyLocationModeChanged();
            }
            mGpsEnabled = mLocationMode == Settings.Secure.LOCATION_MODE_HIGH_ACCURACY ||
                    mLocationMode == Settings.Secure.LOCATION_MODE_SENSORS_ONLY;
            if (mGpsEnabled != oldGpsEnabled) {
                notifyGpsEnabledChanged();
                if (mGpsEnabled) {
                    startGpsStatusTracking();
                } else {
                    stopGpsStatusTracking();
                    if (mGpsFixed) {
                        mGpsFixed = false;
                        notifyGpsFixChanged();
                    }
                }
            }
            if (DEBUG) log("MODE_CHANGED_ACTION received: mode=" + mLocationMode + "; " +
                    "mGpsEnabled=" + mGpsEnabled);
        } else if (intent.getAction().equals(Intent.ACTION_LOCKED_BOOT_COMPLETED)) {
            if (mGpsEnabled) {
                startGpsStatusTracking();
            }
        }
    }

    @SuppressLint("MissingPermission")
    private void startGpsStatusTracking() {
        if (!mGpsStatusTrackingActive) {
            mGpsStatusTrackingActive = mLocMan.registerGnssStatusCallback(mGnssStatusCallback);
            if (DEBUG) log("startGpsStatusTracking: registerGnssStatusCallback returned: " + mGpsStatusTrackingActive);
        }
    }

    private void stopGpsStatusTracking() {
        if (mGpsStatusTrackingActive) {
            mLocMan.unregisterGnssStatusCallback(mGnssStatusCallback);
            mGpsStatusTrackingActive = false;
            if (DEBUG) log("stopGpsStatusTracking: GPS status tracking stopped");
        }
    }

    public int getLocationMode() {
        return mLocationMode;
    }

    public boolean isGpsEnabled() {
        return mGpsEnabled;
    }

    public boolean isGpsFixed() {
        return mGpsFixed;
    }

    public void setLocationMode(int mode) {
        final int currentUserId = Utils.getCurrentUser();
        if (!isUserLocationRestricted(currentUserId)) {
            try {
                final ContentResolver cr = mContext.getContentResolver();
                XposedHelpers.callStaticMethod(Settings.Secure.class, "putIntForUser",
                        cr, Settings.Secure.LOCATION_MODE, mode, currentUserId);
            } catch (Throwable t) {
                GravityBox.log(TAG, t);
            }
        }
    }

    public void setGpsEnabled(boolean enabled) {
        final int mode = enabled ? Settings.Secure.LOCATION_MODE_HIGH_ACCURACY :
            Settings.Secure.LOCATION_MODE_BATTERY_SAVING;
        setLocationMode(mode);
    }

    private int getLocationModeFromSettings() {
        try {
            final int currentUserId = Utils.getCurrentUser();
            final ContentResolver cr = mContext.getContentResolver();
            final int mode = (int) XposedHelpers.callStaticMethod(Settings.Secure.class, "getIntForUser",
                    cr, Settings.Secure.LOCATION_MODE, Settings.Secure.LOCATION_MODE_OFF, currentUserId);
            if (DEBUG) log("getLocationMode: mode=" + mode);
            return mode;
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return Settings.Secure.LOCATION_MODE_OFF;
        }
    }

    private boolean isUserLocationRestricted(int userId) {
        try {
            final UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
            return (boolean) XposedHelpers.callMethod(um, "hasUserRestriction",
                    UserManager.DISALLOW_SHARE_LOCATION,
                    Utils.getUserHandle(userId));
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return false;
        }
    }

    private void notifyLocationModeChanged() {
        synchronized (mListeners) {
            for (Listener l : mListeners) {
                l.onLocationModeChanged(mLocationMode);
            }
        }
    }

    private void notifyGpsEnabledChanged() {
        synchronized (mListeners) {
            for (Listener l : mListeners) {
                l.onGpsEnabledChanged(mGpsEnabled);
            }
        }
    }

    private void notifyGpsFixChanged() {
        synchronized (mListeners) {
            for (Listener l : mListeners) {
                l.onGpsFixChanged(mGpsFixed);
            }
        }
    }

    public void registerListener(Listener l) {
        if (l == null) return;
        synchronized (mListeners) {
            if (!mListeners.contains(l)) {
                mListeners.add(l);
            }
        }
    }

    public void unregisterListener(Listener l) {
        if (l == null) return;
        synchronized (mListeners) {
            if (mListeners.contains(l)) {
                mListeners.remove(l);
            }
        }
    }

    public static String getModeLabel(Context ctx, int currentState) {
        try {
            Context gbContext = Utils.getGbContext(ctx);
            switch (currentState) {
                case Settings.Secure.LOCATION_MODE_OFF:
                    return gbContext.getString(R.string.quick_settings_location_off);
                case Settings.Secure.LOCATION_MODE_BATTERY_SAVING:
                    return gbContext.getString(R.string.location_mode_battery_saving);
                case Settings.Secure.LOCATION_MODE_SENSORS_ONLY:
                    return gbContext.getString(R.string.location_mode_device_only);
                case Settings.Secure.LOCATION_MODE_HIGH_ACCURACY:
                    return gbContext.getString(R.string.location_mode_high_accuracy);
                default:
                    return gbContext.getString(R.string.qs_tile_gps);
             }
        } catch (Throwable e) {
            return String.valueOf(currentState);
        }
    }
}

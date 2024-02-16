/*
 * Copyright (C) 2016 Peter Gregus for GravityBox Project (C3C076@xda)
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

package com.ceco.nougat.gravitybox;

import de.robv.android.xposed.XposedHelpers;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.provider.Settings;
import com.ceco.nougat.gravitybox.R;

public class WifiManagerWrapper {
    private static final String TAG = "GB:WifiManagerWrapper";
    public static final String WIFI_AP_STATE_CHANGED_ACTION = "android.net.wifi.WIFI_AP_STATE_CHANGED";
    public static final String EXTRA_WIFI_AP_STATE = "wifi_state";

    public static final int WIFI_STATE_DISABLING = 0;
    public static final int WIFI_STATE_DISABLED = 1;
    public static final int WIFI_STATE_ENABLING = 2;
    public static final int WIFI_STATE_ENABLED = 3;
    public static final int WIFI_STATE_UNKNOWN = 4;
    public static final String WIFI_SAVED_STATE = "wifi_saved_state";
    
    public static final int WIFI_AP_STATE_DISABLING = 10;
    public static final int WIFI_AP_STATE_DISABLED = 11;
    public static final int WIFI_AP_STATE_ENABLING = 12;
    public static final int WIFI_AP_STATE_ENABLED = 13;
    public static final int WIFI_AP_STATE_FAILED = 14;

    private Context mContext;
    private WifiManager mWifiManager;
    private WifiApStateChangeListener mApStateChangeListener;
    private BroadcastReceiver mApStateChangeReceiver;
    private WifiStateChangeListener mWifiStateChangeListener;

    public interface WifiApStateChangeListener {
        void onWifiApStateChanged(int wifiApState);
    }

    public interface WifiStateChangeListener {
        void onWifiStateChanging(boolean enabling);
    }

    public WifiManagerWrapper(Context context, WifiApStateChangeListener listener) {
        mContext = context;
        mWifiManager = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);
        setWifiApStateChangeListener(listener);
    }

    public WifiManagerWrapper(Context context) {
        this(context, null);
    }

    public void setWifiApStateChangeListener(WifiApStateChangeListener listener) {
        if (listener == null) return;

        mApStateChangeListener = listener;
        registerApStateChangeReceiver();
    }

    public void setWifiStateChangeListener(WifiStateChangeListener listener) {
        if (listener != null) {
            mWifiStateChangeListener = listener;
        }
    }

    private void registerApStateChangeReceiver() {
        if (mContext == null || mApStateChangeReceiver != null)
            return;

        mApStateChangeReceiver = new BroadcastReceiver() {

            @Override
            public void onReceive(Context context, Intent intent) {
                if (intent.getAction().equals(WIFI_AP_STATE_CHANGED_ACTION) &&
                        intent.hasExtra(EXTRA_WIFI_AP_STATE)) {
                    int state = intent.getIntExtra(EXTRA_WIFI_AP_STATE, WIFI_AP_STATE_FAILED);
                    if (mApStateChangeListener != null) {
                        mApStateChangeListener.onWifiApStateChanged(state);
                    }
                }
            }
        };

        IntentFilter intentFilter = new IntentFilter(WIFI_AP_STATE_CHANGED_ACTION);
        mContext.registerReceiver(mApStateChangeReceiver, intentFilter);
    }

    public int getWifiState() {
        return mWifiManager.getWifiState();
    }

    public int getWifiApState() {
        return (Integer) XposedHelpers.callMethod(mWifiManager, "getWifiApState");
    }

    public String getWifiSsid() {
        WifiInfo wifiInfo = mWifiManager.getConnectionInfo();
        return (wifiInfo == null ? null : wifiInfo.getSSID());
    }

    public boolean isWifiEnabled() {
        return mWifiManager.isWifiEnabled();
    }

    public void setWifiEnabled(boolean enable) {
        setWifiEnabled(enable, false);
    }

    public void setWifiEnabled(final boolean enable, final boolean showToast) {
        new AsyncTask<Void,Void,Void>() {
            @Override
            protected Void doInBackground(Void... args) {
                final int wifiApState = getWifiApState();
                if (enable && (wifiApState == WifiManagerWrapper.WIFI_AP_STATE_ENABLING
                               || wifiApState == WifiManagerWrapper.WIFI_AP_STATE_ENABLED)) {
                    setWifiApEnabled(false);
                }
                return null;
            }
            @Override
            protected void onPostExecute(Void args) {
                if (mWifiStateChangeListener != null) {
                    mWifiStateChangeListener.onWifiStateChanging(enable);
                }
                mWifiManager.setWifiEnabled(enable);
                if (showToast) {
                    Utils.postToast(mContext, enable ? R.string.wifi_on :
                        R.string.wifi_off);
                }
            }
        }.execute();
    }

    public void toggleWifiEnabled(boolean showToast) {
        final boolean enable = 
                (getWifiState() != WifiManagerWrapper.WIFI_STATE_ENABLED);
        setWifiEnabled(enable, showToast);
    }

    public boolean isWifiApEnabled() {
        return (getWifiApState() == WIFI_AP_STATE_ENABLED);
    }

    public void setWifiApEnabled(boolean enable) {
        setWifiApEnabled(enable, false);
    }

    public void setWifiApEnabled(boolean enable, boolean showToast) {
        try {
            final ContentResolver cr = mContext.getContentResolver();

            int wifiState = getWifiState(); 
            if (enable && (wifiState == WIFI_STATE_ENABLING ||
                    wifiState == WIFI_STATE_ENABLED)) {
                setWifiEnabled(false);
                Settings.Global.putInt(cr, WIFI_SAVED_STATE, 1);
            }

            Class<?>[] paramArgs = new Class<?>[2];
            paramArgs[0] = WifiConfiguration.class;
            paramArgs[1] = boolean.class;
            XposedHelpers.callMethod(mWifiManager, "setWifiApEnabled", paramArgs, null, enable);

            if (showToast) {
                Utils.postToast(mContext, enable ? R.string.hotspot_on :
                    R.string.hotspot_off);
            }

            if (!enable) {
                int wifiSavedState = 0;
                try {
                    wifiSavedState = Settings.Global.getInt(cr, WIFI_SAVED_STATE);
                } catch (Settings.SettingNotFoundException e) {
                    //
                }
                if (wifiSavedState == 1) {
                    setWifiEnabled(true);
                    Settings.Global.putInt(cr, WIFI_SAVED_STATE, 0);
                }
            }
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }

    public void toggleWifiApEnabled(boolean showToast) {
        final int wifiApState = getWifiApState();
        if (wifiApState == WIFI_AP_STATE_ENABLED) {
            setWifiApEnabled(false, showToast);
        } else if (wifiApState == WIFI_AP_STATE_DISABLED) {
            setWifiApEnabled(true, showToast);
        }
    }
}
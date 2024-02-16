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
package com.ceco.nougat.gravitybox.managers;

import java.util.ArrayList;
import java.util.List;

import com.ceco.nougat.gravitybox.BroadcastSubReceiver;
import com.ceco.nougat.gravitybox.GravityBox;
import com.ceco.nougat.gravitybox.GravityBoxService;
import com.ceco.nougat.gravitybox.Utils;
import com.ceco.nougat.gravitybox.ledcontrol.QuietHours;
import com.ceco.nougat.gravitybox.ledcontrol.QuietHoursActivity;

import de.robv.android.xposed.XSharedPreferences;
import android.content.Context;
import android.content.Intent;

public class StatusbarQuietHoursManager implements BroadcastSubReceiver {
    private static final String TAG = "GB:StatusbarQuietHoursManager";
    private static final Object lock = new Object();
    private static StatusbarQuietHoursManager sManager;

    private Context mContext;
    private XSharedPreferences mQhPrefs;
    private QuietHours mQuietHours;
    private List<QuietHoursListener> mListeners;

    public interface QuietHoursListener {
        void onQuietHoursChanged();
        void onTimeTick();
    }

    protected static StatusbarQuietHoursManager getInstance(Context context, XSharedPreferences qhPrefs) {
        synchronized(lock) {
            if (sManager == null) {
                sManager = new StatusbarQuietHoursManager(context, qhPrefs);
            }
            return sManager;
        }
    }

    private StatusbarQuietHoursManager(Context context, XSharedPreferences qhPrefs) {
        mContext = context;
        mQhPrefs = qhPrefs;
        mListeners = new ArrayList<QuietHoursListener>();

        refreshState();
    }

    @Override
    public void onBroadcastReceived(Context context, Intent intent) {
        final String action = intent.getAction();
        if (action.equals(Intent.ACTION_TIME_TICK) ||
                action.equals(Intent.ACTION_TIME_CHANGED) ||
                action.equals(Intent.ACTION_TIMEZONE_CHANGED)) {
            notifyTimeTick();
        } else if (action.equals(QuietHoursActivity.ACTION_QUIET_HOURS_CHANGED)) {
            refreshState();
            notifyQuietHoursChange();
        }
    }

    public void registerListener(QuietHoursListener listener) {
        if (listener == null) return;

        if (!mListeners.contains(listener)) {
            mListeners.add(listener);
        }
    }

    public void unregisterListener(QuietHoursListener listener) {
        if (listener == null) return;

        if (mListeners.contains(listener)) {
            mListeners.remove(listener);
        }
    }

    private void refreshState() {
        mQhPrefs.reload();
        mQuietHours = new QuietHours(mQhPrefs);
    }

    private void notifyTimeTick() {
        for (QuietHoursListener l : mListeners) {
            l.onTimeTick();
        }
    }

    private void notifyQuietHoursChange() {
        for (QuietHoursListener l : mListeners) {
            l.onQuietHoursChanged();
        }
    }

    public QuietHours getQuietHours() {
        return mQuietHours;
    }

    public void setMode(QuietHours.Mode mode) {
        try {
            Context gbContext = Utils.getGbContext(mContext);
            Intent intent = new Intent(gbContext, GravityBoxService.class);
            intent.setAction(QuietHoursActivity.ACTION_SET_QUIET_HOURS_MODE);
            intent.putExtra(QuietHoursActivity.EXTRA_QH_MODE, mode.toString());
            gbContext.startService(intent);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
        }
    }
}

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

package com.ceco.nougat.gravitybox;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.text.TextUtils;
import android.util.Log;

import com.ceco.nougat.gravitybox.R;

public class TorchService extends Service {
    private static final String TAG = "GB:TorchService";
    private static final boolean DEBUG = false;

    public static final String ACTION_TOGGLE_TORCH = "gravitybox.intent.action.TOGGLE_TORCH";
    public static final String ACTION_TORCH_STATUS_CHANGED = "gravitybox.intent.action.TORCH_STATUS_CHANGED";
    public static final String ACTION_TORCH_GET_STATUS = "gravitybox.intent.action.TORCH_GET_STATUS";
    private static final String ACTION_TORCH_TIMEOUT = "gravitybox.intent.action.TORCH_TIMEOUT";
    public static final String EXTRA_TORCH_STATUS = "torchStatus";
    public static final int TORCH_STATUS_OFF = 0;
    public static final int TORCH_STATUS_ON = 1;
    public static final int TORCH_STATUS_ERROR = -1;
    public static final int TORCH_STATUS_UNKNOWN = -2;

    private CameraManager mCameraManager;
    private String mCameraId;
    private int mTorchStatus;
    private Notification mTorchNotif;
    private Intent mStartIntent;
    private AlarmManager mAlarmManager;
    private PendingIntent mPendingIntent;

    private final CameraManager.TorchCallback mTorchCallback =
            new CameraManager.TorchCallback() {
        @Override
        public void onTorchModeUnavailable(String cameraId) {
            if (DEBUG) Log.d(TAG, "onTorchModeUnavailable: cameraId=" + cameraId);
            if (TextUtils.equals(cameraId, getCameraId())) {
                resetTimeout();
                mTorchStatus = TORCH_STATUS_ERROR;
                maybeProcessStartIntent();
                TorchService.this.stopForeground(true);
                broadcastStatus();
                stopSelf();
            }
        }
        @Override
        public void onTorchModeChanged(String cameraId, boolean enabled) {
            if (DEBUG) Log.d(TAG, "onTorchModeChanged: cameraId=" + cameraId +
                    "; enabled=" + enabled);
            if (TextUtils.equals(cameraId, getCameraId())) {
                resetTimeout();
                if (enabled) {
                    mTorchStatus = TORCH_STATUS_ON;
                    TorchService.this.startForeground(2, mTorchNotif);
                    broadcastStatus();
                    setupTimeout();
                } else {
                    mTorchStatus = TORCH_STATUS_OFF;
                    TorchService.this.stopForeground(true);
                    broadcastStatus();
                }
                maybeProcessStartIntent();
            }
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        mTorchStatus = TORCH_STATUS_UNKNOWN;

        Intent intent = new Intent(this, TorchService.class);
        intent.setAction(ACTION_TOGGLE_TORCH);
        PendingIntent stopIntent = PendingIntent.getService(this, 0, intent, 0);

        Notification.Builder builder = new Notification.Builder(this);
        builder.setVisibility(Notification.VISIBILITY_PUBLIC);
        builder.setContentTitle(getString(R.string.quick_settings_torch_on));
        builder.setSmallIcon(R.drawable.ic_qs_torch_on);
        Bitmap b = BitmapFactory.decodeResource(getResources(), R.drawable.ic_qs_torch_on);
        builder.setLargeIcon(b);
        builder.addAction(new Notification.Action.Builder(null,
                getString(R.string.turn_off), stopIntent).build());
        mTorchNotif = builder.build();

        mAlarmManager = (AlarmManager) getSystemService(Context.ALARM_SERVICE);

        mCameraManager = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
        mCameraManager.registerTorchCallback(mTorchCallback, null);

        if (DEBUG) Log.d(TAG, "onCreate");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            if (ACTION_TOGGLE_TORCH.equals(intent.getAction()) ||
                    ACTION_TORCH_GET_STATUS.equals(intent.getAction())) {
                mStartIntent = intent;
                maybeProcessStartIntent();
                return START_NOT_STICKY;
            } else if (ACTION_TORCH_TIMEOUT.equals(intent.getAction())) {
                if (DEBUG) Log.d(TAG, "Received torch timeout intent");
                setTorchOff();
                return START_NOT_STICKY;
            }
        }
        stopSelf();
        return START_NOT_STICKY;
    }

    private void maybeProcessStartIntent() {
        if (mStartIntent == null || mTorchStatus == TORCH_STATUS_UNKNOWN) return;

        if (ACTION_TOGGLE_TORCH.equals(mStartIntent.getAction())) {
            if (DEBUG) Log.d(TAG, "maybeProcessStartIntent: ACTION_TOGGLE_TORCH");
            toggleTorch();
        } else if (ACTION_TORCH_GET_STATUS.equals(mStartIntent.getAction())) {
            if (DEBUG) Log.d(TAG, "maybeProcessStartIntent: " +
                    "ACTION_TORCH_GET_STATUS: mTorchStatus=" + mTorchStatus);
            ResultReceiver receiver = mStartIntent.getParcelableExtra("receiver");
            Bundle data = new Bundle();
            data.putInt(EXTRA_TORCH_STATUS, mTorchStatus);
            receiver.send(0, data);
        }
        mStartIntent = null;
    }

    private String getCameraId() {
        if (mCameraId == null) {
            try {
                String[] ids = mCameraManager.getCameraIdList();
                for (String id : ids) {
                    CameraCharacteristics c = mCameraManager.getCameraCharacteristics(id);
                    Boolean flashAvailable = c.get(CameraCharacteristics.FLASH_INFO_AVAILABLE);
                    Integer lensFacing = c.get(CameraCharacteristics.LENS_FACING);
                    if (flashAvailable != null && flashAvailable && lensFacing != null && 
                            lensFacing == CameraCharacteristics.LENS_FACING_BACK) {
                        mCameraId = id;
                    }
                }
                if (DEBUG) Log.d(TAG, "getCameraId: " + mCameraId);
            } catch (Exception e) {
                e.printStackTrace();
                mTorchStatus = TORCH_STATUS_ERROR;
                broadcastStatus();
                stopSelf();
            }
        }
        return mCameraId;
    }

    private synchronized void toggleTorch() {
        if (mTorchStatus == TORCH_STATUS_OFF) {
            setTorchOn();
        } else if (mTorchStatus == TORCH_STATUS_ON) {
            setTorchOff();
        }
    }

    private synchronized void setTorchOn() {
        if (mTorchStatus != TORCH_STATUS_OFF) return;
        try {
            mCameraManager.setTorchMode(getCameraId(), true);
            if (DEBUG) Log.d(TAG, "setTorchOn");
        } catch (Exception e) {
            e.printStackTrace();
            mTorchStatus = TORCH_STATUS_ERROR;
            broadcastStatus();
            stopSelf();
        }
    }

    private synchronized void setTorchOff() {
        if (mTorchStatus != TORCH_STATUS_ON) return;
        try {
            mCameraManager.setTorchMode(getCameraId(), false);
            if (DEBUG) Log.d(TAG, "setTorchOff");
        } catch (Exception e) {
            e.printStackTrace();
            mTorchStatus = TORCH_STATUS_ERROR;
            stopForeground(true);
            broadcastStatus();
            stopSelf();
        }
    }

    private void broadcastStatus() {
        Intent i = new Intent(ACTION_TORCH_STATUS_CHANGED);
        i.putExtra(EXTRA_TORCH_STATUS, mTorchStatus);
        sendBroadcast(i);
        if (DEBUG) Log.d(TAG, "broadcastStatus: mTorchStatus=" + mTorchStatus);
    }

    private void setupTimeout() {
        SharedPreferences prefs = SettingsManager.getInstance(this).getMainPrefs();
        int torchTimeout = prefs.getInt(GravityBoxSettings.PREF_KEY_TORCH_AUTO_OFF, 10)*60*1000;
        if (torchTimeout > 0) {
            Intent intent = new Intent(this, TorchService.class);
            intent.setAction(ACTION_TORCH_TIMEOUT);
            mPendingIntent = PendingIntent.getService(this, 1, intent, PendingIntent.FLAG_ONE_SHOT);
            long triggerAtMillis = System.currentTimeMillis() + torchTimeout;
            mAlarmManager.setExact(AlarmManager.RTC_WAKEUP, triggerAtMillis, mPendingIntent);
        }
    }

    private void resetTimeout() {
        if (mPendingIntent != null) {
            mAlarmManager.cancel(mPendingIntent);
            mPendingIntent = null;
        }
    }

    @Override
    public void onDestroy() {
        if (DEBUG) Log.d(TAG, "onDestroy");
        setTorchOff();
        resetTimeout();
        mCameraManager.unregisterTorchCallback(mTorchCallback);
        mCameraId = null;
        mCameraManager = null;
        mTorchNotif = null;
        mStartIntent = null;
        mAlarmManager = null;
        super.onDestroy();
    }
}

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

package com.ceco.nougat.gravitybox;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.MediaRecorder;
import android.os.Bundle;
import android.os.Environment;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.util.Log;

import com.ceco.nougat.gravitybox.R;

public class RecordingService extends Service {
    private static final String TAG = "GB:RecordingService";

    public static final String ACTION_RECORDING_START = "gravitybox.intent.action.RECORDING_START";
    public static final String ACTION_RECORDING_STOP = "gravitybox.intent.action.RECORDING_STOP";
    public static final String ACTION_RECORDING_GET_STATUS = "gravitybox.intent.action.RECORDING_GET_STATUS";
    public static final String ACTION_RECORDING_STATUS_CHANGED = "gravitybox.intent.action.RECORDING_STATUS_CHANGED";
    public static final String EXTRA_RECORDING_STATUS = "recordingStatus";
    public static final String EXTRA_STATUS_MESSAGE = "statusMessage";
    public static final String EXTRA_AUDIO_FILENAME = "audioFileName";
    public static final String EXTRA_SAMPLING_RATE = "samplingRate";

    public static final int RECORDING_STATUS_IDLE = 0;
    public static final int RECORDING_STATUS_STARTED = 1;
    public static final int RECORDING_STATUS_STOPPED = 2;
    public static final int RECORDING_STATUS_ERROR = -1;

    public static final int DEFAULT_SAMPLING_RATE = 22050;

    private MediaRecorder mRecorder;
    private int mRecordingStatus = RECORDING_STATUS_IDLE;
    private Notification mRecordingNotif;
    private PendingIntent mPendingIntent;
    private int mSamplingRate = DEFAULT_SAMPLING_RATE;
    private String mLastAudioFileName;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        mRecordingStatus = RECORDING_STATUS_IDLE;

        Notification.Builder builder = new Notification.Builder(this);
        builder.setContentTitle(getString(R.string.quick_settings_qr_recording));
        builder.setContentText(getString(R.string.quick_settings_qr_recording_notif));
        builder.setSmallIcon(R.drawable.ic_qs_qr_recording);
        Bitmap b = BitmapFactory.decodeResource(getResources(), R.drawable.ic_qs_qr_recording);
        builder.setLargeIcon(b);
        Intent intent = new Intent(ACTION_RECORDING_STOP);
        mPendingIntent = PendingIntent.getService(this, 0, intent, 0);
        builder.setContentIntent(mPendingIntent);
        mRecordingNotif = builder.build();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getAction() != null) {
            if (intent.getAction().equals(ACTION_RECORDING_START)) {
                if (intent.hasExtra(EXTRA_SAMPLING_RATE)) {
                    mSamplingRate = intent.getIntExtra(EXTRA_SAMPLING_RATE, DEFAULT_SAMPLING_RATE);
                }
                startRecording();
                return START_STICKY;
            } else if (intent.getAction().equals(ACTION_RECORDING_STOP)) {
                stopRecording();
                return START_STICKY;
            } else if (intent.getAction().equals(ACTION_RECORDING_GET_STATUS)) {
                ResultReceiver receiver = intent.getParcelableExtra("receiver");
                Bundle data = new Bundle();
                data.putInt(EXTRA_RECORDING_STATUS, mRecordingStatus);
                if (mLastAudioFileName != null) {
                    data.putString(EXTRA_AUDIO_FILENAME, mLastAudioFileName);
                }
                receiver.send(0, data);
                return START_STICKY;
            }
        }

        stopSelf();
        return START_NOT_STICKY;
    }

    MediaRecorder.OnErrorListener mOnErrorListener = new MediaRecorder.OnErrorListener() {

        @Override
        public void onError(MediaRecorder mr, int what, int extra) {
            mRecordingStatus = RECORDING_STATUS_ERROR;

            String statusMessage = "Error in MediaRecorder while recording: " + what + "; " + extra;
            Intent i = new Intent(ACTION_RECORDING_STATUS_CHANGED);
            i.putExtra(EXTRA_RECORDING_STATUS, mRecordingStatus);
            i.putExtra(EXTRA_STATUS_MESSAGE, statusMessage);
            sendBroadcast(i);
            stopForeground(true);
        }
    };

    private String prepareOutputFile() {
        File outputDir = new File(Environment.getExternalStorageDirectory() + "/AudioRecordings");
        if (!outputDir.exists()) {
            if (!outputDir.mkdir()) {
                Log.e(TAG, "Cannot create AudioRecordings directory");
                return null;
            }
        }
        String fileName = "AUDIO_" + new SimpleDateFormat(
                "yyyyMMdd_HHmmss", Locale.US).format(new Date()) + ".mp4";
        return (outputDir.getAbsolutePath() + "/" + fileName);
    }

    private void startRecording() {
        String statusMessage = "";
        mLastAudioFileName = prepareOutputFile();
        if (mLastAudioFileName == null)
            return;

        try {
            mRecorder = new MediaRecorder();
            mRecorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            mRecorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
            mRecorder.setOutputFile(mLastAudioFileName);
            mRecorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
            mRecorder.setAudioEncodingBitRate(96000);
            mRecorder.setAudioSamplingRate(mSamplingRate);
            mRecorder.setOnErrorListener(mOnErrorListener);
            mRecorder.prepare();
            mRecorder.start();
            mRecordingStatus = RECORDING_STATUS_STARTED;
            startForeground(1, mRecordingNotif);
        } catch (Exception e) {
            e.printStackTrace();
            mRecordingStatus = RECORDING_STATUS_ERROR;
            statusMessage = e.getMessage();
        } finally {
            Intent i = new Intent(ACTION_RECORDING_STATUS_CHANGED);
            i.putExtra(EXTRA_RECORDING_STATUS, mRecordingStatus);
            if (mRecordingStatus == RECORDING_STATUS_STARTED) {
                i.putExtra(EXTRA_AUDIO_FILENAME, mLastAudioFileName);
            }
            i.putExtra(EXTRA_STATUS_MESSAGE, statusMessage); 
            sendBroadcast(i);
        }
    }

    private void stopRecording() {
        if (mRecorder == null) return;

        String statusMessage = "";
        try {
            mRecorder.stop();
            mRecorder.release();
            mRecorder = null;
            mRecordingStatus = RECORDING_STATUS_STOPPED;
        } catch (Exception e) {
            e.printStackTrace();
            mRecordingStatus = RECORDING_STATUS_ERROR;
            statusMessage = e.getMessage();
        } finally {
            Intent i = new Intent(ACTION_RECORDING_STATUS_CHANGED);
            i.putExtra(EXTRA_RECORDING_STATUS, mRecordingStatus);
            i.putExtra(EXTRA_STATUS_MESSAGE, statusMessage);
            sendBroadcast(i);
            stopForeground(true);
        }
    }

    @Override
    public void onDestroy() {
        stopRecording();
        super.onDestroy();
    }
}
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
package com.ceco.nougat.gravitybox.visualizer;

import com.ceco.nougat.gravitybox.GravityBoxSettings;
import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.Utils;
import com.ceco.nougat.gravitybox.ModStatusBar.StatusBarState;

import android.content.Context;
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;

public class NavbarVisualizerLayout extends AVisualizerLayout {

    private static final String TAG = "GB:NavbarVisualizerLayout";
    private static final boolean DEBUG = false;

    private static void log(String message) {
        XposedBridge.log(TAG + ": " + message);
    }

    private boolean mEnabled;

    public NavbarVisualizerLayout(Context context) throws Throwable {
        super(context);
    }

    @Override
    public void initPreferences(XSharedPreferences prefs) {
        super.initPreferences(prefs);
        mEnabled = prefs.getBoolean(GravityBoxSettings.PREF_KEY_VISUALIZER_NAVBAR, false);
    }

    @Override
    public void onPreferenceChanged(Intent intent) {
        super.onPreferenceChanged(intent);
        if (intent.hasExtra(GravityBoxSettings.EXTRA_VISUALIZER_NAVBAR)) {
            mEnabled = intent.getBooleanExtra(GravityBoxSettings.EXTRA_VISUALIZER_NAVBAR, false);
        }
    }

    @Override
    public void onCreateView(ViewGroup parent) throws Throwable {
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT);
        setLayoutParams(lp);
        parent.addView(this, 0);

        LayoutInflater inflater = LayoutInflater.from(Utils.getGbContext(getContext(),
                getContext().getResources().getConfiguration()));
        inflater.inflate(R.layout.navbarvisualizer, this);
        mVisualizerView = new VisualizerView(getContext());
        mVisualizerView.setDbCapValue(4f);
        mVisualizerView.setSupportsVerticalPosition(true);
        int idx = indexOfChild(findViewById(R.id.visualizer));
        removeViewAt(idx);
        addView(mVisualizerView, idx);
    }

    @Override
    boolean supportsCurrentStatusBarState() {
        return mStatusBarState == StatusBarState.SHADE;
    }

    @Override
    public boolean isEnabled() {
        return super.isEnabled() && mEnabled;
    }
}

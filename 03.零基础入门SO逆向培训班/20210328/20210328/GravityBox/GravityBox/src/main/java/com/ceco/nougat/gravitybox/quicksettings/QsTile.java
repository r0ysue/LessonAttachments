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
package com.ceco.nougat.gravitybox.quicksettings;

import java.lang.reflect.Constructor;

import com.ceco.nougat.gravitybox.GravityBox;
import com.ceco.nougat.gravitybox.Utils;
import com.ceco.nougat.gravitybox.quicksettings.QsPanel.LockedTileIndicator;

import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedHelpers;

public abstract class QsTile extends BaseTile {
    public static final String CLASS_CUSTOM_TILE = "com.android.systemui.qs.external.CustomTile";
    private static Constructor<?> sDrawableIconClassConstructor;

    protected State mState;

    public static QsTile create(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {

        Context ctx = (Context) XposedHelpers.callMethod(host, "getContext");

        if (key.contains(GravityBoxTile.Service.KEY))
            return new GravityBoxTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(NetworkModeTile.Service.KEY))
            return new NetworkModeTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(ExpandedDesktopTile.Service.KEY))
            return new ExpandedDesktopTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(GpsTile.Service.KEY))
            return new GpsTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(LocationTileSlimkat.Service.KEY))
            return new LocationTileSlimkat(host, key, tile, prefs, eventDistributor);
        else if (key.contains(LockScreenTile.Service.KEY))
            return new LockScreenTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(NfcTile.Service.KEY) && Utils.hasNfc(ctx))
            return new NfcTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(QuickAppTile.Service1.KEY))
            return new QuickAppTile(host, key, tile, prefs, eventDistributor, 1);
        else if (key.contains(QuickAppTile.Service2.KEY))
            return new QuickAppTile(host, key, tile, prefs, eventDistributor, 2);
        else if (key.contains(QuickAppTile.Service3.KEY))
            return new QuickAppTile(host, key, tile, prefs, eventDistributor, 3);
        else if (key.contains(QuickAppTile.Service4.KEY))
            return new QuickAppTile(host, key, tile, prefs, eventDistributor, 4);
        else if (key.contains(QuickRecordTile.Service.KEY))
            return new QuickRecordTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(QuietHoursTile.Service.KEY))
            return new QuietHoursTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(RingerModeTile.Service.KEY))
            return new RingerModeTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(ScreenshotTile.Service.KEY))
            return new ScreenshotTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(SleepTile.Service.KEY))
            return new SleepTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(SmartRadioTile.Service.KEY))
            return new SmartRadioTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(StayAwakeTile.Service.KEY))
            return new StayAwakeTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(SyncTile.Service.KEY))
            return new SyncTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(TorchTile.Service.KEY))
            return new TorchTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(VolumeTile.Service.KEY))
            return new VolumeTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(CompassTile.Service.KEY))
            return new CompassTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(UsbTetherTile.Service.KEY))
            return new UsbTetherTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(BluetoothTetheringTile.Service.KEY))
            return new BluetoothTetheringTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(AmbientDisplayTile.Service.KEY))
            return new AmbientDisplayTile(host, key, tile, prefs, eventDistributor);
        else if (key.contains(HeadsUpTile.Service.KEY))
            return new HeadsUpTile(host, key, tile, prefs, eventDistributor);

        return null;
    }

    protected QsTile(Object host, String key, Object tile, XSharedPreferences prefs,
            QsTileEventDistributor eventDistributor) throws Throwable {
        super(host, key, tile, prefs, eventDistributor);

        mState = new State();
        if (sDrawableIconClassConstructor == null) {
            sDrawableIconClassConstructor = getDrawableIconClassConstructor(mContext.getClassLoader());
        }
    }

    @Override
    public boolean handleLongClick() {
        return true;
    }

    @Override
    public void handleUpdateState(Object state, Object arg) {
        mState.locked = isLocked();
        mState.lockedTileIndicator = getQsPanel().getLockedTileIndicator();
        mState.applyTo(state);
    }

    @Override
    public void handleDestroy() {
        super.handleDestroy();
        mState = null;
        if (DEBUG) log(mKey + ": handleDestroy called");
    }

    protected boolean supportsIconTinting() {
        return Utils.isOxygenOsRom();
    }

    private Integer getTintColor(boolean state) {
        try {
            final Class<?> cls = XposedHelpers.findClass(
                    BaseTile.CLASS_ICON_VIEW, mContext.getClassLoader());
            return XposedHelpers.getStaticIntField(cls,
                    state ? "sIconColor" : "sCustomDisableIconColor");
        } catch (Throwable t) {
            GravityBox.log("Error getting QsTile tint color: ", t);
            return null;
        }
    }

    protected final Object iconFromResId(int resId) {
        return iconFromDrawable(mGbContext.getDrawable(resId));
    }

    protected final Object iconFromDrawable(Drawable d) {
        try {
            d.setTintList(null);
            if (supportsIconTinting()) {
                Integer color = getTintColor(mState.booleanValue);
                if (color != null) {
                    d.setTint(color);
                }
                d.setAlpha(isLocked() && getQsPanel().getLockedTileIndicator() == LockedTileIndicator.DIM ? 80 : 255);
            } else if (!(this instanceof QuickAppTile)) {
                d.clearColorFilter();
                if (isLocked() && getQsPanel().getLockedTileIndicator() == LockedTileIndicator.DIM) {
                    d.setColorFilter(COLOR_LOCKED, PorterDuff.Mode.SRC_IN);
                }
            }
            return sDrawableIconClassConstructor.newInstance(d);
        } catch (Throwable t) {
            GravityBox.log(TAG, t);
            return null;
        }
    }

    private static Constructor<?> getDrawableIconClassConstructor(ClassLoader cl) {
        try {
            Class<?> c = XposedHelpers.findClass(CLASS_BASE_TILE+".DrawableIcon", cl);
            return c.getConstructor(Drawable.class);
        } catch (Throwable t) {
            log("Error getting drawable icon class constructor:");
            GravityBox.log(TAG, t);
            return null;
        }
    }

    public static class State {
        public Object icon;
        public String label = "";
        public boolean autoMirrorDrawable = true;
        public boolean booleanValue = true;
        public boolean locked;
        public LockedTileIndicator lockedTileIndicator;

        public void applyTo(Object state) {
            XposedHelpers.setObjectField(state, "icon", icon);
            String newLabel = label;
            if (locked && (lockedTileIndicator == LockedTileIndicator.PADLOCK ||
                    lockedTileIndicator == LockedTileIndicator.KEY)) {
                newLabel = String.format("%s %s",
                        (lockedTileIndicator == LockedTileIndicator.PADLOCK ?
                         QsPanel.IC_PADLOCK : QsPanel.IC_KEY), label);
            }
            XposedHelpers.setObjectField(state, "label", newLabel);
            XposedHelpers.setBooleanField(state, "autoMirrorDrawable", autoMirrorDrawable);
        }
    }
}

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

package com.ceco.nougat.gravitybox.shortcuts;

import java.util.ArrayList;
import java.util.List;

import com.ceco.nougat.gravitybox.ModStatusBar;
import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.adapters.IIconListAdapterItem;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;

public class ExpandQuicksettingsShortcut extends AMultiShortcut {
    protected static final String ACTION =  ModStatusBar.ACTION_EXPAND_QUICKSETTINGS;

    public ExpandQuicksettingsShortcut(Context context) {
        super(context);
    }

    @Override
    public String getText() {
        return mContext.getString(R.string.qs_panel_toggle);
    }

    @Override
    public Drawable getIconLeft() {
        return mContext.getDrawable(R.drawable.shortcut_quicksettings);
    }

    @Override
    protected String getAction() {
        return ACTION;
    }

    @Override
    protected String getShortcutName() {
        return getText();
    }

    @Override
    protected List<IIconListAdapterItem> getShortcutList() {
        final List<IIconListAdapterItem> list = new ArrayList<>();
        list.add(new ShortcutItem(mContext, R.string.qs_panel_toggle,
                R.drawable.shortcut_quicksettings, null));
        list.add(new ShortcutItem(mContext, R.string.hwkey_action_expand_quicksettings,
                R.drawable.shortcut_quicksettings_expand, new ExtraDelegate() {
                @Override
                public void addExtraTo(Intent intent) {
                    intent.putExtra(EXTRA_ENABLE, true);
                }
        }));
        list.add(new ShortcutItem(mContext, R.string.qs_panel_collapse,
                R.drawable.shortcut_quicksettings_collapse, new ExtraDelegate() {
                @Override
                public void addExtraTo(Intent intent) {
                    intent.putExtra(EXTRA_ENABLE, false);
                }
        }));

        return list;
    }

    public static void launchAction(Context context, Intent intent) {
        Intent launchIntent = new Intent(ACTION);
        launchIntent.putExtras(intent.getExtras());
        context.sendBroadcast(launchIntent);
    }
}

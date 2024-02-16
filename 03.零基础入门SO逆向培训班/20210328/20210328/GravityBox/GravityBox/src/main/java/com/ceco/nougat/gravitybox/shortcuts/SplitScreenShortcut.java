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

package com.ceco.nougat.gravitybox.shortcuts;

import com.ceco.nougat.gravitybox.ModHwKeys;
import com.ceco.nougat.gravitybox.R;

import android.content.Context;
import android.content.Intent;
import android.content.Intent.ShortcutIconResource;
import android.graphics.drawable.Drawable;

public class SplitScreenShortcut extends AShortcut {
    protected static final String ACTION =  ModHwKeys.ACTION_TOGGLE_SPLIT_SCREEN;

    public SplitScreenShortcut(Context context) {
        super(context);
    }

    @Override
    public String getText() {
        return mContext.getString(R.string.hwkey_action_split_screen);
    }

    @Override
    public Drawable getIconLeft() {
        return mContext.getDrawable(R.drawable.shortcut_split_screen);
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
    protected ShortcutIconResource getIconResource() {
        return ShortcutIconResource.fromContext(mContext, R.drawable.shortcut_split_screen);
    }

    public static void launchAction(final Context context, Intent intent) {
        Intent launchIntent = new Intent(ACTION);
        context.sendBroadcast(launchIntent);
    }
}

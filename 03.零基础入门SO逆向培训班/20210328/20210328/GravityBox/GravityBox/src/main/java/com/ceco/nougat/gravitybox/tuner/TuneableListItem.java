/*
 * Copyright (C) 2019 Peter Gregus for GravityBox Project (C3C076@xda)
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
package com.ceco.nougat.gravitybox.tuner;

import android.content.Context;

import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.adapters.IBaseListAdapterItem;

import java.util.Locale;

public class TuneableListItem implements IBaseListAdapterItem {

    private Context mContext;
    private TuneableItem mItem;

    TuneableListItem(Context context, TuneableItem item) {
        mContext = context;
        mItem = item;
    }

    protected TuneableItem getItem() {
        return mItem;
    }

    @Override
    public String getText() {
        return mItem.getKey();
    }

    @Override
    public String getSubText() {
        return String.format(Locale.getDefault(), "%s: %s",
                mContext.getString(R.string.tuneable_current_value),
                String.valueOf(mItem.getValue()));
    }

    boolean requiresReboot() {
        return mItem.isOverridden() && !mItem.getValue().equals(mItem.getUserValue());
    }

    String getOverrideText() {
        String buf = null;
        if (requiresReboot()) {
            buf = String.format(Locale.getDefault(), "%s: %s (%s)",
                    mContext.getString(R.string.tuneable_overridden_value),
                    String.valueOf(mItem.getUserValue()),
                    mContext.getString(R.string.tuneable_reboot_required));
        }
        return buf;
    }

}

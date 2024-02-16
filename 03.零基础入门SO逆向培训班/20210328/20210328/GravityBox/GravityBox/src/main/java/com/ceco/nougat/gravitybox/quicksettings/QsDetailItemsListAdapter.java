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
package com.ceco.nougat.gravitybox.quicksettings;

import java.util.List;

import com.ceco.nougat.gravitybox.Utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.CheckedTextView;

public abstract class QsDetailItemsListAdapter<T> extends ArrayAdapter<T> {

    public QsDetailItemsListAdapter(Context context, List<T> list) {
        super(context, android.R.layout.simple_list_item_single_choice, list);
    }

    @SuppressLint("ViewHolder")
    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        LayoutInflater inflater = LayoutInflater.from(getContext());
        CheckedTextView label = (CheckedTextView) inflater.inflate(
                android.R.layout.simple_list_item_single_choice, parent, false);
        label.setText(getListItemText(getItem(position)));
        label.setTextColor(Utils.isOxygenOsRom() ?
                OOSThemeColorUtils.getColorTextPrimary(getContext()) :
                Utils.getColorFromStyleAttr(getContext(), android.R.attr.textColorPrimary));
        label.setCheckMarkTintList(ColorStateList.valueOf(
                Utils.isOxygenOsRom() ?
                        OOSThemeColorUtils.getColorAccent(getContext()) :
                        Utils.getColorFromStyleAttr(getContext(), android.R.attr.colorAccent)));
        return label;
    }

    protected abstract CharSequence getListItemText(T item);
}

/*
 * Copyright (C) 2014 The Android Open Source Project
 * Copyright (C) 2018 Peter Gregus for GravityBox Project (C3C076@xda)
 *
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

import android.annotation.SuppressLint;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnTouchListener;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;

import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.Utils;

/**
 * Quick settings common detail list view with line items.
 */
public class QsDetailItemsList {

    private Context mSysUiContext;
    private ListView mListView;
    private View mEmpty;
    private TextView mEmptyText;
    private ImageView mEmptyIcon;
    private LinearLayout mView;

    private QsDetailItemsList() { /* must be created via create method */ }

    private QsDetailItemsList(Context sysUiContext, LinearLayout view) {
        mSysUiContext = sysUiContext;
        mView = view;

        mListView = (ListView) mView.findViewById(android.R.id.list);
        mListView.setOnTouchListener(new OnTouchListener() {
            // Setting on Touch Listener for handling the touch inside ScrollView
            @SuppressLint("ClickableViewAccessibility")
            @Override
            public boolean onTouch(View v, MotionEvent event) {
                // Disallow the touch request for parent scroll on touch of child view
                v.getParent().requestDisallowInterceptTouchEvent(true);
                return false;
            }
        });
        mEmpty = mView.findViewById(android.R.id.empty);
        mEmpty.setVisibility(View.GONE);
        mEmptyText = (TextView) mEmpty.findViewById(android.R.id.title);
        mEmptyText.setTextColor(Utils.isOxygenOsRom() ?
                OOSThemeColorUtils.getColorTextSecondary(mSysUiContext) :
                Utils.getColorFromStyleAttr(mSysUiContext, android.R.attr.textColorSecondary));
        mEmptyIcon = (ImageView) mEmpty.findViewById(android.R.id.icon);
        mListView.setEmptyView(mEmpty);
    }

    public static QsDetailItemsList create(Context context, ViewGroup parent) throws Throwable {
        LayoutInflater inflater = LayoutInflater.from(Utils.getGbContext(context));
        LinearLayout view = (LinearLayout) inflater.inflate(R.layout.qs_detail_items_list, parent, false);
        if (parent.getParent() instanceof ScrollView) {
            ((ScrollView)parent.getParent()).setFillViewport(true);
        }
        return new QsDetailItemsList(context, view);
    }

    public View getView() {
        return mView;
    }

    public void setAdapter(ListAdapter adapter) {
        mListView.setAdapter(adapter);
    }

    public ListView getListView() {
        return mListView;
    }

    public void setEmptyState(int icon, String text) {
        mEmptyIcon.setImageResource(icon);
        mEmptyText.setText(text);
    }
}

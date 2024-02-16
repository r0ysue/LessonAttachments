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
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import com.ceco.nougat.gravitybox.R;
import com.ceco.nougat.gravitybox.adapters.BaseListAdapterFilter;
import com.ceco.nougat.gravitybox.adapters.BaseListAdapterFilter.IBaseListAdapterFilterable;

import java.util.ArrayList;
import java.util.List;

public class TuneableListAdapter extends ArrayAdapter<TuneableListItem>
                            implements IBaseListAdapterFilterable<TuneableListItem> {

    private Context mContext;
    private List<TuneableListItem> mData;
    private List<TuneableListItem> mFilteredData;
    private android.widget.Filter mFilter;

    TuneableListAdapter(Context context, List<TuneableListItem> objects) {
        super(context, R.layout.tuneable_list_item, objects);

        mContext = context;
        mData = new ArrayList<>(objects);
        mFilteredData = new ArrayList<>(objects);
    }

    static class ViewHolder {
        TextView nameView;
        TextView valueView;
        TextView valueOverriddenView;
        TuneableStatusView statusView;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View row = convertView;
        ViewHolder holder;

        if(row == null) {
            LayoutInflater inflater = 
                    (LayoutInflater) mContext.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            row = inflater.inflate(R.layout.tuneable_list_item, parent, false);

            holder = new ViewHolder();
            holder.nameView = row.findViewById(R.id.tuneable_name);
            holder.valueView = row.findViewById(R.id.tuneable_value);
            holder.valueOverriddenView = row.findViewById(R.id.tuneable_value_overridden);
            holder.statusView = row.findViewById(R.id.tuneable_overridden);

            row.setTag(holder);
        } else {
            holder = (ViewHolder) row.getTag();
        }

        TuneableListItem item = mFilteredData.get(position);
        holder.nameView.setText(item.getText());
        holder.valueView.setText(item.getSubText());
        holder.valueOverriddenView.setText(item.getOverrideText());
        if (item.getItem().isOverridden()) {
            holder.valueOverriddenView.setVisibility(item.requiresReboot() ? View.VISIBLE : View.GONE);
            holder.statusView.setVisibility(View.VISIBLE);
            holder.statusView.setColor(item.requiresReboot() ? 0xffffa500 : 0xff32cd32);
        } else {
            holder.valueOverriddenView.setVisibility(View.GONE);
            holder.statusView.setVisibility(View.GONE);
        }

        return row;
    }

    @Override
    public android.widget.Filter getFilter() {
        if(mFilter == null) {
            mFilter = new BaseListAdapterFilter<>(this);
        }

        return mFilter;
    }

    @Override
    public List<TuneableListItem> getOriginalData() {
        return mData;
    }

    @Override
    public List<TuneableListItem> getFilteredData() {
        return mFilteredData;
    }

    @Override
    public void onFilterPublishResults(List<TuneableListItem> results) {
        mFilteredData = results;
        clear();
        for (int i = 0; i < mFilteredData.size(); i++) {
            TuneableListItem item = mFilteredData.get(i);
            add(item);
        }
    }
}

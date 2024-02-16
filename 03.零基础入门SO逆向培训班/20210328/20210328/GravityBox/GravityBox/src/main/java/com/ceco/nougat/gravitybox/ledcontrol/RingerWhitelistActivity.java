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
package com.ceco.nougat.gravitybox.ledcontrol;

import com.ceco.nougat.gravitybox.GravityBoxAppCompatActivity;
import com.ceco.nougat.gravitybox.R;

import android.graphics.Point;
import android.os.Bundle;

import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.SearchView.OnQueryTextListener;
import android.text.TextUtils.TruncateAt;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import android.widget.TextView;
import android.widget.Toast;

public class RingerWhitelistActivity extends GravityBoxAppCompatActivity {

    static final String KEY_SEARCH_QUERY = "searchQuery";
    static final String KEY_SELECTION_TYPE = "selectionType";
    static final String KEY_SELECTED_KEYS = "selectedKeys";
    enum SelectionType { DEFAULT, STARRED, WHITELISTED }

    private String mSearchQuery;
    private SelectionType mSelectionType;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (savedInstanceState != null) {
            mSearchQuery = savedInstanceState.getString(KEY_SEARCH_QUERY, null);
            mSelectionType = SelectionType.valueOf(savedInstanceState.getString(KEY_SELECTION_TYPE, "DEFAULT"));
        }

        setContentView(R.layout.ringer_whitelist_activity);
    }

    private ContactsFragment getFragment() {
        return (ContactsFragment) getSupportFragmentManager()
                .findFragmentById(R.id.contacts_fragment);
    }

    @Override
    public void onSaveInstanceState(Bundle bundle) {
        if (mSearchQuery != null) {
            bundle.putString(KEY_SEARCH_QUERY, mSearchQuery);
        }
        if (mSelectionType != null) {
            bundle.putString(KEY_SELECTION_TYPE, mSelectionType.toString());
        }
        super.onSaveInstanceState(bundle);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.ringer_whitelist_menu, menu);

        final MenuItem search = menu.findItem(R.id.search);
        final SearchView searchView = (SearchView) search.getActionView();
        final MenuItem searchKeyword = menu.findItem(R.id.searchKeyword);
        final TextView searchKeywordView = (TextView) searchKeyword.getActionView();
        final MenuItem searchReset = menu.findItem(R.id.searchReset);
        final MenuItem showAll = menu.findItem(R.id.showAll);
        final MenuItem showStarred = menu.findItem(R.id.showStarred);
        final MenuItem showWhitelisted = menu.findItem(R.id.showWhitelisted);

        searchView.setOnQueryTextListener(new OnQueryTextListener() {
            @Override
            public boolean onQueryTextChange(String text) {
                return false;
            }
            @Override
            public boolean onQueryTextSubmit(String text) {
                if (text.trim().length() < 2) {
                    Toast.makeText(RingerWhitelistActivity.this,
                            R.string.search_keyword_short, Toast.LENGTH_SHORT).show();
                } else {
                    mSearchQuery = text.trim();
                    searchView.clearFocus();
                    search.collapseActionView();
                    search.setVisible(false);
                    searchReset.setVisible(true);
                    searchKeyword.setVisible(true);
                    searchKeywordView.setText(mSearchQuery);
                    getFragment().fetchData(mSearchQuery);
                }
                return true;
            }
        });

        searchReset.setOnMenuItemClickListener(new OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                mSearchQuery = null;
                search.setVisible(true);
                searchReset.setVisible(false);
                searchKeyword.setVisible(false);
                searchKeywordView.setText(null);
                getFragment().fetchData();
                return true;
            }
        });

        searchKeywordView.setSingleLine(true);
        searchKeywordView.setEllipsize(TruncateAt.END);
        Point size = new Point();
        getWindowManager().getDefaultDisplay().getSize(size);
        searchKeywordView.setMaxWidth(size.x / 3);

        final OnMenuItemClickListener selectionTypeClickListener =
                new OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                if (item == showStarred) {
                    mSelectionType = SelectionType.STARRED;
                    showAll.setEnabled(true);
                    showWhitelisted.setEnabled(true);
                } else if (item == showWhitelisted) {
                    mSelectionType = SelectionType.WHITELISTED;
                    showAll.setEnabled(true);
                    showStarred.setEnabled(true);
                } else {
                    mSelectionType = SelectionType.DEFAULT;
                    showStarred.setEnabled(true);
                    showWhitelisted.setEnabled(true);
                }
                item.setEnabled(false);
                getFragment().setSelectionType(mSelectionType);
                getFragment().fetchData(mSearchQuery);
                return true;
            }
        };
        showAll.setOnMenuItemClickListener(selectionTypeClickListener);
        showAll.setEnabled(mSelectionType != null && mSelectionType != SelectionType.DEFAULT);
        showStarred.setOnMenuItemClickListener(selectionTypeClickListener);
        showStarred.setEnabled(mSelectionType == null || mSelectionType != SelectionType.STARRED);
        showWhitelisted.setOnMenuItemClickListener(selectionTypeClickListener);
        showWhitelisted.setEnabled(mSelectionType == null || mSelectionType != SelectionType.WHITELISTED);

        if (mSearchQuery != null) {
            searchReset.setVisible(true);
            searchKeyword.setVisible(true);
            searchKeywordView.setText(mSearchQuery);
        } else {
            search.setVisible(true);
        }

        return true;
    }
}

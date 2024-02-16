package com.ceco.nougat.gravitybox.ledcontrol;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.CheckedTextView;
import android.widget.ListView;
import android.widget.Toast;

import com.ceco.nougat.gravitybox.R;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import androidx.cursoradapter.widget.SimpleCursorAdapter;
import androidx.fragment.app.Fragment;
import androidx.loader.app.LoaderManager;
import androidx.loader.content.CursorLoader;
import androidx.loader.content.Loader;

import static com.ceco.nougat.gravitybox.ledcontrol.RingerWhitelistActivity.KEY_SEARCH_QUERY;
import static com.ceco.nougat.gravitybox.ledcontrol.RingerWhitelistActivity.KEY_SELECTED_KEYS;
import static com.ceco.nougat.gravitybox.ledcontrol.RingerWhitelistActivity.KEY_SELECTION_TYPE;

public class ContactsFragment extends Fragment
        implements LoaderManager.LoaderCallbacks<Cursor>,
                   AdapterView.OnItemClickListener {

    private static final String[] FROM_COLUMNS = {
            ContactsContract.Contacts.DISPLAY_NAME_PRIMARY,
    };

    private static final int[] TO_IDS = {
            R.id.contactName,
    };

    private static final String[] PROJECTION = {
            ContactsContract.Contacts._ID,
            ContactsContract.Contacts.LOOKUP_KEY,
            ContactsContract.Contacts.DISPLAY_NAME_PRIMARY,
    };

    private static final int LOOKUP_KEY_INDEX = 1;

    private ListView mContactsList;
    private CustomCursorAdapter mCursorAdapter;
    private Set<String> mSelectedKeys = new HashSet<>();
    private String mCurrentQuery;
    private RingerWhitelistActivity.SelectionType mSelectionType;

    public ContactsFragment() { }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        final View layout = inflater.inflate(
                R.layout.ringer_whitelist_fragment, container, false);
        mContactsList = layout.findViewById(android.R.id.list);
        mContactsList.setOnItemClickListener(this);

        return layout;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        Intent intent = getActivity().getIntent();
        if (savedInstanceState != null && savedInstanceState.containsKey(KEY_SELECTED_KEYS)) {
            mSelectedKeys = new HashSet<String>(
                    savedInstanceState.getStringArrayList(KEY_SELECTED_KEYS));
        } else if (intent != null && intent.hasExtra(QuietHoursActivity.EXTRA_QH_RINGER_WHITELIST)) {
            mSelectedKeys = new HashSet<String>(intent.getStringArrayListExtra(
                    QuietHoursActivity.EXTRA_QH_RINGER_WHITELIST));
        } else {
            mSelectedKeys = new HashSet<String>();
        }
        updateResult();

        mCursorAdapter = new CustomCursorAdapter(
                getActivity(),
                R.layout.ringer_whitelist_item,
                null,
                FROM_COLUMNS, TO_IDS,
                0);
        mContactsList.setAdapter(mCursorAdapter);

        String query = null;
        mSelectionType = RingerWhitelistActivity.SelectionType.DEFAULT;
        if (savedInstanceState != null) {
            query = savedInstanceState.getString(KEY_SEARCH_QUERY, null);
            mSelectionType = RingerWhitelistActivity.SelectionType.valueOf(
                    savedInstanceState.getString(KEY_SELECTION_TYPE, "DEFAULT"));
        }
        fetchData(query);
    }

    private void updateResult() {
        getActivity().setResult(Activity.RESULT_OK,
                (new Intent()).putStringArrayListExtra(QuietHoursActivity.EXTRA_QH_RINGER_WHITELIST,
                        new ArrayList<>(mSelectedKeys)));
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        if (mCurrentQuery != null) {
            outState.putString(KEY_SEARCH_QUERY, mCurrentQuery);
        }
        if (mSelectionType != null) {
            outState.putString(KEY_SELECTION_TYPE, mSelectionType.toString());
        }
        if (mSelectedKeys != null) {
            outState.putStringArrayList(KEY_SELECTED_KEYS,
                    new ArrayList<>(mSelectedKeys));
        }
        super.onSaveInstanceState(outState);
    }

    private boolean hasContactReadPermission() {
        return getActivity().checkSelfPermission(Manifest.permission.READ_CONTACTS)
                == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           String[] permissions, int[] grantResults) {
        if (grantResults.length > 0 && grantResults[0] ==
                PackageManager.PERMISSION_GRANTED) {
            fetchData(mCurrentQuery);
        } else {
            Toast.makeText(getActivity(), R.string.qhrw_permission_denied,
                    Toast.LENGTH_SHORT).show();
        }
    }

    public void fetchData() {
        fetchData(null);
    }

    public void fetchData(String query) {
        mCurrentQuery = query;

        if (!hasContactReadPermission()) {
            requestPermissions(new String[] { Manifest.permission.READ_CONTACTS }, 0);
            return;
        }

        Bundle args = null;
        if (mCurrentQuery != null) {
            args = new Bundle();
            args.putString(KEY_SEARCH_QUERY, mCurrentQuery);
        }
        getLoaderManager().restartLoader(0, args, this);
    }

    public void setSelectionType(RingerWhitelistActivity.SelectionType type) {
        mSelectionType = type;
    }

    private String createSelection() {
        switch (mSelectionType) {
            default:
            case DEFAULT:
                return ContactsContract.Contacts.DISPLAY_NAME_PRIMARY + " LIKE ? " +
                        "AND " + ContactsContract.Contacts.HAS_PHONE_NUMBER + " != 0";
            case STARRED:
                return ContactsContract.Contacts.DISPLAY_NAME_PRIMARY + " LIKE ? " +
                        "AND " + ContactsContract.Contacts.STARRED + " = 1 " +
                        "AND " + ContactsContract.Contacts.HAS_PHONE_NUMBER + " != 0 ";
            case WHITELISTED:
                String arg = "";
                for (int i = 0; i < mSelectedKeys.size(); i++) {
                    if (!arg.isEmpty()) arg += ",";
                    arg += "?";
                }
                return ContactsContract.Contacts.DISPLAY_NAME_PRIMARY + " LIKE ? " +
                        "AND " + ContactsContract.Contacts.LOOKUP_KEY + " IN (" + arg + ")";
        }
    }

    private String[] createSelectionArgs(String query) {
        switch (mSelectionType) {
            default:
            case DEFAULT:
            case STARRED:
                return new String[] { query.equals("%") ? query : "%" + query + "%" };
            case WHITELISTED:
                String args[] = new String[mSelectedKeys.size()+1];
                args[0] = query.equals("%") ? query : "%" + query + "%";
                int i = 1;
                for (String key : mSelectedKeys) {
                    args[i++] = key;
                }
                return args;
        }
    }

    @Override
    public Loader<Cursor> onCreateLoader(int id, Bundle args) {
        String query = "%";
        if (args != null && args.containsKey(KEY_SEARCH_QUERY)) {
            query = args.getString(KEY_SEARCH_QUERY);
        }

        return new CursorLoader(
                getActivity(),
                ContactsContract.Contacts.CONTENT_URI,
                PROJECTION,
                createSelection(),
                createSelectionArgs(query),
                ContactsContract.Contacts.DISPLAY_NAME_PRIMARY
        );
    }

    @Override
    public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
        mCursorAdapter.swapCursor(data);
        if (data.getCount() == 0) {
            Toast.makeText(getActivity(), R.string.search_no_contacts,
                    Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onLoaderReset(Loader<Cursor> loader) {
        mCursorAdapter.swapCursor(null);
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
        Cursor cursor = ((CustomCursorAdapter) parent.getAdapter()).getCursor();
        cursor.moveToPosition(position);
        String contactKey = cursor.getString(LOOKUP_KEY_INDEX);

        CheckedTextView cb = view.findViewById(R.id.contactName);
        if (!cb.isChecked()) {
            cb.setChecked(true);
            mSelectedKeys.add(contactKey);
        } else {
            cb.setChecked(false);
            mSelectedKeys.remove(contactKey);
        }
        updateResult();
    }

    private class CustomCursorAdapter extends SimpleCursorAdapter {

        public CustomCursorAdapter(Context context, int layout, Cursor c,
                                   String[] from, int[] to, int flags) {
            super(context, layout, c, from, to, flags);
        }

        @Override
        public void bindView(View view, Context context, Cursor cursor) {
            super.bindView(view, context, cursor);

            String key = cursor.getString(LOOKUP_KEY_INDEX);
            CheckedTextView nameView = view.findViewById(R.id.contactName);
            nameView.setChecked(mSelectedKeys.contains(key));
        }
    }
}
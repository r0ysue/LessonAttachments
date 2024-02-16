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
package com.ceco.nougat.gravitybox;

import java.util.Locale;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.LocaleList;

public class GravityBoxContextWrapper extends ContextWrapper {

    public GravityBoxContextWrapper(Context base) {
        super(base);
    }

    public static ContextWrapper wrap(Context context) {
        if (SettingsManager.getInstance(context).getMainPrefs()
                .getBoolean(GravityBoxSettings.PREF_KEY_FORCE_ENGLISH_LOCALE, false)) {
            Locale locale = new Locale("en");
            Resources res = context.getResources();
            Configuration configuration = res.getConfiguration();
            configuration.setLocale(locale);
            LocaleList localeList = new LocaleList(locale);
            LocaleList.setDefault(localeList);
            configuration.setLocales(localeList);
            context = context.createConfigurationContext(configuration);
        }
        return new ContextWrapper(context);
    }
}

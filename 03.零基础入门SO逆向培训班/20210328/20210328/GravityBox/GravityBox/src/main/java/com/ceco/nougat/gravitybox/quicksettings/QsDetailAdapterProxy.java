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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import android.content.Context;
import android.content.Intent;
import android.view.View;
import android.view.ViewGroup;
import de.robv.android.xposed.XposedHelpers;

/**
 * Generic invocation handler for handling tile's DetailAdapter interface proxy calls
 * Registered callback handles method calls defined on the interface 
 */
public class QsDetailAdapterProxy implements InvocationHandler {

    public static final String IFACE_DETAIL_ADAPTER = BaseTile.CLASS_BASE_TILE+".DetailAdapter";

    public interface Callback {
        CharSequence getTitle();
        Boolean getToggleState();
        View createDetailView(Context context, View convertView, ViewGroup parent) throws Throwable;
        Intent getSettingsIntent();
        void setToggleState(boolean state);
        boolean getToggleEnabled();
    }

    private Object mProxy;
    private Callback mCallback;

    private QsDetailAdapterProxy() { /* must be created via createProxy */ }

    private QsDetailAdapterProxy(ClassLoader cl, Callback cb) {
        mCallback = cb;
        mProxy = Proxy.newProxyInstance(cl,
                new Class<?>[] { XposedHelpers.findClass(IFACE_DETAIL_ADAPTER, cl) },
                this);
    }

    public static QsDetailAdapterProxy create(ClassLoader cl, Callback cb) {
        if (cl == null) throw new IllegalArgumentException("Classloader cannot be null");
        if (cb == null) throw new IllegalArgumentException("Callback cannot be null");
        return new QsDetailAdapterProxy(cl, cb);
    }

    public Object getProxy() {
        return mProxy;
    }

    public void destroy() {
        mProxy = null;
        mCallback = null;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getName().equals("getTitle")) {
            return mCallback.getTitle();
        } else if (method.getName().equals("getToggleState")) {
            return mCallback.getToggleState();
        } else if (method.getName().equals("getSettingsIntent")) {
            return mCallback.getSettingsIntent();
        } else if (method.getName().equals("setToggleState")) {
            mCallback.setToggleState((boolean)args[0]);
            return null;
        } else if (method.getName().equals("getMetricsCategory")) {
            return 111;
        } else if (method.getName().equals("createDetailView")) {
            return mCallback.createDetailView((Context)args[0], (View)args[1], (ViewGroup)args[2]);
        } else if (method.getName().equals("getToggleEnabled")) {
            return mCallback.getToggleEnabled();
        } else {
            return null;
        }
    }
}

/*
 * Copyright (C) 2013 Peter Gregus for GravityBox Project (C3C076@xda)
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

package com.ceco.nougat.gravitybox.adapters;

public class BasicListItem implements IBaseListAdapterItem {
    private String mText;
    private String mSubText;

    public BasicListItem(String text, String subText) {
        mText = text;
        mSubText = subText;
    }

    @Override
    public String getText() {
        return mText;
    }

    @Override
    public String getSubText() {
        return mSubText;
    }

    public void setText(String text) {
        mText = text;           
    }

    public void setSubText(String text) {
        mSubText = text;
    }
}
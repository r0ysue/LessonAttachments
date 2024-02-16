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

import java.io.File;

import com.ceco.nougat.gravitybox.quicksettings.TileOrderActivity;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public class BootCompletedReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        maybePerformTasksAfterRestore(context);
        prepareAssets(context);
        SettingsManager.getInstance(context).fixFolderPermissionsAsync();
    }

    // copies required files from assets to file system
    private void prepareAssets(Context context) {
        File f;

        // prepare alternative screenrecord binary if doesn't exist yet
        f = new File(Utils.getFilesDir(context) + "/screenrecord");
        if (!f.exists()) {
            String assetName = Build.SUPPORTED_64_BIT_ABIS.length > 0 ?
                    "screenrecord_arm64" : "screenrecord";
            Utils.writeAssetToFile(context, assetName, f);
        }
        if (f.exists()) {
            f.setExecutable(true);
        }
    }

    // performs necessary tasks after last restore of the settings
    private void maybePerformTasksAfterRestore(Context context) {
        File uuidFile = null;
        for (File file : Utils.getFilesDir(context).listFiles()) {
            if (file.getName().startsWith("uuid_")) {
                uuidFile = file;
                break;
            }
        }
        if (uuidFile != null) {
            uuidFile.delete();
            String uuid = uuidFile.getName().split("_")[1];
            SettingsManager.getInstance(context).resetUuid(uuid);
            TileOrderActivity.updateServiceComponents(context);
        }
    }
}

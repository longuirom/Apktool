/*
 *  Copyright (C) 2010 Ryszard Wiśniewski <brut.alll@gmail.com>
 *  Copyright (C) 2010 Connor Tumbleson <connor.tumbleson@gmail.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package brut.androlib.src;

import com.android.tools.smali.baksmali.Baksmali;
import com.android.tools.smali.baksmali.BaksmaliOptions;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.analysis.InlineMethodResolver;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedOdexFile;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import brut.androlib.exceptions.AndrolibException;

public class SmaliDecoder {
    private final File mApkFile;
    private final String mDexName;
    private final boolean mBakDeb;
    private final int mApiLevel;

    public SmaliDecoder(File apkFile, String dexName, boolean bakDeb, int apiLevel) {
        mApkFile = apkFile;
        mDexName = dexName;
        mBakDeb = bakDeb;
        mApiLevel = apiLevel;
    }

    public DexFile decode(File outDir, File outDirOnly) throws AndrolibException {
        try {
            BaksmaliOptions options = new BaksmaliOptions();

            // options
            options.deodex = false;
            options.implicitReferences = false;
            options.parameterRegisters = true;
            options.localsDirective = true;
            options.sequentialLabels = true;
            options.debugInfo = mBakDeb;
            options.codeOffsets = false;
            options.accessorComments = false;
            options.registerInfo = 0;
            options.inlineResolver = null;

            // set jobs automatically
            int jobs = Runtime.getRuntime().availableProcessors();
            if (jobs > 6) {
                jobs = 6;
            }

            // create the container
            MultiDexContainer<? extends DexBackedDexFile> container =
                DexFileFactory.loadDexContainer(mApkFile, mApiLevel > 0 ? Opcodes.forApi(mApiLevel) : null);
            List<MultiDexContainer.DexEntry<? extends DexBackedDexFile>> dexEntries = new ArrayList<>();
            List<DexBackedDexFile> dexFiles;

            // If we have 1 item, ignore the passed file. Pull the DexFile we need.
            if (container.getDexEntryNames().size() == 1) {
                dexEntries.add(container.getEntry(container.getDexEntryNames().get(0)));
            } else if (container.getDexEntryNames().size() > 1) {
                for (int i = 0; i < container.getDexEntryNames().size(); i++) {
                    dexEntries.add(container.getEntry(container.getDexEntryNames().get(i)));
                }
            } else {
                dexEntries.add(container.getEntry(mDexName));
            }

            dexFiles = dexEntries.stream()
                .map(MultiDexContainer.DexEntry::getDexFile)
                .collect(Collectors.toList());

            for (int i = 0; i < dexFiles.size(); i++) {
                DexBackedDexFile dexFile = dexFiles.get(i);

                if (dexFile.supportsOptimizedOpcodes()) {
                    throw new AndrolibException("Warning: You are disassembling an odex file without deodexing it.");
                }

                if (dexFile instanceof DexBackedOdexFile) {
                    options.inlineResolver =
                        InlineMethodResolver.createInlineMethodResolver(((DexBackedOdexFile) dexFile).getOdexVersion());
                }

                String smaliFolderName = i == 0 ? "smali" : "smali_classes" + (i + 1);

                File newOutDir = new File(outDirOnly, smaliFolderName);
                Baksmali.disassembleDexFile(dexFile, newOutDir, jobs, options);
            }

            return dexFiles.get(0);
        } catch (IOException ex) {
            throw new AndrolibException("Could not baksmali file: " + mDexName, ex);
        }
    }
}

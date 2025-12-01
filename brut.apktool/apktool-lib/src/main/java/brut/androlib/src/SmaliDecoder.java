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

import brut.androlib.exceptions.AndrolibException;
import brut.util.OSDetection;
import com.android.tools.smali.baksmali.Baksmali;
import com.android.tools.smali.baksmali.BaksmaliOptions;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedOdexFile;
import com.android.tools.smali.dexlib2.analysis.InlineMethodResolver;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;
import com.android.tools.smali.dexlib2.util.SyntheticAccessorResolver;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

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
            MultiDexContainer.DexEntry<? extends DexBackedDexFile> dexEntry;
            DexBackedDexFile dexFile;

            // If we have 1 item, ignore the passed file. Pull the DexFile we need.
            if (container.getDexEntryNames().size() == 1) {
                dexEntry = container.getEntry(container.getDexEntryNames().get(0));
            } else {
                dexEntry = container.getEntry(mDexName);
            }

            // Double-check the passed param exists
            if (dexEntry == null) {
                dexEntry = container.getEntry(container.getDexEntryNames().get(0));
            }

            assert dexEntry != null;
            dexFile = dexEntry.getDexFile();

            if (dexFile.supportsOptimizedOpcodes()) {
                throw new AndrolibException("Warning: You are disassembling an odex file without deodexing it.");
            }

            if (dexFile instanceof DexBackedOdexFile) {
                options.inlineResolver =
                        InlineMethodResolver.createInlineMethodResolver(((DexBackedOdexFile) dexFile).getOdexVersion());
            }

            MultiDexContainer<? extends DexBackedDexFile> newCheckDexContainer = dexEntry.getContainer();
            List<String> entryNames;
            try {
                entryNames = container.getDexEntryNames();
            } catch (IOException e) {
                System.err.println("Error reading container entries: " + e.getMessage());
                System.exit(1);
                return dexFile;
            }


            byte[] magic = dexFile.getBuffer().readByteRange(0, 8);
            String magicStr = new String(magic, StandardCharsets.US_ASCII);

            if (magicStr.equals("dex\n041\0")) {
                int indexLoop = 0;

                for (String entryName : entryNames) {
                    MultiDexContainer.DexEntry<? extends DexBackedDexFile> entry;
                    try {
                        entry = newCheckDexContainer.getEntry(entryName);
                    } catch (IOException e) {
                        System.err.println("Failed to read " + entryName + ": " + e.getMessage());
                        continue;
                    }
                    if (entry == null) continue;

                    // System.out.println("out: " + outDir);

                    if (!outDir.exists() && !outDir.mkdirs()) {
                        System.err.println("Cannot create directory: " + outDir);
                        System.exit(1);
                    }

                    if (options.accessorComments) {
                        options.syntheticAccessorResolver = new SyntheticAccessorResolver(entry.getDexFile().getOpcodes(), entry.getDexFile().getClasses());
                    }

                    indexLoop++;
                    String basePath = outDirOnly.getAbsolutePath();
                    String newOutDirName = (indexLoop == 1)
                        ? "smali"
                        : "smali_classes" + indexLoop;

                    File newOutDir = new File(basePath, newOutDirName);
                    if (entryNames.size() > 1 &&
                        newOutDir.exists() &&
                        newOutDir.isDirectory() &&
                        Objects.requireNonNull(newOutDir.list()).length > 0) {

                        throw new AndrolibException("Duplicate smali directory: " + newOutDir);
                    }


                    Baksmali.disassembleDexFile(entry.getDexFile(), newOutDir, jobs, options);
                }

            } else {
                Baksmali.disassembleDexFile(dexFile, outDir, jobs, options);
            }

            return dexFile;
        } catch (IOException ex) {
            throw new AndrolibException("Could not baksmali file: " + mDexName, ex);
        }
    }
}

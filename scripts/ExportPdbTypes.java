// Headless PDB type export, using an empty Windows program for architecture context.
// @category Data Types
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import pdb.symbolserver.SymbolFileInfo;

public class ExportPdbTypes extends GhidraScript {
    private FileDataTypeManager createArchive(File output, Language language,
                                              CompilerSpecID compiler) throws Exception {
        if (!FileDataTypeManager.class.isInterface())
            return FileDataTypeManager.createFileArchive(output, language.getLanguageID(), compiler);
        // 12.3 moved archives to DomainObjects. Set architecture inside an outer
        // transaction so the inner commit cannot flush events while holding its lock.
        // The LanguageUpdateOption enum also moved; resolve that one API dynamically.
        FileDataTypeManager archive = FileDataTypeManager.createFileArchive(output);
        boolean success = false;
        try {
            int tx = archive.startTransaction("Configure Windows architecture");
            try {
                java.lang.reflect.Method setter = Arrays.stream(FileDataTypeManager.class.getMethods())
                    .filter(m -> m.getName().equals("setProgramArchitecture") &&
                        m.getParameterCount() == 4 && m.getParameterTypes()[0] == Language.class)
                    .findFirst().orElseThrow();
                Object clear = Arrays.stream(setter.getParameterTypes()[2].getEnumConstants())
                    .filter(value -> value.toString().equals("CLEAR")).findFirst().orElseThrow();
                setter.invoke(archive, language, compiler, clear, monitor);
                success = true;
            } finally {
                archive.endTransaction(tx, success);
            }
            return archive;
        } finally {
            if (!success) archive.close();
        }
    }

    private String layout(DataType type) {
        // DB-backed and in-memory implementations differ, so compare the public type kind.
        StringBuilder out = new StringBuilder(type.getDisplayName()).append('|').append(type.getLength());
        if (type instanceof Composite composite) {
            for (DataTypeComponent field : composite.getDefinedComponents()) {
                // Resolving synthetic anonymous unions can restore trailing padding.
                int size = field.getFieldName() == null && field.getDataType() instanceof Composite
                    ? field.getDataType().getLength() : field.getLength();
                out.append('\n').append(field.getOffset()).append('|').append(size)
                    .append('|').append(field.getFieldName()).append('|')
                    .append(field.getDataType().getPathName());
                if (field.getDataType() instanceof BitFieldDataType bit)
                    out.append('|').append(bit.getBitSize()).append('|').append(bit.getBitOffset());
            }
        }
        if (type instanceof ghidra.program.model.data.Enum enumeration)
            for (String name : enumeration.getNames())
                out.append('\n').append(name).append('=').append(enumeration.getValue(name));
        if (type instanceof TypeDef alias) out.append('|').append(alias.getBaseDataType().getPathName());
        if (type instanceof Pointer pointer)
            out.append('|').append(pointer.getDataType() == null ? "void" : pointer.getDataType().getPathName());
        if (type instanceof Array array)
            out.append('|').append(array.getNumElements()).append('|').append(array.getElementLength())
                .append('|').append(array.getDataType().getPathName());
        if (type instanceof FunctionDefinition function) {
            out.append('|').append(function.getReturnType().getPathName())
                .append('|').append(function.getCallingConventionName()).append('|').append(function.hasVarArgs());
            for (ParameterDefinition parameter : function.getArguments())
                out.append('|').append(parameter.getDataType().getPathName());
        }
        return out.toString();
    }

    private void fields(Composite composite, int base, String name, StringBuilder out, int depth) {
        if (depth > 64) throw new IllegalStateException("Nested aggregate depth exceeds 64");
        for (DataTypeComponent field : composite.getDefinedComponents()) {
            int offset = base + field.getOffset(), bitPosition = -1, bitSize = -1;
            if (field.getDataType() instanceof BitFieldDataType bit) {
                bitPosition = offset * 8 + bit.getBitOffset();
                bitSize = bit.getBitSize();
            }
            if (field.getFieldName() != null)
                out.append("F\t").append(name).append('\t').append(field.getFieldName())
                    .append('\t').append(offset).append('\t').append(bitPosition)
                    .append('\t').append(bitSize).append('\n');
            if (field.getDataType() instanceof Composite nested) {
                String member = field.getFieldName();
                // Ghidra synthesizes containers for overlapping PDB members. Named
                // embedded structs have their own namespace and must not be flattened.
                boolean synthetic = member != null && member.matches("_[us]_\\d+") &&
                    nested.getName().equals(composite.getName() + member);
                if (member == null || synthetic)
                    fields(nested, offset, name, out, depth + 1);
            }
        }
    }

    private void audit(FileDataTypeManager archive, LanguageID language, CompilerSpecID compiler,
                       int width, Path layoutFile) throws Exception {
        if (archive.getProgramArchitecture() == null ||
            !archive.getProgramArchitecture().getLanguage().getLanguageID().equals(language) ||
            !archive.getProgramArchitecture().getCompilerSpec().getCompilerSpecID().equals(compiler) ||
            archive.getDataOrganization().getPointerSize() != width)
            throw new IllegalStateException("Archive architecture/pointer width mismatch");
        StringBuilder out = new StringBuilder();
        Iterator<DataType> iterator = archive.getAllDataTypes();
        while (iterator.hasNext()) {
            DataType type = iterator.next();
            if (type instanceof Composite composite &&
                type.getCategoryPath().getPath().matches("/[^/]+\\.[pP][dD][bB]")) {
                out.append("T\t").append(type.getName()).append('\t').append(type.getLength()).append('\n');
                fields(composite, 0, type.getName(), out, 0);
            }
        }
        Files.writeString(layoutFile, out.toString());
    }

    private int correctKnownPacking(DataTypeManager manager, String key, int width) {
        // This correction was audited for this exact ntkrnlmp.pdb only.
        if (width != 8 || !key.equalsIgnoreCase("89284D0CA6ACC8274B9A44BD5AF9290B1")) return 0;
        String[] paths = {
            "/ntkrnlmp.pdb/_DBGKD_ANY_CONTROL_SET/_DBGKD_ANY_CONTROL_SET_u_0",
            "/ntkrnlmp.pdb/_DBGKD_ANY_CONTROL_SET",
            "/ntkrnlmp.pdb/_DBGKD_CONTINUE2/_DBGKD_CONTINUE2_u_4",
            "/ntkrnlmp.pdb/_DBGKD_CONTINUE2"
        };
        int[] lengths = {28, 28, 28, 32};
        for (int i = 0; i < paths.length; i++) {
            DataType found = manager.getDataType(paths[i]);
            if (!(found instanceof Composite composite))
                throw new IllegalStateException("Missing known packing target: " + paths[i]);
            composite.setToDefaultAligned();
            composite.setExplicitPackingValue(1);
            if (composite.getLength() != lengths[i])
                throw new IllegalStateException("Unexpected corrected size: " + paths[i]);
        }
        return paths.length;
    }

    private JsonObject export(JsonObject job) throws Exception {
        String arch = job.get("architecture").getAsString();
        if (!arch.equals("x64") && !arch.equals("x86")) throw new IllegalArgumentException("Architecture " + arch);
        int width = arch.equals("x64") ? 8 : 4;
        LanguageID languageID = new LanguageID(width == 8 ? "x86:LE:64:default" : "x86:LE:32:default");
        CompilerSpecID compilerID = new CompilerSpecID("windows");
        Language language = getLanguage(languageID);
        File output = new File(job.get("output").getAsString());
        Path layoutFile = Path.of(job.get("layout").getAsString());
        JsonObject result = new JsonObject();
        result.addProperty("module", job.get("module").getAsString());
        result.addProperty("architecture", arch);
        result.addProperty("language", languageID.toString());
        result.addProperty("compiler", compilerID.toString());
        result.addProperty("pointer_size", width);
        if (job.has("audit_only") && job.get("audit_only").getAsBoolean()) {
            try (FileDataTypeManager archive = FileDataTypeManager.openFileArchive(output, false)) {
                audit(archive, languageID, compilerID, width, layoutFile);
                result.addProperty("types_reopened", archive.getDataTypeCount(true));
            }
            return result;
        }
        if (output.exists()) throw new IllegalStateException("Output already exists: " + output);
        File pdbFile = new File(job.get("pdb_path").getAsString());
        String key = job.get("pdb_key").getAsString();
        SymbolFileInfo actual = SymbolFileInfo.fromFile(pdbFile, monitor);
        if (actual == null || !actual.getUniqueDirName().equalsIgnoreCase(key))
            throw new IllegalStateException("PDB identity mismatch: " + pdbFile);
        ProgramDB program = new ProgramDB("pdb-types", language,
            language.getCompilerSpecByID(compilerID), this);
        try {
            int transaction = program.startTransaction("Apply PDB types");
            try {
                PdbApplicatorOptions options = new PdbApplicatorOptions();
                options.setProcessingControl(PdbApplicatorControl.DATA_TYPES_ONLY);
                MessageLog log = new MessageLog();
                try (AbstractPdb pdb = PdbParser.parse(pdbFile, new PdbReaderOptions(), monitor)) {
                    pdb.deserialize();
                    new DefaultPdbApplicator(pdb, program, program.getDataTypeManager(),
                        program.getImageBase(), options, monitor, log).applyNoAnalysisState();
                }
                if (log.hasMessages()) println(log.toString());
                result.addProperty("packing_corrections", correctKnownPacking(program.getDataTypeManager(), key, width));
            } finally {
                program.endTransaction(transaction, true);
            }
            List<DataType> types = new ArrayList<>();
            program.getDataTypeManager().getAllDataTypes(types);
            Map<DataTypePath,String> expected = new HashMap<>();
            int aggregates = 0, pointers = 0;
            for (DataType type : types) {
                expected.put(type.getDataTypePath(), layout(type));
                if (type instanceof Composite && type.getLength() > 0) aggregates++;
                if (type instanceof Pointer) pointers++;
            }
            if (aggregates == 0) throw new IllegalStateException("PDB application produced no aggregate definitions");
            output.getParentFile().mkdirs();
            try (FileDataTypeManager archive = createArchive(output, language, compilerID)) {
                int tx = archive.startTransaction("Export PDB types and dependencies");
                boolean success = false;
                try {
                    archive.addDataTypes(types, DataTypeConflictHandler.DEFAULT_HANDLER, monitor);
                    success = true;
                } finally {
                    archive.endTransaction(tx, success);
                }
                archive.save();
            }
            try (FileDataTypeManager archive = FileDataTypeManager.openFileArchive(output, false)) {
                for (Map.Entry<DataTypePath,String> entry : expected.entrySet()) {
                    DataType saved = archive.getDataType(entry.getKey());
                    if (saved == null || !entry.getValue().equals(layout(saved)))
                        throw new IllegalStateException("Export/reopen layout mismatch: " + entry.getKey() +
                            "\nEXPECTED\n" + entry.getValue() + "\nSAVED\n" + (saved == null ? "missing" : layout(saved)));
                }
                audit(archive, languageID, compilerID, width, layoutFile);
                result.addProperty("types_reopened", expected.size());
                result.addProperty("pointers_checked", pointers);
                result.addProperty("aggregates_exported", aggregates);
            }
        } finally {
            program.release(this);
        }
        println("ARCHIVE_VERIFIED " + output);
        return result;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected jobs.json results.json");
        JsonArray jobs = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonArray();
        JsonArray results = new JsonArray();
        for (JsonElement job : jobs) results.add(export(job.getAsJsonObject()));
        // The Python caller requires this file: analyzeHeadless may return 0 on script errors.
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(results));
    }
}

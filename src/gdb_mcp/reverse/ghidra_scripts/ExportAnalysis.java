// Headless Ghidra exporter for gdb-mcp. Invoked by AnalysisManager only.
//@category gdb-mcp

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.stream.JsonWriter;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportAnalysis extends GhidraScript {
    private static final int SCHEMA_VERSION = 2;
    private static final int MAX_DISASSEMBLY_INSTRUCTIONS = 2_000_000;
    private static final int MAX_REFERENCES_PER_FUNCTION = 100_000;
    private static final int MAX_SYMBOLS = 250_000;
    private File outputDir;
    private File functionsDir;
    private int decompileTimeout = 15;
    private DecompInterface decompiler;
    private final List<Map<String, Object>> functionSummaries = new ArrayList<>();
    private int decompiledCount = 0;
    private int failedCount = 0;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("output directory is required");
        }
        outputDir = new File(args[0]);
        functionsDir = new File(outputDir, "functions");
        if (!functionsDir.mkdirs() && !functionsDir.isDirectory()) {
            throw new IllegalStateException("cannot create function output directory");
        }
        if (args.length > 1) {
            decompileTimeout = Math.max(1, Integer.parseInt(args[1]));
        }

        decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(decompiler.getLastMessage());
        }

        try {
            exportFunctions();
            exportDisassembly();
            exportIndex();
        }
        finally {
            decompiler.dispose();
        }
    }

    private static String addr(Address address) {
        return address == null ? null : "0x" + address.toString();
    }

    private static long unsignedOffset(Address address) {
        return address == null ? 0 : address.getUnsignedOffset();
    }

    private JsonWriter writer(File file) throws Exception {
        JsonWriter writer = new JsonWriter(new BufferedWriter(new OutputStreamWriter(
            new FileOutputStream(file), StandardCharsets.UTF_8)));
        writer.setIndent("");
        return writer;
    }

    private void exportFunctions() throws Exception {
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function function = iterator.next();
            if (!currentProgram.getMemory().contains(function.getEntryPoint())) {
                continue;
            }
            Map<String, Object> summary = functionSummary(function);
            functionSummaries.add(summary);
            if (function.isExternal() || function.isThunk()) {
                summary.put("decompiled", false);
                continue;
            }
            File output = new File(functionsDir,
                Long.toUnsignedString(unsignedOffset(function.getEntryPoint()), 16) + ".json");
            boolean success = exportFunction(function, output);
            summary.put("decompiled", success);
            if (success) {
                decompiledCount++;
            }
            else {
                failedCount++;
            }
        }
    }

    private Map<String, Object> functionSummary(Function function) {
        Map<String, Object> summary = new HashMap<>();
        summary.put("entry", addr(function.getEntryPoint()));
        summary.put("end", addr(function.getBody().getMaxAddress()));
        summary.put("name", function.getName());
        summary.put("external", function.isExternal());
        summary.put("thunk", function.isThunk());
        summary.put("signature", function.getSignature().getPrototypeString());
        return summary;
    }

    private boolean exportFunction(Function function, File output) throws Exception {
        DecompileResults results = decompiler.decompileFunction(function, decompileTimeout, monitor);
        boolean completed = results.decompileCompleted() && results.getCCodeMarkup() != null;
        try (JsonWriter json = writer(output)) {
            json.beginObject();
            json.name("entry").value(addr(function.getEntryPoint()));
            json.name("end").value(addr(function.getBody().getMaxAddress()));
            json.name("name").value(function.getName());
            json.name("signature").value(function.getSignature().getPrototypeString());
            json.name("decompiled").value(completed);
            if (!completed) {
                json.name("error").value(results.getErrorMessage());
                json.name("code").value("");
                json.name("lines").beginArray().endArray();
            }
            else {
                writeDecompiledLines(json, results.getCCodeMarkup());
            }
            writeInstructions(json, function);
            writeRelations(json, function);
            json.endObject();
        }
        return completed;
    }

    private void writeDecompiledLines(JsonWriter json, ClangTokenGroup markup) throws Exception {
        List<ClangLine> lines = DecompilerUtils.toLines(markup);
        StringBuilder code = new StringBuilder();
        List<String> texts = new ArrayList<>();
        for (ClangLine line : lines) {
            StringBuilder text = new StringBuilder(line.getIndentString());
            for (ClangToken token : line.getAllTokens()) {
                text.append(token.getText());
            }
            texts.add(text.toString());
            if (code.length() > 0) {
                code.append('\n');
            }
            code.append(text);
        }
        json.name("code").value(code.toString());
        json.name("lines").beginArray();
        for (int i = 0; i < lines.size(); i++) {
            ClangLine line = lines.get(i);
            Address minimum = null;
            Address maximum = null;
            for (ClangToken token : line.getAllTokens()) {
                Address tokenMin = token.getMinAddress();
                Address tokenMax = token.getMaxAddress();
                if (tokenMin != null && (minimum == null || tokenMin.compareTo(minimum) < 0)) {
                    minimum = tokenMin;
                }
                if (tokenMax != null && (maximum == null || tokenMax.compareTo(maximum) > 0)) {
                    maximum = tokenMax;
                }
            }
            json.beginObject();
            json.name("number").value(i + 1);
            json.name("text").value(texts.get(i));
            json.name("indent").value(line.getIndentString());
            if (minimum != null) {
                json.name("min").value(addr(minimum));
                json.name("max").value(addr(maximum == null ? minimum : maximum));
            }
            json.name("tokens").beginArray();
            for (ClangToken token : line.getAllTokens()) {
                json.beginObject();
                json.name("text").value(token.getText());
                json.name("type").value(tokenType(token.getSyntaxType()));
                if (token.getMinAddress() != null) {
                    json.name("min").value(addr(token.getMinAddress()));
                    json.name("max").value(addr(token.getMaxAddress()));
                }
                json.endObject();
            }
            json.endArray();
            json.endObject();
        }
        json.endArray();
    }

    private String tokenType(int syntaxType) {
        switch (syntaxType) {
            case ClangToken.KEYWORD_COLOR: return "keyword";
            case ClangToken.COMMENT_COLOR: return "comment";
            case ClangToken.TYPE_COLOR: return "type";
            case ClangToken.FUNCTION_COLOR: return "function";
            case ClangToken.VARIABLE_COLOR: return "variable";
            case ClangToken.CONST_COLOR: return "constant";
            case ClangToken.PARAMETER_COLOR: return "parameter";
            case ClangToken.GLOBAL_COLOR: return "global";
            case ClangToken.ERROR_COLOR: return "error";
            case ClangToken.SPECIAL_COLOR: return "special";
            default: return "plain";
        }
    }

    private void writeInstructions(JsonWriter json, Function function) throws Exception {
        json.name("instructions").beginArray();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            writeInstruction(json, instructions.next());
        }
        json.endArray();
    }

    private void writeInstruction(JsonWriter json, Instruction instruction) throws Exception {
        json.beginObject();
        json.name("address").value(addr(instruction.getAddress()));
        json.name("text").value(instruction.toString());
        json.name("bytes").value(instructionBytes(instruction));
        json.endObject();
    }

    private void exportDisassembly() throws Exception {
        try (JsonWriter json = writer(new File(outputDir, "disassembly.json"))) {
            json.beginObject();
            json.name("schema_version").value(SCHEMA_VERSION);
            json.name("instructions").beginArray();
            int count = 0;
            boolean truncated = false;
            outer:
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (!block.isExecute()) {
                    continue;
                }
                AddressSet range = new AddressSet(block.getStart(), block.getEnd());
                InstructionIterator instructions = currentProgram.getListing().getInstructions(range, true);
                while (instructions.hasNext() && !monitor.isCancelled()) {
                    if (count >= MAX_DISASSEMBLY_INSTRUCTIONS) {
                        truncated = true;
                        break outer;
                    }
                    writeInstruction(json, instructions.next());
                    count++;
                }
            }
            json.endArray();
            json.name("truncated").value(truncated);
            json.endObject();
        }
    }

    private String instructionBytes(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte value : bytes) {
                result.append(String.format("%02x", value & 0xff));
            }
            return result.toString();
        }
        catch (MemoryAccessException exception) {
            return "";
        }
    }

    private void writeRelations(JsonWriter json, Function function) throws Exception {
        Set<Function> callees = function.getCalledFunctions(monitor);
        Set<Function> callers = function.getCallingFunctions(monitor);
        writeFunctionSet(json, "callees", callees);
        writeFunctionSet(json, "callers", callers);

        json.name("xrefs_to").beginArray();
        Set<String> emittedTo = new HashSet<>();
        AddressIterator destinations = currentProgram.getReferenceManager()
            .getReferenceDestinationIterator(function.getBody(), true);
        while (destinations.hasNext() && emittedTo.size() < MAX_REFERENCES_PER_FUNCTION) {
            ReferenceIterator references = currentProgram.getReferenceManager()
                .getReferencesTo(destinations.next());
            while (references.hasNext() && emittedTo.size() < MAX_REFERENCES_PER_FUNCTION) {
                writeReference(json, references.next(), true, emittedTo);
            }
        }
        json.endArray();

        json.name("xrefs_from").beginArray();
        Set<String> emittedFrom = new HashSet<>();
        AddressIterator sources = currentProgram.getReferenceManager()
            .getReferenceSourceIterator(function.getBody(), true);
        while (sources.hasNext() && emittedFrom.size() < MAX_REFERENCES_PER_FUNCTION) {
            Reference[] references = currentProgram.getReferenceManager()
                .getReferencesFrom(sources.next());
            for (Reference reference : references) {
                if (emittedFrom.size() >= MAX_REFERENCES_PER_FUNCTION) {
                    break;
                }
                writeReference(json, reference, false, emittedFrom);
            }
        }
        json.endArray();
    }

    private void writeReference(
        JsonWriter json, Reference reference, boolean incoming, Set<String> emitted
    ) throws Exception {
        String key = addr(reference.getFromAddress()) + ":" + addr(reference.getToAddress())
            + ":" + reference.getReferenceType().getName();
        if (!emitted.add(key)) {
            return;
        }
        json.beginObject();
        json.name("from").value(addr(reference.getFromAddress()));
        json.name("to").value(addr(reference.getToAddress()));
        json.name("type").value(reference.getReferenceType().getName());
        Address relatedAddress = incoming ? reference.getFromAddress() : reference.getToAddress();
        Function related = currentProgram.getFunctionManager().getFunctionContaining(relatedAddress);
        if (related != null) {
            json.name("function").value(related.getName());
            json.name("function_entry").value(addr(related.getEntryPoint()));
        }
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(reference.getToAddress());
        if (symbol != null) {
            json.name("symbol").value(symbol.getName());
        }
        json.endObject();
    }

    private void writeFunctionSet(JsonWriter json, String name, Set<Function> functions) throws Exception {
        json.name(name).beginArray();
        for (Function function : functions) {
            if (!currentProgram.getMemory().contains(function.getEntryPoint())) {
                continue;
            }
            json.beginObject();
            json.name("entry").value(addr(function.getEntryPoint()));
            json.name("name").value(function.getName());
            json.endObject();
        }
        json.endArray();
    }

    private void exportIndex() throws Exception {
        try (JsonWriter json = writer(new File(outputDir, "index.json"))) {
            json.beginObject();
            json.name("schema_version").value(SCHEMA_VERSION);
            writeBinary(json);
            writeSections(json);
            writeSymbols(json);
            writeStrings(json);
            json.name("functions");
            writeMaps(json, functionSummaries);
            json.name("counts").beginObject();
            json.name("functions").value(functionSummaries.size());
            json.name("decompiled").value(decompiledCount);
            json.name("failed").value(failedCount);
            json.endObject();
            json.endObject();
        }
    }

    private void writeBinary(JsonWriter json) throws Exception {
        json.name("binary").beginObject();
        json.name("name").value(currentProgram.getName());
        json.name("path").value(currentProgram.getExecutablePath());
        json.name("format").value(currentProgram.getExecutableFormat());
        json.name("language").value(currentProgram.getLanguageID().toString());
        json.name("compiler").value(currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        json.name("image_base").value(addr(currentProgram.getImageBase()));
        json.name("min_address").value(addr(currentProgram.getMinAddress()));
        json.name("max_address").value(addr(currentProgram.getMaxAddress()));
        json.name("entry_points").beginArray();
        AddressIterator entries = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (entries.hasNext()) {
            json.value(addr(entries.next()));
        }
        json.endArray();
        json.endObject();
    }

    private void writeSections(JsonWriter json) throws Exception {
        json.name("sections").beginArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            json.beginObject();
            json.name("name").value(block.getName());
            json.name("start").value(addr(block.getStart()));
            json.name("end").value(addr(block.getEnd()));
            json.name("size").value(block.getSize());
            json.name("read").value(block.isRead());
            json.name("write").value(block.isWrite());
            json.name("execute").value(block.isExecute());
            json.name("initialized").value(block.isInitialized());
            json.endObject();
        }
        json.endArray();
    }

    private void writeSymbols(JsonWriter json) throws Exception {
        json.name("symbols").beginArray();
        Set<String> emitted = new HashSet<>();
        SymbolIterator external = currentProgram.getSymbolTable().getExternalSymbols();
        while (external.hasNext() && emitted.size() < MAX_SYMBOLS) {
            Symbol symbol = external.next();
            writeSymbol(json, symbol, "import", emitted);
        }
        AddressIterator exports = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (exports.hasNext() && emitted.size() < MAX_SYMBOLS) {
            Address address = exports.next();
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
            if (symbol != null) {
                writeSymbol(json, symbol, "export", emitted);
            }
        }
        SymbolIterator allSymbols = currentProgram.getSymbolTable().getAllSymbols(false);
        while (allSymbols.hasNext() && emitted.size() < MAX_SYMBOLS) {
            Symbol symbol = allSymbols.next();
            String kind = symbol.isExternal()
                ? "import"
                : symbol.getSymbolType().toString().toLowerCase();
            writeSymbol(json, symbol, kind, emitted);
        }
        json.endArray();
    }

    private void writeSymbol(JsonWriter json, Symbol symbol, String kind, Set<String> emitted) throws Exception {
        String key = symbol.getName() + ":" + addr(symbol.getAddress());
        if (!emitted.add(key)) {
            return;
        }
        json.beginObject();
        json.name("name").value(symbol.getName());
        json.name("address").value(addr(symbol.getAddress()));
        json.name("kind").value(kind);
        json.endObject();
    }

    private void writeStrings(JsonWriter json) throws Exception {
        json.name("strings").beginArray();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        int count = 0;
        while (data.hasNext() && count < 100000) {
            Data item = data.next();
            if (!item.hasStringValue()) {
                continue;
            }
            Object value = item.getValue();
            json.beginObject();
            json.name("address").value(addr(item.getAddress()));
            json.name("value").value(value == null ? "" : value.toString());
            json.name("length").value(item.getLength());
            json.endObject();
            count++;
        }
        json.endArray();
    }

    @SuppressWarnings("unchecked")
    private void writeMaps(JsonWriter json, List<Map<String, Object>> maps) throws Exception {
        json.beginArray();
        for (Map<String, Object> map : maps) {
            json.beginObject();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                json.name(entry.getKey());
                Object value = entry.getValue();
                if (value instanceof Boolean) {
                    json.value((Boolean) value);
                }
                else if (value instanceof Number) {
                    json.value((Number) value);
                }
                else if (value == null) {
                    json.nullValue();
                }
                else {
                    json.value(value.toString());
                }
            }
            json.endObject();
        }
        json.endArray();
    }
}

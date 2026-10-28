"use strict";
const assert = require("node:assert/strict");
const RFTrace = require("./trace_sanitizer.js");
const headers = ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail", "Unused"];
function cell(value) { return '"' + String(value).replace(/"/g, '""') + '"'; }
function csv(rows, customHeaders) { return [customHeaders || headers].concat(rows).map(row => row.map(cell).join(",")).join("\r\n"); }
function event(overrides) {
  return Object.assign({ time: "PRIVATE_TIME_SENTINEL", process: "rumblefighter.exe", pid: "PRIVATE_PID_SENTINEL",
    operation: "CreateFile", path: "C:\\Games\\RF\\settings.ini", result: "SUCCESS",
    detail: "PRIVATE_DETAIL_SENTINEL", unused: "PRIVATE_UNUSED_SENTINEL" }, overrides);
}
function row(value) { return [value.time, value.process, value.pid, value.operation, value.path, value.result, value.detail, value.unused]; }
let passed = 0;
function test(name, fn) { fn(); passed++; console.log("PASS " + name); }
function parse(events) { return RFTrace.parseProcmonCsv(csv(events.map(row))); }

test("CommonJS and global API", () => assert.equal(globalThis.RFTrace, RFTrace));
test("BOM, quoted commas/newlines/doubled quotes; private columns omitted", () => {
  const report = RFTrace.parseProcmonCsv("\uFEFF" + csv([row(event({ path: 'C:\\Games\\RF\\a,b"c.ini', detail: 'PRIVATE_DETAIL_SENTINEL, "quoted"\r\nsecond line' }))]));
  assert.equal(report.entries[0].path, 'C:\\Games\\RF\\a,b"c.ini');
  const output = JSON.stringify(report);
  for (const value of ["PRIVATE_DETAIL_SENTINEL", "PRIVATE_PID_SENTINEL", "PRIVATE_TIME_SENTINEL", "PRIVATE_UNUSED_SENTINEL", "second line"]) assert.equal(output.includes(value), false);
  assert.equal(report.rows_seen, 1);
});
test("unquoted CSV and reordered required columns", () => {
  const report = RFTrace.parseProcmonCsv("Result,Path,Operation,Process Name\nSUCCESS,C:\\RF\\settings.cfg,ReadFile,RumbleLauncher.exe\n");
  assert.equal(report.entries[0].process, "RumbleLauncher.exe");
});
test("success and failed probes stay separate with counts", () => {
  const report = parse([event(), event(), event({ result: "NAME NOT FOUND" }), event({ result: "PATH NOT FOUND" })]);
  assert.deepEqual(report.entries.map(entry => [entry.result, entry.successful, entry.count]), [["SUCCESS", true, 2], ["NAME NOT FOUND", false, 1], ["PATH NOT FOUND", false, 1]]);
});
test("foreign processes, disallowed operations/results, assets excluded", () => {
  const events = [event({ process: "browser.exe" }), event({ operation: "WriteFile" }), event({ result: "ACCESS DENIED" })];
  for (const extension of [".nsz", ".nsx", ".nst", ".png", ".mp3", ".ttf", ".log", ".exe", ".txt"]) events.push(event({ path: "C:\\RF\\asset" + extension }));
  assert.equal(parse(events).entries.length, 0);
});
test("allowed candidates plus extensionless paths", () => {
  const extensions = [".ini", ".cfg", ".conf", ".config", ".xml", ".json", ".dat", ".bin", ""];
  const report = parse(extensions.map(extension => event({ path: "C:\\RF\\candidate" + extension })));
  assert.equal(report.entries.length, extensions.length);
  assert.equal(report.entries.at(-1).category, "extensionless_file_or_directory_candidate");
});
test("Users/SID redaction and registry names without values", () => {
  const report = parse([event({ path: "C:/Users/SyntheticAlice/AppData/Local/RF/a.ini" }),
    event({ operation: "RegQueryValue", path: "HKU\\S-1-5-21-111-222-333-1001_Classes\\Software\\RF\\Endpoint", detail: "PRIVATE_REGISTRY_VALUE" }),
    event({ operation: "RegOpenKey", path: "HKCU\\Software\\RF", result: "NAME NOT FOUND" })]);
  const output = JSON.stringify(report);
  assert.equal(output.includes("SyntheticAlice"), false);
  assert.equal(output.includes("S-1-5-21-111-222-333-1001"), false);
  assert.equal(output.includes("PRIVATE_REGISTRY_VALUE"), false);
  assert.equal(report.entries[0].path, "C:\\Users\\<user>\\AppData\\Local\\RF\\a.ini");
  assert.equal(report.entries[1].path, "HKU\\<sid>_Classes\\Software\\RF\\Endpoint");
  assert.equal(report.entries[1].category, "registry_key_or_value_name");
  assert.equal(report.entries[2].successful, false);
});
test("case-insensitive deduplication and retained operation distinction", () => {
  const report = parse([event(), event({ process: "RUMBLEFIGHTER.EXE", path: "c:\\games\\rf\\SETTINGS.INI" }), event({ operation: "ReadFile" })]);
  assert.equal(report.entries.length, 2); assert.equal(report.entries[0].count, 2);
});
test("1500 unique-entry cap keeps counting retained duplicates", () => {
  const events = Array.from({ length: 1501 }, (_, i) => event({ path: "C:\\RF\\file" + i + ".ini" }));
  events.push(events[0], events[1500]);
  const report = parse(events);
  assert.equal(report.entries.length, 1500); assert.equal(report.truncated, true);
  assert.equal(report.entries[0].count, 2); assert.equal(report.omitted_matching_rows, 2);
});
test("structural errors contain no source field values", () => {
  const bad = ["", "PRIVATE_HEADER_SENTINEL,Other\n", "Process Name,Operation,Path,Result,Path\n",
    "Process Name,Operation,Path,Result\nrumblefighter.exe,ReadFile\n",
    'Process Name,Operation,Path,Result\n"PRIVATE_QUOTE_SENTINEL',
    'Process Name,Operation,Path,Result\n"PRIVATE_QUOTE_SENTINEL"junk,ReadFile,x.ini,SUCCESS',
    'Process Name,Operation,Path,Result\nPRIVATE_QUOTE_SENTINEL",ReadFile,x.ini,SUCCESS'];
  for (const input of bad) {
    assert.throws(() => RFTrace.parseProcmonCsv(input), error => {
      assert.equal(error.message.includes("PRIVATE_HEADER_SENTINEL"), false);
      assert.equal(error.message.includes("PRIVATE_QUOTE_SENTINEL"), false); return true;
    });
  }
});
test("extra declared columns ignored; undeclared columns rejected", () => {
  const report = RFTrace.parseProcmonCsv(csv([["rumblefighter.exe", "CreateFile", "C:\\RF\\a.ini", "SUCCESS", "PRIVATE_EXTRA_SENTINEL"]], ["Process Name", "Operation", "Path", "Result", "PRIVATE_HEADER_SENTINEL"]));
  assert.equal(JSON.stringify(report).includes("PRIVATE_EXTRA_SENTINEL"), false);
  assert.equal(JSON.stringify(report).includes("PRIVATE_HEADER_SENTINEL"), false);
  assert.throws(() => RFTrace.parseProcmonCsv("Process Name,Operation,Path,Result\nrumblefighter.exe,ReadFile,x.ini,SUCCESS,extra"));
  assert.throws(() => RFTrace.parseProcmonCsv(headers.map(cell).join(",") + "\nPRIVATE_ONE_COLUMN_SENTINEL"));
  assert.throws(() => RFTrace.parseProcmonCsv(Array(257).fill("column").join(",")));
});
test("64 MiB bounds include UTF-8 byte length; wrong input type rejected", () => {
  assert.throws(() => RFTrace.parseProcmonCsv(null));
  assert.throws(() => RFTrace.parseProcmonCsv("x".repeat(RFTrace.limits.maxInputBytes + 1)), /64 MiB/);
  assert.throws(() => RFTrace.parseProcmonCsv("\u00e9".repeat(RFTrace.limits.maxInputBytes / 2 + 1)), /64 MiB/);
});


function streamChunks(chunks) {
  const parser = RFTrace.createProcmonCsvParser();
  for (const chunk of chunks) parser.write(chunk);
  return parser.finish();
}
function expectedStreaming(text) {
  const expected = RFTrace.parseProcmonCsv(text);
  expected.limits.max_input_bytes = RFTrace.limits.maxStreamInputBytes;
  return expected;
}

test("streaming every split boundary: BOM, CRLF, quotes, multiline, Unicode pairs", () => {
  const fixture = "\uFEFF\r\n" + csv([
    row(event({ path: 'C:\\Users\\SyntheticPerson\\RF\\caf\u00e9-\ud83d\ude00,a"b.ini', detail: 'IGNORED_PRIVATE, "double"\r\nmultiline\ntext' })),
    row(event({ operation: "RegQueryValue", path: "HKU\\S-1-5-21-1-2-3-1001_Classes\\Software\\RF\\Host", result: "NAME NOT FOUND" })),
    row(event({ process: "RumbleLauncher.exe", path: "C:\\RF\\launch.cfg", result: "PATH NOT FOUND" })),
    row(event({ process: "foreign.exe" }))
  ]) + "\r\n";
  const expected = expectedStreaming(fixture);
  assert.equal(expected.input_bytes, Buffer.byteLength(fixture, "utf8"));
  for (let split = 0; split <= fixture.length; split++) {
    assert.deepEqual(streamChunks([fixture.slice(0, split), "", fixture.slice(split)]), expected);
  }
  assert.deepEqual(streamChunks(Array.from({ length: fixture.length }, (_, i) => fixture[i])), expected);
});
test("streaming trailing comma/EOF and incomplete records fail consistently", () => {
  const malformed = [
    "Process Name,Operation,Path,Result\r\nrumblefighter.exe,ReadFile,x.ini,SUCCESS,",
    'Process Name,Operation,Path,Result\r\n"PRIVATE_UNFINISHED',
    'Process Name,Operation,Path,Result\r\n"rumblefighter.exe"x,ReadFile,x.ini,SUCCESS'
  ];
  for (const text of malformed) {
    for (let split = 0; split <= text.length; split++) {
      assert.throws(() => streamChunks([text.slice(0, split), text.slice(split)]), error => {
        assert.equal(error.message.includes("PRIVATE_UNFINISHED"), false); return true;
      });
    }
  }
});
test("streaming ignores a large Detail field without retaining its contents", () => {
  const detail = "PRIVATE_LARGE_DETAIL_SENTINEL" + "x".repeat(512 * 1024);
  const text = csv([row(event({ detail: detail }))]);
  const parser = RFTrace.createProcmonCsvParser();
  for (let i = 0; i < text.length; i += 4093) parser.write(text.slice(i, i + 4093));
  const result = parser.finish();
  assert.equal(result.entries.length, 1);
  assert.equal(result.input_bytes, Buffer.byteLength(text, "utf8"));
  assert.equal(JSON.stringify(result).includes("PRIVATE_LARGE_DETAIL_SENTINEL"), false);
  assert.ok(JSON.stringify(result).length < 4096);
});
test("streaming retained-field byte and structural-record bounds", () => {
  const prefix = "C:\\RF\\";
  const suffix = ".ini";
  const exactPath = prefix + "x".repeat(RFTrace.limits.maxRetainedFieldBytes - prefix.length - suffix.length) + suffix;
  assert.equal(streamChunks([csv([row(event({ path: exactPath }))])]).entries.length, 1);
  for (const path of [exactPath + "x", prefix + "\u00e9".repeat(RFTrace.limits.maxRetainedFieldBytes / 2) + suffix]) {
    assert.throws(() => streamChunks([csv([row(event({ path: path }))])]), /32 KiB/);
  }
  const parser = RFTrace.createProcmonCsvParser();
  const excessiveRecord = csv([row(event({ detail: "PRIVATE_OVERLONG_RECORD" + "x".repeat(RFTrace.limits.maxRecordBytes) }))]);
  assert.throws(() => {
    for (let i = 0; i < excessiveRecord.length; i += 3071) parser.write(excessiveRecord.slice(i, i + 3071));
    parser.finish();
  }, error => {
    assert.match(error.message, /1 MiB/); assert.equal(error.message.includes("PRIVATE_OVERLONG_RECORD"), false); return true;
  });
  assert.throws(() => parser.finish(), /earlier error/);
});
test("streaming finish is stable; writing after finish or after failure is rejected", () => {
  const parser = RFTrace.createProcmonCsvParser();
  parser.write(csv([row(event())]));
  const first = parser.finish();
  assert.equal(parser.finish(), first);
  assert.throws(() => parser.write(""), /already finished/);
  const bad = RFTrace.createProcmonCsvParser();
  assert.throws(() => bad.write(null), /must be text/);
  assert.throws(() => bad.write("text"), /earlier error/);
});
test("streaming keeps the 1500-entry bound across chunks", () => {
  const parser = RFTrace.createProcmonCsvParser();
  parser.write(headers.map(cell).join(",") + "\r\n");
  for (let i = 0; i < 1502; i++) parser.write(row(event({ path: "C:\\RF\\item" + i + ".ini" })).map(cell).join(",") + "\r\n");
  parser.write(row(event({ path: "C:\\RF\\item0.ini" })).map(cell).join(","));
  const report = parser.finish();
  assert.equal(report.entries.length, 1500); assert.equal(report.truncated, true);
  assert.equal(report.omitted_matching_rows, 2); assert.equal(report.entries[0].count, 2);
});
test("streaming accepts more than 64 MiB using repeated bounded chunks", () => {
  const parser = RFTrace.createProcmonCsvParser();
  const header = headers.map(cell).join(",") + "\r\n";
  const line = row(event({ detail: "IGNORED_REPEATED_DETAIL" })).map(cell).join(",") + "\r\n";
  const rows = Math.floor(RFTrace.limits.maxInputBytes / Buffer.byteLength(line, "utf8")) + 2;
  const blockRows = 256;
  const block = line.repeat(blockRows);
  parser.write(header);
  let sent = 0;
  while (sent + blockRows <= rows) { parser.write(block); sent += blockRows; }
  if (sent < rows) parser.write(line.repeat(rows - sent));
  const report = parser.finish();
  assert.ok(report.input_bytes > RFTrace.limits.maxInputBytes);
  assert.equal(report.input_bytes, Buffer.byteLength(header, "utf8") + rows * Buffer.byteLength(line, "utf8"));
  assert.equal(report.rows_seen, rows); assert.equal(report.entries.length, 1);
  assert.equal(report.entries[0].count, rows);
  assert.equal(report.limits.max_input_bytes, 2 * 1024 * 1024 * 1024);
});


test("configurable streaming retention keeps more than 2000 distinct entries", () => {
  const parser = RFTrace.createProcmonCsvParser({ maxUniqueEntries: 20000 });
  parser.write(headers.map(cell).join(",") + "\r\n");
  for (let i = 0; i < 2501; i++) parser.write(row(event({ path: "C:\\RF\\extra" + i + ".ini" })).map(cell).join(",") + "\r\n");
  const report = parser.finish();
  assert.equal(report.entries.length, 2501); assert.equal(report.truncated, false);
  assert.deepEqual(report.truncation_reasons, []);
  assert.equal(report.limits.max_unique_entries, 20000);
  assert.ok(report.retained_metadata_estimated_bytes <= report.limits.max_retained_metadata_bytes);
});
test("configurable upper cap and invalid limits", () => {
  for (const value of [0, -1, 20001, 1.5, NaN, Infinity, "20000", true, null, undefined]) {
    assert.throws(() => RFTrace.createProcmonCsvParser({ maxUniqueEntries: value }), /integer from 1 through 20000/);
  }
  for (const options of [null, [], 20000, "private-option-value"]) {
    assert.throws(() => RFTrace.createProcmonCsvParser(options), error => {
      assert.equal(error.message.includes("private-option-value"), false); return true;
    });
  }
  const parser = RFTrace.createProcmonCsvParser({ maxUniqueEntries: 20000 });
  parser.write(headers.map(cell).join(",") + "\n");
  for (let i = 0; i < 20001; i++) parser.write(row(event({ path: "C:\\RF\\limit" + i + ".cfg" })).map(cell).join(",") + "\n");
  parser.write(row(event({ path: "C:\\RF\\limit0.cfg" })).map(cell).join(","));
  const report = parser.finish();
  assert.equal(report.entries.length, 20000); assert.equal(report.truncated, true);
  assert.deepEqual(report.truncation_reasons, ["unique_entry_limit"]);
  assert.equal(report.omitted_matching_rows, 1); assert.equal(report.entries[0].count, 2);
  const smallest = RFTrace.createProcmonCsvParser({ maxUniqueEntries: 1 });
  smallest.write(csv([row(event()), row(event({ path: "C:\\RF\\other.ini" }))]));
  assert.equal(smallest.finish().entries.length, 1);
});
test("retained metadata budget is independent of entry cap and preserves duplicate counts", () => {
  const parser = RFTrace.createProcmonCsvParser({ maxUniqueEntries: 20000 });
  const longStem = "x".repeat(32000);
  const path = index => "C:\\RF\\" + index + "-" + longStem + ".ini";
  parser.write(headers.map(cell).join(",") + "\n");
  for (let i = 0; i < 300; i++) parser.write(row(event({ path: path(i) })).map(cell).join(",") + "\n");
  parser.write(row(event({ path: path(0) })).map(cell).join(","));
  const report = parser.finish();
  assert.ok(report.entries.length > 0 && report.entries.length < 300);
  assert.equal(report.truncated, true);
  assert.deepEqual(report.truncation_reasons, ["retained_metadata_budget"]);
  assert.equal(report.omitted_matching_rows, 300 - report.entries.length);
  assert.equal(report.entries[0].count, 2);
  assert.ok(report.retained_metadata_estimated_bytes <= 16 * 1024 * 1024);
  assert.ok(Buffer.byteLength(JSON.stringify(report.entries), "utf8") < 16 * 1024 * 1024);
});
console.log("All " + passed + " synthetic trace-sanitizer tests passed.");

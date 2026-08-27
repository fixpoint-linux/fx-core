// fx-wire.zig — fx-compose Lens 3, step 2: the wire/codec layer.
//
// The four pipeline value shapes (see fx-pipeline.zig) each have a canonical
// WIRE encoding that is what gets interned into the CAS and threaded between
// stages.  Determinism is the thesis: identical value + identical shape MUST
// produce identical bytes (-> identical sha256).  The codec is PURE — no I/O,
// no CAS, no engine.
//
//   bytes   raw bytes (zero transform — the honest-cut stream)
//   lines   raw bytes (zero transform)
//   rows    JSON LINES: one canonical JSON object per line, LF-terminated,
//           field order = the DECLARED record type's field order (NOT
//           insertion order, NOT sorted).  Width-subtyping: a decoder
//           declared with a narrower type simply does not read extra fields.
//   single  ONE canonical JSON value, LF-terminated.
//
// A `single` with a record payload (e.g. wc -> {"lines","words","bytes"}) is
// also serialized in the DECLARED field order.
//
// Canonical JSON writer: emits {"a":1,"b":"x"} with keys walked in the given
// order and values escaped by the same rules as caslog.jsonEscape.  This is
// what makes hashes stable-but-correct (L3 landmine): the key order is pinned
// by the TYPE, not by whoever produced the data.

const std = @import("std");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Value model (in-memory, shape-agnostic)
// ---------------------------------------------------------------------------

pub const FieldValue = union(enum) {
    text: []const u8,
    natural: u64,
};

pub const Field = struct {
    name: []const u8,
    value: FieldValue,
};

/// One decoded row: an unordered-ish set of (name, value) fields.  Order is
/// pinned at (de)serialization time by the Shape's declared record type.
pub const Row = struct {
    fields: []const Field,
};

pub const Rows = struct {
    records: []const Row,
};

pub const Single = struct {
    fields: []const Field,
};

pub const Value = union(enum) {
    bytes: []const u8,
    lines: []const u8,
    rows: Rows,
    single: Single,
};

// ---------------------------------------------------------------------------
// Canonical JSON writer
// ---------------------------------------------------------------------------

pub const WireErr = error{ NoMem, BadType, BadWire, DuplicateField };

fn writeString(out: *std.ArrayList(u8), gpa: Allocator, s: []const u8) WireErr!void {
    out.append(gpa, '"') catch return error.NoMem;
    for (s) |c| switch (c) {
        '"' => out.appendSlice(gpa, "\\\"") catch return error.NoMem,
        '\\' => out.appendSlice(gpa, "\\\\") catch return error.NoMem,
        '\n' => out.appendSlice(gpa, "\\n") catch return error.NoMem,
        '\t' => out.appendSlice(gpa, "\\t") catch return error.NoMem,
        '\r' => out.appendSlice(gpa, "\\r") catch return error.NoMem,
        0x08 => out.appendSlice(gpa, "\\b") catch return error.NoMem,
        0x0C => out.appendSlice(gpa, "\\f") catch return error.NoMem,
        else => {
            if (c < 0x20) {
                const hexdig = "0123456789abcdef";
                var esc: [6]u8 = .{ '\\', 'u', '0', '0', 0, 0 };
                esc[4] = hexdig[(c >> 4) & 0xF];
                esc[5] = hexdig[c & 0xF];
                out.appendSlice(gpa, &esc) catch return error.NoMem;
            } else {
                out.append(gpa, c) catch return error.NoMem;
            }
        },
    };
    out.append(gpa, '"') catch return error.NoMem;
}

/// Emit one canonical JSON OBJECT from `fields`, with keys walked in `key_order`
/// (the declared record field order).  Values are pulled by name; a missing key
/// is BadWire; a value whose kind doesn't match the declared field kind is
/// BadType.  Each key's kind (text vs natural) is derived from the declared
/// type term so the SERIALIZATION is pinned by the type, not the data.
pub fn writeCanonicalJsonObject(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    key_order: []const []const u8,
    kinds: []const FieldKind,
    fields: []const Field,
) WireErr!void {
    if (key_order.len != kinds.len) return error.BadType;
    out.append(gpa, '{') catch return error.NoMem;
    for (key_order, 0..) |key, i| {
        // find the value by name
        var found: ?FieldValue = null;
        for (fields) |f| {
            if (std.mem.eql(u8, f.name, key)) {
                if (found != null) return error.DuplicateField;
                found = f.value;
            }
        }
        const v = found orelse return error.BadWire;
        if (i > 0) out.append(gpa, ',') catch return error.NoMem;
        try writeString(out, gpa, key);
        out.append(gpa, ':') catch return error.NoMem;
        switch (kinds[i]) {
            .text => {
                switch (v) {
                    .text => |s| try writeString(out, gpa, s),
                    else => return error.BadType,
                }
            },
            .natural => {
                switch (v) {
                    .natural => |n| {
                        out.print(gpa, "{d}", .{n}) catch return error.NoMem;
                    },
                    else => return error.BadType,
                }
            },
        }
    }
    out.append(gpa, '}') catch return error.NoMem;
}

// ---------------------------------------------------------------------------
// Field kinds — derived from the Dhall record TYPE
// ---------------------------------------------------------------------------

pub const FieldKind = enum { text, natural };

/// Walk a Dhall RECORD-TYPE SOURCE STRING (e.g. `{ path : Text, size : Natural }`)
/// and return the ordered field labels + kinds in the DECLARED order.
///
/// NOTE (L3 landmine): the canonical JSON key order MUST follow the type's
/// DECLARED field order.  The dhall-c parser SORTS record fields on parse (the
/// normalized Term's rec.fs is alphabetized), so the parsed Term cannot tell us
/// the declaration order — only the source string can.  We therefore scan the
/// source directly.  `Text`/union (e.g. `< File | Dir >`) => JSON string;
/// `Natural` => JSON number.
pub fn declaredFieldKinds(
    gpa: Allocator,
    src: []const u8,
) WireErr!struct { names: [][]const u8, kinds: []FieldKind } {
    var names = std.ArrayList([]const u8).empty;
    errdefer names.deinit(gpa);
    var kinds = std.ArrayList(FieldKind).empty;
    errdefer kinds.deinit(gpa);

    // Skip leading '{'
    var i: usize = 0;
    while (i < src.len and src[i] != '{') i += 1;
    i += 1;

    while (true) {
        // skip ws/commas
        while (i < src.len and (src[i] == ' ' or src[i] == '\t' or src[i] == ',' or src[i] == '\n' or src[i] == '\r')) i += 1;
        if (i >= src.len or src[i] == '}') break;
        // label
        const lbl_start = i;
        while (i < src.len and (std.ascii.isAlphanumeric(src[i]) or src[i] == '_' or src[i] == '-')) i += 1;
        if (i == lbl_start) return error.BadWire;
        const label = gpa.dupe(u8, src[lbl_start..i]) catch return error.NoMem;
        errdefer gpa.free(label);
        // skip ws then ':' then ws
        while (i < src.len and (src[i] == ' ' or src[i] == '\t')) i += 1;
        if (i >= src.len or src[i] != ':') return error.BadWire;
        i += 1;
        while (i < src.len and (src[i] == ' ' or src[i] == '\t')) i += 1;
        // type token: read until top-level ',' or '}' (tracking <> and () nesting)
        const ty_start = i;
        var depth: usize = 0;
        while (i < src.len) : (i += 1) {
            const c = src[i];
            if (c == '<' or c == '(') {
                depth += 1;
            } else if (c == '>' or c == ')') {
                depth = if (depth > 0) depth - 1 else 0;
            } else if ((c == ',' or c == '}') and depth == 0) {
                break;
            }
        }
        const ty = src[ty_start..i];
        const kind: FieldKind = if (std.mem.eql(u8, std.mem.trim(u8, ty, " \t"), "Natural")) .natural else .text;
        names.append(gpa, label) catch return error.NoMem;
        kinds.append(gpa, kind) catch return error.NoMem;
    }
    return .{ .names = names.toOwnedSlice(gpa) catch return error.NoMem, .kinds = kinds.toOwnedSlice(gpa) catch return error.NoMem };
}

// ---------------------------------------------------------------------------
// encode / decode
// ---------------------------------------------------------------------------

/// Serialize a Value to its canonical wire bytes.  Only the zero-transform
/// shapes (bytes/lines) can be encoded here: rows/single REQUIRE the DECLARED
/// record field order (derived from the type source), which this function has
/// no access to.  Emitting producer-order bytes here would be a silent
/// canonicality trap (N1), so those shapes are rejected — callers must use
/// `encodeRowsOrdered` / `encodeSingleOrdered` with an explicit key order.
pub fn encode(gpa: Allocator, v: Value, shape: anytype) WireErr![]u8 {
    _ = shape;
    return switch (v) {
        .bytes => |b| gpa.dupe(u8, b) catch return error.NoMem,
        .lines => |l| gpa.dupe(u8, l) catch return error.NoMem,
        .rows, .single => error.BadType,
    };
}

/// The shape-driven row encoder used by the engine: key order comes from the
/// DECLARED record type, guaranteeing T1 (same data, different declared order
/// -> different bytes).  `key_order`/`kinds` are produced by recordFieldKinds.
pub fn encodeRowsOrdered(
    gpa: Allocator,
    rows: Rows,
    key_order: []const []const u8,
    kinds: []const FieldKind,
) WireErr![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    for (rows.records) |r| {
        try writeCanonicalJsonObject(gpa, &out, key_order, kinds, r.fields);
        out.append(gpa, '\n') catch return error.NoMem;
    }
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

/// The shape-driven SINGLE encoder (symmetric to encodeRowsOrdered): one
/// canonical JSON object LF-terminated, keyed in the DECLARED field order.
pub fn encodeSingleOrdered(
    gpa: Allocator,
    s: Single,
    key_order: []const []const u8,
    kinds: []const FieldKind,
) WireErr![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    try writeCanonicalJsonObject(gpa, &out, key_order, kinds, s.fields);
    out.append(gpa, '\n') catch return error.NoMem;
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

// ---------------------------------------------------------------------------
// Minimal JSON object parser (for decode of rows/single)
// ---------------------------------------------------------------------------

const Parser = struct {
    src: []const u8,
    i: usize = 0,
    gpa: Allocator,
    err: bool = false,

    fn skipWs(self: *Parser) void {
        while (self.i < self.src.len and (self.src[self.i] == ' ' or self.src[self.i] == '\t' or
            self.src[self.i] == '\r' or self.src[self.i] == '\n')) self.i += 1;
    }
    fn peek(self: *Parser) ?u8 {
        self.skipWs();
        if (self.i >= self.src.len) return null;
        return self.src[self.i];
    }
    fn expectChar(self: *Parser, c: u8) bool {
        self.skipWs();
        if (self.i < self.src.len and self.src[self.i] == c) {
            self.i += 1;
            return true;
        }
        return false;
    }
    fn parseString(self: *Parser) ?[]const u8 {
        if (!self.expectChar('"')) return null;
        const start = self.i;
        var end = self.i;
        while (end < self.src.len) : (end += 1) {
            if (self.src[end] == '\\') {
                end += 1;
                continue;
            }
            if (self.src[end] == '"') break;
        }
        if (end >= self.src.len) return null;
        // unescape into a fresh buffer (handles \", \\, \n, \t, \r, \b, \f, \u00XX)
        var buf = std.ArrayList(u8).empty;
        // free the partial buffer on any error return below (toOwnedSlice at the
        // end empties buf, so this is a no-op on the success path).
        defer buf.deinit(self.gpa);
        var j = start;
        while (j < end) : (j += 1) {
            const c = self.src[j];
            if (c == '\\' and j + 1 < end) {
                j += 1;
                const e = self.src[j];
                switch (e) {
                    '"' => buf.append(self.gpa, '"') catch return null,
                    '\\' => buf.append(self.gpa, '\\') catch return null,
                    'n' => buf.append(self.gpa, '\n') catch return null,
                    't' => buf.append(self.gpa, '\t') catch return null,
                    'r' => buf.append(self.gpa, '\r') catch return null,
                    'b' => buf.append(self.gpa, 0x08) catch return null,
                    'f' => buf.append(self.gpa, 0x0C) catch return null,
                    'u' => {
                        // need 4 hex digits before the closing quote (j+4 < end);
                        // the old j+4 < end+1 rejected every valid \u escape.
                        if (j + 4 >= end) return null;
                        const hex = self.src[j + 1 .. j + 5];
                        // u8 parse accepts \u00XX only; \u01XX+ is BadWire (the
                        // canonical writer never emits it, and surrogates are not
                        // produced here).
                        const val = std.fmt.parseInt(u8, hex, 16) catch return null;
                        buf.append(self.gpa, val) catch return null;
                        j += 4;
                    },
                    else => return null,
                }
            } else {
                buf.append(self.gpa, c) catch return null;
            }
        }
        self.i = end + 1;
        return buf.toOwnedSlice(self.gpa) catch null;
    }
    fn parseNatural(self: *Parser) ?u64 {
        self.skipWs();
        const start = self.i;
        while (self.i < self.src.len and self.src[self.i] >= '0' and self.src[self.i] <= '9') self.i += 1;
        if (self.i == start) return null;
        return std.fmt.parseInt(u64, self.src[start..self.i], 10) catch null;
    }
    fn parseFieldValue(self: *Parser) ?FieldValue {
        self.skipWs();
        if (self.i >= self.src.len) return null;
        const c = self.src[self.i];
        if (c == '"') return .{ .text = self.parseString() orelse return null };
        if (c >= '0' and c <= '9') return .{ .natural = self.parseNatural() orelse return null };
        return null;
    }
};

/// Parse one JSON OBJECT `{ "name": value, ... }` into an ordered Field list
/// (the emitted key order is preserved — caller decides declared order).
fn parseJsonObject(gpa: Allocator, src: []const u8) WireErr![]Field {
    var p = Parser{ .src = src, .gpa = gpa };
    var fields = std.ArrayList(Field).empty;
    errdefer {
        // free the duped names + text values already appended (deinit alone
        // would only free the ArrayList struct — S4 leak).
        for (fields.items) |f| {
            gpa.free(f.name);
            if (f.value == .text) gpa.free(f.value.text);
        }
        fields.deinit(gpa);
    }
    if (!p.expectChar('{')) return error.BadWire;
    // allow empty object
    if (p.peek() == '}') {
        p.i += 1;
        return fields.toOwnedSlice(gpa) catch return error.NoMem;
    }
    while (true) {
        const name = p.parseString() orelse return error.BadWire;
        if (!p.expectChar(':')) {
            gpa.free(name);
            return error.BadWire;
        }
        const val = p.parseFieldValue() orelse {
            gpa.free(name);
            return error.BadWire;
        };
        fields.append(gpa, .{ .name = name, .value = val }) catch {
            gpa.free(name);
            if (val == .text) gpa.free(val.text);
            return error.NoMem;
        };
        if (p.expectChar(',')) {
            continue;
        } else if (p.expectChar('}')) {
            break;
        } else {
            return error.BadWire;
        }
    }
    return fields.toOwnedSlice(gpa) catch return error.NoMem;
}

/// Split wire bytes into LF-terminated logical records (rows) or a single value
/// (single).  Trailing empty line (the final LF) is not a record.
fn splitLines(gpa: Allocator, bytes: []const u8) WireErr![][]const u8 {
    var lines = std.ArrayList([]const u8).empty;
    errdefer lines.deinit(gpa);
    var start: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == '\n') {
            lines.append(gpa, bytes[start..i]) catch return error.NoMem;
            start = i + 1;
        }
    }
    if (start < bytes.len) {
        // unterminated final line
        lines.append(gpa, bytes[start..]) catch return error.NoMem;
    }
    return lines.toOwnedSlice(gpa) catch return error.NoMem;
}

pub const Decoded = union(enum) {
    rows: Rows,
    single: Single,

    pub fn deinit(self: Decoded, gpa: Allocator) void {
        switch (self) {
            .rows => |rows| {
                for (rows.records) |rec| {
                    for (rec.fields) |f| {
                        gpa.free(f.name);
                        switch (f.value) {
                            .text => |s| gpa.free(s),
                            else => {},
                        }
                    }
                    gpa.free(rec.fields);
                }
                gpa.free(rows.records);
            },
            .single => |s| {
                for (s.fields) |f| {
                    gpa.free(f.name);
                    switch (f.value) {
                        .text => |t| gpa.free(t),
                        else => {},
                    }
                }
                gpa.free(s.fields);
            },
        }
    }
};

/// Decode wire bytes against a Shape tag into an in-memory value.  For rows the
/// record type's DECLARED field order (names + kinds, from declaredFieldKinds)
/// is used to re-order fields (extra fields in the wire are dropped — width
/// subtyping).
pub fn decode(
    gpa: Allocator,
    bytes: []const u8,
    tag: anytype,
    declared_names: []const []const u8,
    declared_kinds: []const FieldKind,
) WireErr!Decoded {
    switch (tag) {
        .rows => {
            const raw_lines = try splitLines(gpa, bytes);
            defer gpa.free(raw_lines);
            var records = std.ArrayList(Row).empty;
            errdefer {
                // free every already-appended row's fields (deinit alone frees
                // only the ArrayList struct — S4 leak).
                for (records.items) |rec| {
                    for (rec.fields) |f| {
                        gpa.free(f.name);
                        if (f.value == .text) gpa.free(f.value.text);
                    }
                    gpa.free(rec.fields);
                }
                records.deinit(gpa);
            }
            for (raw_lines) |line| {
                if (line.len == 0) continue;
                const parsed = try parseJsonObject(gpa, line);
                defer gpa.free(parsed);
                // Track which parsed TEXT values get moved into `ordered` (their
                // ownership transfers).  Sized to parsed.len so it is correct for
                // ANY field count — a fixed 512-bit set would overflow past its
                // stack masks for a >512-field line (B3).
                const consumed = gpa.alloc(bool, parsed.len) catch return error.NoMem;
                @memset(consumed, false);
                defer {
                    for (parsed, 0..) |pf, idx| {
                        gpa.free(pf.name);
                        if (pf.value == .text and !consumed[idx]) gpa.free(pf.value.text);
                    }
                    gpa.free(consumed);
                }
                // re-order into declared key order, dropping extras
                var ordered = std.ArrayList(Field).empty;
                errdefer {
                    for (ordered.items) |f| {
                        gpa.free(f.name);
                        if (f.value == .text) gpa.free(f.value.text);
                    }
                    ordered.deinit(gpa);
                }
                for (declared_names, declared_kinds) |name, kind| {
                    var found: ?FieldValue = null;
                    var found_idx: ?usize = null;
                    for (parsed, 0..) |f, idx| {
                        if (std.mem.eql(u8, f.name, name)) {
                            found = f.value;
                            found_idx = idx;
                            break;
                        }
                    }
                    const v = found orelse continue; // missing field -> drop
                    // check kind
                    const ok = switch (kind) {
                        .text => v == .text,
                        .natural => v == .natural,
                    };
                    if (!ok) return error.BadType;
                    // The declared label lives in the caller's buffer (names);
                    // dupe it so decoded fields own their name independently.
                    const owned_name = gpa.dupe(u8, name) catch return error.NoMem;
                    if (v == .text) consumed[found_idx.?] = true;
                    ordered.append(gpa, .{ .name = owned_name, .value = v }) catch return error.NoMem;
                }
                const fields_slice = ordered.toOwnedSlice(gpa) catch return error.NoMem;
                records.append(gpa, .{ .fields = fields_slice }) catch {
                    for (fields_slice) |f| {
                        gpa.free(f.name);
                        if (f.value == .text) gpa.free(f.value.text);
                    }
                    gpa.free(fields_slice);
                    return error.NoMem;
                };
            }
            return .{ .rows = .{ .records = records.toOwnedSlice(gpa) catch return error.NoMem } };
        },
        .single => {
            // single: first non-empty LF-terminated line is the value
            const raw_lines = try splitLines(gpa, bytes);
            defer gpa.free(raw_lines);
            var line: []const u8 = "";
            for (raw_lines) |l| {
                if (l.len > 0) {
                    line = l;
                    break;
                }
            }
            const fields = try parseJsonObject(gpa, line);
            return .{ .single = .{ .fields = fields } };
        },
        else => return error.BadType,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn row(fields: []const Field) Row {
    return .{ .fields = fields };
}

test "bytes/lines round-trip raw (zero transform)" {
    const gpa = testing.allocator;
    const raw = "hello world\nsecond line\n\x00\x01\x02\xFF";
    const enc = try encode(gpa, .{ .bytes = raw }, .{ .tag = .bytes });
    defer gpa.free(enc);
    try testing.expectEqualStrings(raw, enc);
    const enc2 = try encode(gpa, .{ .lines = raw }, .{ .tag = .lines });
    defer gpa.free(enc2);
    try testing.expectEqualStrings(raw, enc2);
}

test "rows encode -> decode round-trip preserves fields" {
    const gpa = testing.allocator;
    const rec_src = "{ path : Text, size : Natural }";
    const kk = try declaredFieldKinds(gpa, rec_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }

    const rows_v = Rows{ .records = &.{
        row(&.{ .{ .name = "path", .value = .{ .text = "/a" } }, .{ .name = "size", .value = .{ .natural = 42 } } }),
        row(&.{ .{ .name = "path", .value = .{ .text = "/b" } }, .{ .name = "size", .value = .{ .natural = 7 } } }),
    } };

    const enc = try encodeRowsOrdered(gpa, rows_v, kk.names, kk.kinds);
    defer gpa.free(enc);

    const want = "{\"path\":\"/a\",\"size\":42}\n{\"path\":\"/b\",\"size\":7}\n";
    try testing.expectEqualStrings(want, enc);

    const dec = try decode(gpa, enc, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try testing.expectEqual(@as(usize, 2), r.records.len);
            try testing.expectEqual(@as(usize, 2), r.records[0].fields.len);
            try testing.expectEqualStrings("/a", r.records[0].fields[0].value.text);
        },
        else => unreachable,
    }
}

test "T1: canonical key order follows the DECLARED field order" {
    const gpa = testing.allocator;

    // same DATA, two different declared record types
    const data = Rows{ .records = &.{
        row(&.{ .{ .name = "path", .value = .{ .text = "/x" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 5 } }, .{ .name = "mtime", .value = .{ .natural = 100 } } }),
    } };

    const t1_src = "{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }";
    const kk1 = try declaredFieldKinds(gpa, t1_src);
    defer {
        for (kk1.names) |n| gpa.free(n);
        gpa.free(kk1.names);
        gpa.free(kk1.kinds);
    }
    const enc1 = try encodeRowsOrdered(gpa, data, kk1.names, kk1.kinds);
    defer gpa.free(enc1);

    const t2_src = "{ size : Natural, path : Text, kind : < File | Dir >, mtime : Natural }";
    const kk2 = try declaredFieldKinds(gpa, t2_src);
    defer {
        for (kk2.names) |n| gpa.free(n);
        gpa.free(kk2.names);
        gpa.free(kk2.kinds);
    }
    const enc2 = try encodeRowsOrdered(gpa, data, kk2.names, kk2.kinds);
    defer gpa.free(enc2);

    // same data, different declared order -> bytes MUST differ
    try testing.expect(!std.mem.eql(u8, enc1, enc2));
    try testing.expectEqualStrings("{\"path\":\"/x\",\"kind\":\"File\",\"size\":5,\"mtime\":100}\n", enc1);
    try testing.expectEqualStrings("{\"size\":5,\"path\":\"/x\",\"kind\":\"File\",\"mtime\":100}\n", enc2);
}

test "width subtyping: decode drops extra fields" {
    const gpa = testing.allocator;

    // producer emits 4 fields, consumer declared with only {path}
    const wide_src = "{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }";
    const kk = try declaredFieldKinds(gpa, wide_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const data = Rows{ .records = &.{
        row(&.{ .{ .name = "path", .value = .{ .text = "/a" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } }),
    } };
    const enc = try encodeRowsOrdered(gpa, data, kk.names, kk.kinds);
    defer gpa.free(enc);

    // narrow declared type
    const narrow_src = "{ path : Text }";
    const narrow = try declaredFieldKinds(gpa, narrow_src);
    defer {
        for (narrow.names) |n| gpa.free(n);
        gpa.free(narrow.names);
        gpa.free(narrow.kinds);
    }

    const dec = try decode(gpa, enc, .rows, narrow.names, narrow.kinds);
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try testing.expectEqual(@as(usize, 1), r.records.len);
            try testing.expectEqual(@as(usize, 1), r.records[0].fields.len);
            try testing.expectEqualStrings("path", r.records[0].fields[0].name);
            try testing.expectEqualStrings("/a", r.records[0].fields[0].value.text);
        },
        else => unreachable,
    }
}

test "single encodes as one canonical JSON value, LF-terminated" {
    const gpa = testing.allocator;
    const single_v = Single{ .fields = &.{
        .{ .name = "lines", .value = .{ .natural = 3 } },
        .{ .name = "words", .value = .{ .natural = 12 } },
        .{ .name = "bytes", .value = .{ .natural = 67 } },
    } };
    const enc = try encodeSingleOrdered(gpa, single_v, &.{ "lines", "words", "bytes" }, &.{ .natural, .natural, .natural });
    defer gpa.free(enc);
    try testing.expectEqualStrings("{\"lines\":3,\"words\":12,\"bytes\":67}\n", enc);
}

test "encode rejects rows/single (no declared order available)" {
    const gpa = testing.allocator;
    try testing.expectError(error.BadType, encode(gpa, .{ .single = .{ .fields = &.{} } }, .{ .tag = .single }));
    try testing.expectError(error.BadType, encode(gpa, .{ .rows = .{ .records = &.{} } }, .{ .tag = .rows }));
}

test "decode error paths are leak-free: BadType on kind mismatch" {
    const gpa = testing.allocator;
    // declared { size : Natural } but the wire carries a string
    const enc = "{\"size\":\"not-a-number\"}\n";
    try testing.expectError(error.BadType, decode(gpa, enc, .rows, &.{"size"}, &.{.natural}));
}

test "decode error paths are leak-free: BadWire mid-object" {
    const gpa = testing.allocator;
    // a name with no colon/value after it
    const enc = "{\"path\":\"ok\",\"kind\"}\n";
    try testing.expectError(error.BadWire, decode(gpa, enc, .rows, &.{"path"}, &.{.text}));
}

test "decode handles a row with more than 512 fields (B3)" {
    const gpa = testing.allocator;
    // Build one JSON object with 600 fields; the LAST one is the declared "z".
    var line = std.ArrayList(u8).empty;
    defer line.deinit(gpa);
    line.append(gpa, '{') catch unreachable;
    var k: usize = 0;
    while (k < 599) : (k += 1) {
        if (k > 0) line.append(gpa, ',') catch unreachable;
        line.print(gpa, "\"a{d}\":{d}", .{ k, k }) catch unreachable;
    }
    line.appendSlice(gpa, ",\"z\":\"value\"}\n") catch unreachable;
    const dec = try decode(gpa, line.items, .rows, &.{"z"}, &.{.text});
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try testing.expectEqual(@as(usize, 1), r.records.len);
            try testing.expectEqual(@as(usize, 1), r.records[0].fields.len);
            try testing.expectEqualStrings("z", r.records[0].fields[0].name);
            try testing.expectEqualStrings("value", r.records[0].fields[0].value.text);
        },
        else => unreachable,
    }
}

test "\\u escape decodes (N2)" {
    const gpa = testing.allocator;
    // \u000a is a newline; the writer emits control chars <0x20 this way.
    const dec = try decode(gpa, "{\"path\":\"a\\u000ab\"}\n", .rows, &.{"path"}, &.{.text});
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| try testing.expectEqualStrings("a\nb", r.records[0].fields[0].value.text),
        else => unreachable,
    }
}

test "json string escaping matches caslog rules" {
    const gpa = testing.allocator;
    const s = "quote\" back\\ nl\n tab\t";
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const fields = [_]Field{.{ .name = "a", .value = .{ .text = s } }};
    try writeCanonicalJsonObject(gpa, &out, &.{"a"}, &.{.text}, &fields);
    try testing.expectEqualStrings("{\"a\":\"quote\\\" back\\\\ nl\\n tab\\t\"}", out.items);
}

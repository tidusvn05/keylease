#!/usr/bin/env python3
"""Generate Swift Codable models from `keylease contracts` output.

Usage:
    cargo run -p keylease-cli -- contracts > contracts.json
    scripts/generate-swift-contracts.py contracts.json \
        apps/desktop-macos/Sources/KeyLeaseCore/Generated/ContractModels.swift

The generator deliberately supports only the JSON Schema features schemars
emits for this workspace today. Anything new fails loudly so a schema change
forces an explicit decision instead of silent mis-generation.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field

SWIFT_KEYWORDS = {
    "associatedtype", "class", "deinit", "enum", "extension", "fileprivate",
    "func", "import", "init", "inout", "internal", "let", "open", "operator",
    "private", "precedencegroup", "protocol", "public", "rethrows", "static",
    "struct", "subscript", "typealias", "var", "break", "case", "catch",
    "continue", "default", "defer", "do", "else", "fallthrough", "for",
    "guard", "if", "in", "repeat", "return", "throw", "switch", "where",
    "while", "as", "any", "false", "is", "nil", "self", "Self", "super",
    "throw", "throws", "true", "try", "Type", "Protocol",
}

INT_FORMATS = {
    "uint8": "UInt8",
    "uint16": "UInt16",
    "uint32": "UInt32",
    "uint64": "UInt64",
    "int8": "Int8",
    "int16": "Int16",
    "int32": "Int32",
    "int64": "Int64",
    "uint": "UInt",
    "int": "Int",
    "usize": "UInt",
}


def pascal(name: str) -> str:
    return "".join(part.capitalize() or "_" for part in re.split(r"[_\-]", name))


def camel(name: str) -> str:
    p = pascal(name)
    return p[:1].lower() + p[1:] if p else name


def prop_name(name: str) -> str:
    out = camel(name)
    return f"`{out}`" if out in SWIFT_KEYWORDS else out


class GenError(Exception):
    pass


@dataclass
class EnumVariant:
    const: str
    case_name: str
    fields: list  # list[(wire_name, swift_type, optional)]
    struct_name: str


@dataclass
class Context:
    """Collects every named type so one output file can reference them all."""

    defs: dict = field(default_factory=dict)  # name -> schema
    synthetic: dict = field(default_factory=dict)  # anonymous objects
    emitted: set = field(default_factory=set)


def resolve_type(schema: dict, ctx: Context, hint: str) -> str:
    """Map a JSON Schema fragment to a Swift type name."""
    if schema is True:
        return "JSONValue"
    if schema is False:
        raise GenError(f"`false` schema at {hint} accepts no value")
    if not isinstance(schema, dict):
        raise GenError(f"non-object schema at {hint}")
    if not schema:
        return "JSONValue"
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise GenError(f"unsupported ref {ref} at {hint}")
        return ref.split("/")[-1]
    if "anyOf" in schema or "oneOf" in schema:
        key = "anyOf" if "anyOf" in schema else "oneOf"
        variants = schema[key]
        non_null = [v for v in variants if v.get("type") != "null"]
        if len(non_null) == 1 and len(non_null) != len(variants):
            return resolve_type(non_null[0], ctx, hint) + "?"
        if key == "oneOf" and _discriminator(variants):
            raise GenError(
                f"discriminated union at {hint} must be a named $defs entry"
            )
        raise GenError(f"unsupported {key} at {hint}")
    if "enum" in schema:
        raise GenError(f"anonymous enum at {hint} must be a named $defs entry")
    if "const" in schema:
        return "String"

    typ = schema.get("type")
    if isinstance(typ, list):
        non_null = [t for t in typ if t != "null"]
        if len(non_null) == 1:
            inner = dict(schema, type=non_null[0])
            return resolve_type(inner, ctx, hint) + "?"
        raise GenError(f"unsupported type union {typ} at {hint}")
    if typ == "string":
        return "String"
    if typ == "boolean":
        return "Bool"
    if typ == "integer":
        return INT_FORMATS.get(schema.get("format", "int"), "Int")
    if typ == "number":
        return "Double"
    if typ == "array":
        return "[" + resolve_type(schema.get("items", {}), ctx, hint) + "]"
    if typ == "object":
        addl = schema.get("additionalProperties")
        if "properties" in schema:
            # Inline object: synthesize a named sibling type.
            parts = [p for p in hint.split(".") if p]
            synth = pascal("_".join(parts[1:])) or pascal(parts[0])
            existing = ctx.synthetic.get(synth)
            if existing is not None and json.dumps(
                existing, sort_keys=True
            ) != json.dumps(schema, sort_keys=True):
                raise GenError(
                    f"anonymous object at {hint} collides with {synth}"
                )
            ctx.synthetic[synth] = schema
            return synth
        if addl is True or addl is None:
            return "[String: JSONValue]"
        return (
            "[String: " + resolve_type(addl, ctx, hint) + "]"
        )
    if typ is None and "properties" in schema:
        parts = [p for p in hint.split(".") if p]
        synth = pascal("_".join(parts[1:])) or pascal(parts[0])
        ctx.synthetic.setdefault(synth, schema)
        return synth
    if typ == "null":
        return "JSONValue"
    raise GenError(f"unsupported schema at {hint}: {json.dumps(schema)[:120]}")


def _discriminator(variants: list) -> str | None:
    """Return the shared const property name if variants form a tagged union."""
    candidates = None
    for v in variants:
        props = v.get("properties", {})
        consts = {
            k for k, p in props.items() if isinstance(p, dict) and "const" in p
        }
        candidates = consts if candidates is None else candidates & consts
    if not candidates:
        return None
    return sorted(candidates)[0]


def _fields_of(schema: dict, ctx: Context, hint: str, skip: set) -> list:
    required = set(schema.get("required", []))
    out = []
    for wire, prop in schema.get("properties", {}).items():
        if wire in skip:
            continue
        optional = wire not in required
        typ = resolve_type(prop, ctx, f"{hint}.{wire}")
        if optional and not typ.endswith("?"):
            typ += "?"
        out.append((wire, prop_name(wire), typ, optional))
    return out


def _enum_from_oneof(name: str, variants: list, ctx: Context) -> str:
    disc = _discriminator(variants)
    if disc is None:
        raise GenError(f"{name}: oneOf without a shared const discriminator")
    cases = []
    decls = []
    for v in variants:
        const = v["properties"][disc]["const"]
        case = camel(const)
        if case in SWIFT_KEYWORDS:
            case = f"`{case}`"
        fields = _fields_of(v, ctx, f"{name}.{const}", skip={disc})
        struct_name = f"{name}{pascal(const)}"
        if not fields:
            decls.append(
                f"    public struct {struct_name}: Codable, Equatable, Sendable "
                "{ public init() {} }"
            )
        else:
            lines = [
                f"    public struct {struct_name}: Codable, Equatable, Sendable {{"
            ]
            for wire, prop, typ, _ in fields:
                lines.append(f"        public let {prop}: {typ}")
            args = ", ".join(f"{p}: {t}" for _, p, t, _ in fields)
            assigns = "\n".join(
                f"            self.{p} = {p}" for _, p, _, _ in fields
            )
            lines.append(f"        public init({args}) {{")
            lines.append(assigns)
            lines.append("        }")
            if any(wire != p for wire, p, _, _ in fields):
                lines.append("        private enum CodingKeys: String, CodingKey {")
                for wire, p, _, _ in fields:
                    lines.append(f'            case {p} = "{wire}"')
                lines.append("        }")
            lines.append("    }")
            decls.append("\n".join(lines))
        cases.append((const, case, struct_name))
    out = [f"public enum {name}: Codable, Equatable, Sendable {{"]
    out.extend(decls)
    for const, case, struct_name in cases:
        out.append(f"    case {case}({struct_name})")
    out.append(f'    private enum Discriminator: String, Codable {{')
    for const, case, _ in cases:
        out.append(f'        case {case} = "{const}"')
    out.append("    }")
    out.append("    private enum CodingKeys: String, CodingKey {")
    out.append(f'        case discriminator = "{disc}"')
    out.append("    }")
    out.append(
        "    public init(from decoder: Decoder) throws {"
    )
    out.append(
        "        let container = try decoder.container(keyedBy: CodingKeys.self)"
    )
    out.append(
        "        switch try container.decode(Discriminator.self, "
        "forKey: .discriminator) {"
    )
    for const, case, struct_name in cases:
        out.append(
            f"        case .{case}: self = .{case}"
            f"(try {struct_name}(from: decoder))"
        )
    out.append("        }")
    out.append("    }")
    out.append("    public func encode(to encoder: Encoder) throws {")
    out.append(
        "        var container = encoder.container(keyedBy: CodingKeys.self)"
    )
    out.append("        switch self {")
    for const, case, struct_name in cases:
        out.append(f"        case .{case}(let payload):")
        out.append(
            f"            try container.encode(Discriminator.{case}, "
            "forKey: .discriminator)"
        )
        out.append("            try payload.encode(to: encoder)")
    out.append("        }")
    out.append("    }")
    out.append("}")
    return "\n".join(out)


def _string_enum(name: str, schema: dict) -> str:
    values = schema["enum"]
    if not all(isinstance(v, str) for v in values):
        raise GenError(f"{name}: non-string enum values")
    out = [
        f"public enum {name}: String, Codable, CaseIterable, Equatable, "
        "Sendable {"
    ]
    for v in values:
        case = camel(v)
        if case in SWIFT_KEYWORDS:
            case = f"`{case}`"
        out.append(f'    case {case} = "{v}"')
    out.append("}")
    return "\n".join(out)


def _struct(name: str, schema: dict, ctx: Context) -> str:
    fields = _fields_of(schema, ctx, name, skip=set())
    out = [f"public struct {name}: Codable, Equatable, Sendable {{"]
    for wire, prop, typ, _ in fields:
        out.append(f"    public let {prop}: {typ}")
    args = ", ".join(f"{p}: {t}" for _, p, t, _ in fields)
    out.append(f"    public init({args}) {{")
    for _, p, _, _ in fields:
        out.append(f"        self.{p} = {p}")
    out.append("    }")
    if any(wire != p for wire, p, _, _ in fields):
        out.append("    private enum CodingKeys: String, CodingKey {")
        for wire, p, _, _ in fields:
            out.append(f'        case {p} = "{wire}"')
        out.append("    }")
    out.append("}")
    return "\n".join(out)


def emit_type(name: str, schema: dict, ctx: Context) -> str:
    if "oneOf" in schema:
        return _enum_from_oneof(name, schema["oneOf"], ctx)
    if schema.get("type") == "string" and "enum" in schema:
        return _string_enum(name, schema)
    if schema.get("type") == "object" and "properties" in schema:
        return _struct(name, schema, ctx)
    raise GenError(
        f"{name}: unsupported top-level schema {json.dumps(schema)[:120]}"
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    contracts_path, out_path = sys.argv[1], sys.argv[2]
    contracts = json.load(open(contracts_path))
    schemas = contracts["schemas"]

    ctx = Context()
    # Collect $defs across every schema; identical names must be identical
    # types, otherwise the shared file would silently pick one.
    for sname, schema in schemas.items():
        for dname, dschema in schema.get("$defs", {}).items():
            if dname in ctx.defs:
                if json.dumps(ctx.defs[dname], sort_keys=True) != json.dumps(
                    dschema, sort_keys=True
                ):
                    raise GenError(
                        f"$defs/{dname} differs between schemas; "
                        "rename one in Rust before generating"
                    )
            else:
                ctx.defs[dname] = dschema

    chunks = [
        "// Generated by scripts/generate-swift-contracts.py from "
        "`keylease contracts`. Do not edit.",
        "// Regenerate: scripts/generate-swift-contracts.py <contracts.json>"
        " <this file>",
        "",
        "import Foundation",
        "",
        f"public enum KeyLeaseContract {{ public static let version = "
        f"{contracts['contract_version']} }}",
        "",
    ]

    for dname in sorted(ctx.defs):
        chunks.append(emit_type(dname, ctx.defs[dname], ctx))
        chunks.append("")
    for sname in sorted(schemas):
        tname = pascal(sname)
        if tname in ctx.defs:
            # A top-level schema whose PascalCase name matches a shared def:
            # only safe to skip when the shapes are identical.
            meta = {"$schema", "title", "description", "$defs"}
            schema = {
                k: v for k, v in schemas[sname].items() if k not in meta
            }
            dschema = {
                k: v for k, v in ctx.defs[tname].items() if k not in meta
            }
            if json.dumps(schema, sort_keys=True) != json.dumps(
                dschema, sort_keys=True
            ):
                raise GenError(
                    f"top-level schema {sname} collides with $defs/{tname} "
                    "but has a different shape"
                )
            continue
        if tname in ctx.emitted:
            continue
        ctx.emitted.add(tname)
        chunks.append(emit_type(tname, schemas[sname], ctx))
        chunks.append("")

    # Anonymous inline objects discovered while emitting, possibly nested.
    while ctx.synthetic:
        pending = sorted(ctx.synthetic)
        for sname in pending:
            schema = ctx.synthetic.pop(sname)
            if sname in ctx.emitted or sname in ctx.defs:
                continue
            ctx.emitted.add(sname)
            chunks.append(emit_type(sname, schema, ctx))
            chunks.append("")

    with open(out_path, "w") as fh:
        fh.write("\n".join(chunks).rstrip() + "\n")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GenError as exc:
        print(f"generate-swift-contracts: {exc}", file=sys.stderr)
        sys.exit(1)

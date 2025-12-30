use anyhow::{Context as _, Result};
use scroll::Pread;

use std::collections::HashMap;
use std::env;
use std::fs::File;

// CTF Format Constants
const CTF_MAGIC: u16 = 0xcff1;
const CTF_VERSION: u8 = 2;
const CTF_F_COMPRESS: u8 = 0x01;

// Type encoding constants
const CTF_MAX_VLEN: u16 = 0x3ff;
const CTF_MAX_SIZE: u16 = 0xfffe;
const CTF_LSIZE_SENT: u16 = 0xffff;

// Type kinds
const CTF_K_UNKNOWN: u16 = 0;
const CTF_K_INTEGER: u16 = 1;
const CTF_K_FLOAT: u16 = 2;
const CTF_K_POINTER: u16 = 3;
const CTF_K_ARRAY: u16 = 4;
const CTF_K_FUNCTION: u16 = 5;
const CTF_K_STRUCT: u16 = 6;
const CTF_K_UNION: u16 = 7;
const CTF_K_ENUM: u16 = 8;
const CTF_K_FORWARD: u16 = 9;
const CTF_K_TYPEDEF: u16 = 10;
const CTF_K_VOLATILE: u16 = 11;
const CTF_K_CONST: u16 = 12;
const CTF_K_RESTRICT: u16 = 13;

// Integer encoding flags
const CTF_INT_SIGNED: u32 = 0x01;
const CTF_INT_CHAR: u32 = 0x02;
const CTF_INT_BOOL: u32 = 0x04;
const CTF_INT_VARARGS: u32 = 0x08;

// Float encoding values
const CTF_FP_SINGLE: u32 = 1;
const CTF_FP_DOUBLE: u32 = 2;
const CTF_FP_CPLX: u32 = 3;
const CTF_FP_DCPLX: u32 = 4;
const CTF_FP_LDCPLX: u32 = 5;
const CTF_FP_LDOUBLE: u32 = 6;
const CTF_FP_INTRVL: u32 = 7;
const CTF_FP_DINTRVL: u32 = 8;
const CTF_FP_LDINTRVL: u32 = 9;
const CTF_FP_IMAGRY: u32 = 10;
const CTF_FP_DIMAGRY: u32 = 11;
const CTF_FP_LDIMAGRY: u32 = 12;

const HEADER_SIZE: usize = 36;

#[derive(Pread, Debug)]
struct CtfPreamble {
    magic: u16,
    version: u8,
    flags: u8,
}

#[derive(Pread, Debug)]
struct CtfHeader {
    preamble: CtfPreamble,
    parlabel: u32,
    parname: u32,
    lbloff: u32,
    objtoff: u32,
    funcoff: u32,
    typeoff: u32,
    stroff: u32,
    strlen: u32,
}

#[derive(Debug)]
struct CtfLabel {
    name: u32,
    typeidx: u32,
}

#[derive(Debug)]
struct CtfArray {
    contents: u16,
    index: u16,
    nelems: u32,
}

#[derive(Debug)]
struct CtfMember {
    name: u32,
    type_id: u16,
    offset: u16,
}

#[derive(Debug)]
struct CtfLMember {
    name: u32,
    type_id: u16,
    offsethi: u32,
    offsetlo: u32,
}

#[derive(Debug)]
struct CtfEnum {
    name: u32,
    value: i32,
}

#[derive(Debug)]
struct TypeInfo {
    kind: u16,
    is_root: bool,
    vlen: u16,
}

struct CtfValidator<'a> {
    data: &'a [u8],
    header: CtfHeader,
    strings: &'a [u8],
    is_child: bool,
    max_type_id: u16,
}

impl<'a> CtfValidator<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            anyhow::bail!(
                "input len {} is less than CTF header size of 36",
                data.len()
            );
        }

        let header: CtfHeader = data.pread(0).context("failed to read header")?;

        if header.preamble.magic != CTF_MAGIC {
            anyhow::bail!(
                "Invalid magic number: 0x{:04x}, expected 0x{CTF_MAGIC:04x}",
                header.preamble.magic
            );
        }

        if header.preamble.version != CTF_VERSION {
            anyhow::bail!(
                "Unsupported version: {}, expected {CTF_VERSION}",
                header.preamble.version
            );
        }

        if header.preamble.flags & CTF_F_COMPRESS != 0 {
            anyhow::bail!("compressed CTF not supported");
        }

        let str_start = HEADER_SIZE + header.stroff as usize;
        let str_end = str_start + header.strlen as usize;

        if str_end > data.len() {
            anyhow::bail!("strlen would exceed end of file");
        }

        let strings = &data[str_start..str_end];

        // Check if this is a child (has a parent name)
        let is_child = header.parname != 0;

        Ok(CtfValidator {
            data,
            header,
            strings,
            is_child,
            max_type_id: 0x8000,
        })
    }

    fn validate_string_ref(&self, offset: u32, table_id: u8) -> Result<&str> {
        // String identifier: high bit indicates table (0=internal, 1=external)
        let actual_offset = offset & 0x7fffffff;
        let table = ((offset >> 31) & 1) as u8;

        if table != table_id {
            anyhow::bail!("String reference uses wrong table: got {table}, expected {table_id}");
        }

        if table == 1 {
            // External string table (ELF symbol table) - we can't validate this
            return Ok("<external string>");
        }

        if actual_offset as usize >= self.strings.len() {
            anyhow::bail!(
                "String offset 0x{actual_offset:x} out of bounds (string table size: 0x{:x})",
                self.strings.len()
            );
        }

        // Find null terminator
        let start = actual_offset as usize;
        let mut end = start;
        while end < self.strings.len() && self.strings[end] != 0 {
            end += 1;
        }

        if end >= self.strings.len() {
            anyhow::bail!("String at offset 0x{actual_offset:x} not null-terminated");
        }

        match std::str::from_utf8(&self.strings[start..end]) {
            Ok(s) => Ok(s),
            Err(_) => Err(anyhow::anyhow!(
                "Invalid UTF-8 in string at offset 0x{:x}",
                actual_offset
            )),
        }
    }

    fn validate_type_id(&self, type_id: u16, allow_zero: bool) -> Result<()> {
        if type_id == 0 {
            if allow_zero {
                return Ok(());
            }
            anyhow::bail!("Type ID 0 used where not allowed");
        }

        if self.is_child {
            // Child can reference 0x1-0x7fff (parent) or 0x8000-0xffff (own types)
            if type_id > self.max_type_id && type_id >= 0x8000 {
                anyhow::bail!(
                    "Type ID 0x{type_id:x} exceeds maximum 0x{:x}",
                    self.max_type_id
                );
            }
        } else {
            // Non-child can only reference 0x1-0x7fff
            if type_id > 0x7fff {
                anyhow::bail!("Type ID 0x{type_id:x} invalid for non-child file");
            }
            if type_id > self.max_type_id {
                anyhow::bail!(
                    "Type ID 0x{type_id:x} exceeds maximum 0x{:x}",
                    self.max_type_id
                );
            }
        }

        Ok(())
    }

    fn decode_type_info(info: u16) -> TypeInfo {
        let kind = (info & 0xf800) >> 11;
        let is_root = (info & 0x0400) >> 10 != 0;
        let vlen = info & CTF_MAX_VLEN;

        TypeInfo {
            kind,
            is_root,
            vlen,
        }
    }

    fn kind_name(kind: u16) -> &'static str {
        match kind {
            CTF_K_UNKNOWN => "UNKNOWN",
            CTF_K_INTEGER => "INTEGER",
            CTF_K_FLOAT => "FLOAT",
            CTF_K_POINTER => "POINTER",
            CTF_K_ARRAY => "ARRAY",
            CTF_K_FUNCTION => "FUNCTION",
            CTF_K_STRUCT => "STRUCT",
            CTF_K_UNION => "UNION",
            CTF_K_ENUM => "ENUM",
            CTF_K_FORWARD => "FORWARD",
            CTF_K_TYPEDEF => "TYPEDEF",
            CTF_K_VOLATILE => "VOLATILE",
            CTF_K_CONST => "CONST",
            CTF_K_RESTRICT => "RESTRICT",
            _ => "INVALID",
        }
    }

    fn validate_labels(&self) -> Result<()> {
        println!("\n=== Validating Label Section ===");

        let start = HEADER_SIZE + self.header.lbloff as usize;
        let end = HEADER_SIZE + self.header.objtoff as usize;

        if !start.is_multiple_of(4) {
            anyhow::bail!("Label section not 4-byte aligned");
        }

        if start == end {
            println!("No labels defined");
            return Ok(());
        }

        let mut offset = start;
        let mut label_idx = 0;

        while offset < end {
            if offset + 8 > end {
                anyhow::bail!("Incomplete label at offset 0x{offset:x}");
            }

            let name_offset: u32 = self.data.gread(&mut offset)?;
            let type_idx: u32 = self.data.gread(&mut offset)?;

            let name = self
                .validate_string_ref(name_offset, 0)
                .context("label_name")?;

            println!("Label {label_idx}: '{name}' (type_idx: 0x{type_idx:x})",);

            label_idx += 1;
        }

        println!("Total labels: {}", label_idx);
        Ok(())
    }

    fn validate_objects(&self) -> Result<()> {
        println!("\n=== Validating Object Section ===");

        let start = HEADER_SIZE + self.header.objtoff as usize;
        let end = HEADER_SIZE + self.header.funcoff as usize;

        if !start.is_multiple_of(2) {
            anyhow::bail!("Object section not 2-byte aligned");
        }

        if start == end {
            println!("No objects defined");
            return Ok(());
        }

        let num_objects = (end - start) / 2;
        println!("Number of object entries: {}", num_objects);

        for i in 0..num_objects {
            let mut offset = start + i * 2;
            let type_id: u16 = self.data.gread(&mut offset)?;

            if type_id != 0 {
                self.validate_type_id(type_id, true)?;
            }
        }

        println!("All object type references valid");
        Ok(())
    }

    fn validate_functions(&self) -> Result<()> {
        println!("\n=== Validating Function Section ===");

        let start = 36 + self.header.funcoff as usize;
        let end = 36 + self.header.typeoff as usize;

        if !start.is_multiple_of(2) {
            anyhow::bail!("Function section not 2-byte aligned");
        }

        if start == end {
            println!("No functions defined");
            return Ok(());
        }

        let mut offset = start;
        let mut func_idx = 0;

        while offset < end {
            let info: u16 = self.data.gread(&mut offset)?;

            let type_info = Self::decode_type_info(info);

            if type_info.kind == CTF_K_UNKNOWN && type_info.vlen == 0 {
                // No type info for this function
                println!("Function {}: <no type info>", func_idx);
            } else if type_info.kind == CTF_K_FUNCTION {
                if offset + size_of::<u16>() > end {
                    anyhow::bail!("Incomplete function at index {func_idx}");
                }

                let return_type: u16 = self.data.gread(&mut offset)?;

                self.validate_type_id(return_type, true)?;

                let mut nargs = type_info.vlen;
                let mut has_varargs = false;

                // Read argument types
                for arg in 0..nargs {
                    if offset + size_of::<u16>() > end {
                        anyhow::bail!("Incomplete arguments for function {func_idx}");
                    }

                    let arg_type: u16 = self.data.gread(&mut offset)?;

                    if arg_type == 0 {
                        has_varargs = true;
                        if arg != nargs - 1 {
                            anyhow::bail!("Varargs argument not last in function {func_idx}");
                        }
                    } else {
                        self.validate_type_id(arg_type, false)?;
                    }
                }

                //if !nargs.is_multiple_of(2) {
                //    // Padding arg
                //    offset += size_of::<u16>();
                //}

                println!(
                    "Function {}: return=0x{:x}, args={}{}, root={}",
                    func_idx,
                    return_type,
                    if has_varargs { nargs - 1 } else { nargs },
                    if has_varargs { "+varargs" } else { "" },
                    type_info.is_root
                );
            } else {
                anyhow::bail!(
                    "Invalid function kind {} at index {func_idx}",
                    type_info.kind
                );
            }

            func_idx += 1;
        }

        println!("Total functions: {}", func_idx);
        Ok(())
    }

    fn validate_types(&mut self) -> Result<()> {
        println!("\n=== Validating Type Section ===");

        let start = HEADER_SIZE + self.header.typeoff as usize;
        let end = HEADER_SIZE + self.header.stroff as usize;

        if !start.is_multiple_of(4) {
            anyhow::bail!("Type section not 4-byte aligned");
        }

        if start == end {
            println!("No types defined");
            return Ok(());
        }

        let mut offset = start;
        let mut type_id = if self.is_child { 0x8000u16 } else { 1u16 };

        while offset < end {
            let obj_start = offset;
            if offset + 8 > end {
                anyhow::bail!("Incomplete type at offset 0x{offset:x}");
            }

            let name_offset: u32 = self.data.gread(&mut offset)?;
            let info: u16 = self.data.gread(&mut offset)?;

            let type_info = Self::decode_type_info(info);
            dbg!(&type_info);
            let name = self
                .validate_string_ref(name_offset, 0)
                .context("type_name")?;

            print!(
                "Type {type_id}: kind={} ({}), vlen={}, root={}, name='{name}'",
                type_info.kind,
                Self::kind_name(type_info.kind),
                type_info.vlen,
                type_info.is_root,
            );

            let size_or_type: u16 = self.data.gread(&mut offset)?;

            match type_info.kind {
                CTF_K_INTEGER => {
                    if type_info.vlen != 0 {
                        anyhow::bail!("Integer type 0x{type_id:x} has non-zero vlen");
                    }
                    println!(", size={size_or_type} bytes");

                    if offset + size_of::<u32>() > end {
                        anyhow::bail!("Incomplete integer encoding at type 0x{type_id:x}");
                    }
                    let encoding: u32 = self.data.gread(&mut offset)?;

                    let enc_flags = (encoding >> 24) & 0xff;
                    let enc_offset = (encoding >> 16) & 0xff;
                    let enc_bits = encoding & 0xffff;
                }

                CTF_K_FLOAT => {
                    if type_info.vlen != 0 {
                        anyhow::bail!("Float type 0x{type_id:x} has non-zero vlen");
                    }
                    println!(", size={size_or_type} bytes");

                    if offset + 12 > end {
                        anyhow::bail!("Incomplete float encoding at type 0x{type_id:x}");
                    }
                    let encoding: u32 = self.data.gread(&mut offset)?;

                    let fp_encoding = (encoding >> 24) & 0xff;
                    if !(CTF_FP_SINGLE..=CTF_FP_LDIMAGRY).contains(&fp_encoding) {
                        anyhow::bail!(
                            "Invalid float encoding {fp_encoding} for type 0x{type_id:x}"
                        );
                    }
                }

                CTF_K_ARRAY => {
                    if type_info.vlen != 0 {
                        anyhow::bail!("Array type 0x{type_id:x} has non-zero vlen");
                    }
                    if size_or_type != 0 {
                        anyhow::bail!("Array type 0x{type_id:x} has non-zero size");
                    }

                    if offset + 16 > end {
                        anyhow::bail!("Incomplete array at type 0x{type_id:x}");
                    }

                    let contents: u16 = self.data.gread(&mut offset)?;
                    let index: u16 = self.data.gread(&mut offset)?;
                    let nelems: u32 = self.data.gread(&mut offset)?;

                    self.validate_type_id(contents, false)?;
                    self.validate_type_id(index, false)?;

                    println!(
                        ", contents=0x{:x}, index=0x{:x}, nelems={}",
                        contents, index, nelems
                    );
                }

                CTF_K_FUNCTION => {
                    hexdump(&self.data[obj_start..offset + 4]);
                    self.validate_type_id(size_or_type, true)?;

                    let nargs = type_info.vlen as usize;
                    print!(", return={}, args={}", size_or_type, nargs);

                    for arg in 0..nargs {
                        if offset + 2 * (arg + 1) > end {
                            anyhow::bail!("Incomplete function arguments at type 0x{type_id:x}");
                        }
                        let arg_type: u16 = self.data.gread(&mut offset)?;
                        if arg_type != 0 {
                            self.validate_type_id(arg_type, false)?;
                        }
                    }

                    if !nargs.is_multiple_of(2) {
                        // Padding arg. Undocumented by man page.
                        offset += size_of::<u16>();
                    }

                    println!();
                }

                CTF_K_STRUCT | CTF_K_UNION => {
                    let is_large = size_or_type == CTF_LSIZE_SENT;
                    let actual_size = if is_large {
                        if offset + 16 > end {
                            anyhow::bail!("Incomplete large struct/union at type 0x{type_id:x}");
                        }
                        let size_hi: u64 = self.data.gread(&mut offset)?;
                        let size_lo: u64 = self.data.gread(&mut offset)?;
                        (size_hi << 32) | size_lo
                    } else {
                        size_or_type as u64
                    };

                    println!(", size={actual_size} bytes, members={}", type_info.vlen);

                    let member_size = if actual_size >= 8192 { 12 } else { 8 };

                    for i in 0..type_info.vlen {
                        if offset + member_size > end {
                            anyhow::bail!("Incomplete member {i} at type 0x{type_id:x}");
                        }

                        let member_name: u32 = self.data.gread(&mut offset)?;
                        let member_type: u16 = self.data.gread(&mut offset)?;
                        let member_offset: u16 = self.data.gread(&mut offset)?;

                        let mn = self.validate_string_ref(member_name, 0)?;
                        self.validate_type_id(member_type, false)?;
                        println!("  Member {mn} - Type 0x{member_type:x}: offset={member_offset}",);
                    }
                }

                CTF_K_ENUM => {
                    if size_or_type != 4 {
                        anyhow::bail!(
                            "Enum type 0x{type_id:x} has size {size_or_type} (expected 4)"
                        );
                    }

                    println!(", enumerators={}", type_info.vlen);

                    for i in 0..type_info.vlen {
                        let enum_offset = offset + 8 * i as usize;
                        if enum_offset + 8 > end {
                            anyhow::bail!("Incomplete enumerator {i} at type 0x{type_id:x}");
                        }

                        let enum_name: u32 = self.data.gread(&mut offset)?;
                        let _ = self.validate_string_ref(enum_name, 0);
                    }
                }

                CTF_K_FORWARD => {
                    unimplemented!();
                }

                CTF_K_POINTER | CTF_K_TYPEDEF | CTF_K_VOLATILE | CTF_K_CONST | CTF_K_RESTRICT => {
                    if type_info.vlen != 0 {
                        anyhow::bail!(
                            "{} type 0x{type_id:x} has non-zero vlen",
                            Self::kind_name(type_info.kind),
                        );
                    }
                    self.validate_type_id(size_or_type, false)?;
                    println!(", refers_to={size_or_type}");
                }

                CTF_K_UNKNOWN => {
                    println!(" <gap>");
                }

                _ => {
                    anyhow::bail!("Unknown type kind {} at type 0x{type_id:x}", type_info.kind,);
                }
            }

            if type_id == 0x7fff && !self.is_child {
                anyhow::bail!("Type ID exceeded 0x7fff in non-child file");
            }
            if type_id == 0xffff {
                anyhow::bail!("Type ID exceeded 0xffff");
            }

            type_id += 1;
        }

        self.max_type_id = type_id - 1;
        println!(
            "\nTotal types: {} (max ID: {:})",
            if self.is_child {
                type_id - 0x8000
            } else {
                type_id - 1
            },
            self.max_type_id
        );

        Ok(())
    }

    fn validate_strings(&self) -> Result<()> {
        println!("\n=== Validating String Section ===");

        if self.strings.is_empty() {
            anyhow::bail!("String section is empty");
        }

        if self.strings[0] != 0 {
            anyhow::bail!("String section does not start with null terminator");
        }

        let mut offset = 0;
        let mut string_count = 0;
        let mut total_length = 0;

        while offset < self.strings.len() {
            let start = offset;
            while offset < self.strings.len() && self.strings[offset] != 0 {
                offset += 1;
            }

            if offset >= self.strings.len() {
                anyhow::bail!("Unterminated string at offset {start}");
            }

            let len = offset - start;
            total_length += len;
            string_count += 1;
            offset += 1; // Skip null terminator
        }

        println!("String section size: {} bytes", self.strings.len());
        println!("Number of strings: {string_count}");
        println!("Total character data: {total_length} bytes");
        println!("Overhead (null terminators): {string_count} bytes",);

        Ok(())
    }

    fn validate(&mut self) -> Result<()> {
        println!("=== CTF File Validation ===");
        println!("Magic: 0x{:04x}", self.header.preamble.magic);
        println!("Version: {}", self.header.preamble.version);
        println!("Flags: 0x{:02x}", self.header.preamble.flags);
        println!("Is child: {}", self.is_child);

        if self.is_child {
            let parent_name = self
                .validate_string_ref(self.header.parname, 0)
                .context("parent_name")?;
            println!("parent_name: '{}'", parent_name);

            if self.header.parlabel != 0 {
                let parent_label = self
                    .validate_string_ref(self.header.parlabel, 0)
                    .context("parent_parlabel")?;
                println!("Parent label: '{}'", parent_label);
            }
        }

        println!("\nSection offsets:");
        println!(
            "  Labels:    0x{:x} - 0x{:x}",
            36 + self.header.lbloff,
            36 + self.header.objtoff
        );
        println!(
            "  Objects:   0x{:x} - 0x{:x}",
            36 + self.header.objtoff,
            36 + self.header.funcoff
        );
        println!(
            "  Functions: 0x{:x} - 0x{:x}",
            36 + self.header.funcoff,
            36 + self.header.typeoff
        );
        println!(
            "  Types:     0x{:x} - 0x{:x}",
            36 + self.header.typeoff,
            36 + self.header.stroff
        );
        println!(
            "  Strings:   0x{:x} - 0x{:x}",
            36 + self.header.stroff,
            36 + self.header.stroff + self.header.strlen
        );

        self.validate_labels()?;
        self.validate_objects()?;
        self.validate_types()?;
        self.validate_functions()?;
        self.validate_strings()?;

        println!("\n=== Validation Complete ===");
        println!("✓ All validations passed!");

        Ok(())
    }
}

fn hexdump(data: &[u8]) {
    println!();
    for (i, chunk) in data.chunks(16).enumerate() {
        // Print offset
        print!("{:08x}: ", i * 16);

        // Print hex bytes (in pairs)
        for (j, byte) in chunk.iter().enumerate() {
            if j > 0 && j % 2 == 0 {
                print!(" ");
            }
            print!("{:02x}", byte);
        }

        // Pad if less than 16 bytes
        let padding = (16 - chunk.len()) * 2 + (16 - chunk.len()) / 2;
        print!("{:width$}", "", width = padding);

        // Print ASCII representation
        print!("  ");
        for byte in chunk {
            let c = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            print!("{}", c);
        }

        println!();
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <ctf_file>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    let file = File::open(filename)?;

    let data = unsafe { memmap2::Mmap::map(&file)? };

    let mut validator = match CtfValidator::new(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error reading CTF file: {}", e);
            std::process::exit(1);
        }
    };

    validator.validate()
}

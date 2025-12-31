use crate::GlobalTypeOffset;

// CTF Constants
pub const CTF_MAGIC: u16 = 0xcff1;
pub const CTF_VERSION: u8 = 2;
pub const CTF_F_COMPRESS: u8 = 0x01;
pub const CTF_MAX_VLEN: u16 = 0x3ff;

// CTF Type Kinds
pub const CTF_K_UNKNOWN: u8 = 0;
pub const CTF_K_INTEGER: u8 = 1;
pub const CTF_K_FLOAT: u8 = 2;
pub const CTF_K_POINTER: u8 = 3;
pub const CTF_K_ARRAY: u8 = 4;
pub const CTF_K_FUNCTION: u8 = 5;
pub const CTF_K_STRUCT: u8 = 6;
pub const CTF_K_UNION: u8 = 7;
pub const CTF_K_ENUM: u8 = 8;
pub const _CTF_K_FORWARD: u8 = 9; // We will never forward-declare a Rust type.
pub const CTF_K_TYPEDEF: u8 = 10;
pub const CTF_K_VOLATILE: u8 = 11;
pub const CTF_K_CONST: u8 = 12;
pub const CTF_K_RESTRICT: u8 = 13;

// CTF Integer Encoding Flags
pub const CTF_INT_SIGNED: u8 = 0x01;
pub const CTF_INT_CHAR: u8 = 0x02;
pub const CTF_INT_BOOL: u8 = 0x04;

pub fn ctf_type_info(kind: u8, is_root: bool, vlen: u16) -> u16 {
    ((kind as u16) << 11) | ((if is_root { 1u16 } else { 0 }) << 10) | (vlen & CTF_MAX_VLEN)
}

pub fn ctf_int_data(encoding: u8, offset: u8, bits: u32) -> u32 {
    ((encoding as u32) << 24) | ((offset as u32) << 16) | bits
}

#[derive(Debug)]
#[repr(C)]
pub struct CtfPreamble {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
}

#[derive(Debug)]
#[repr(C)]
pub struct CtfHeader {
    pub preamble: CtfPreamble,
    pub parlabel: u32,
    pub parname: u32,
    pub lbloff: u32,
    pub objtoff: u32,
    pub funcoff: u32,
    pub typeoff: u32,
    pub stroff: u32,
    pub strlen: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MaybeOffset {
    Found(u16),
    Pending(GlobalTypeOffset),
}

#[derive(Clone, Debug)]
pub enum CtfType {
    Integer {
        name: String,
        size: u32,
        encoding: u32,
    },
    Float {
        name: String,
        size: u32,
        encoding: u32,
    },
    Pointer {
        name: String,
        target_type: MaybeOffset,
    },
    Typedef {
        name: String,
        target_type: MaybeOffset,
    },
    Const {
        name: String,
        target_type: MaybeOffset,
    },
    Volatile {
        name: String,
        target_type: MaybeOffset,
    },
    Restrict {
        name: String,
        target_type: MaybeOffset,
    },
    Array {
        name: String,
        element_type: MaybeOffset,
        index_type: MaybeOffset,
        nelems: u32,
    },
    Struct {
        name: String,
        size: u32,
        members: Vec<CtfMember>,
    },
    Union {
        name: String,
        size: u32,
        members: Vec<CtfMember>,
    },
    Enum {
        name: String,
        size: u32,
        enumerators: Vec<CtfEnumerator>,
    },
    Function {
        name: String,
        return_type: MaybeOffset,
        args: Vec<MaybeOffset>,
        is_varargs: bool,
    },
    Unknown,
}

impl CtfType {
    pub fn name(&self) -> &str {
        match self {
            Self::Integer { name, .. } => name,
            Self::Float { name, .. } => name,
            Self::Pointer { name, .. } => name,
            Self::Typedef { name, .. } => name,
            Self::Const { name, .. } => name,
            Self::Volatile { name, .. } => name,
            Self::Restrict { name, .. } => name,
            Self::Struct { name, .. } => name,
            Self::Union { name, .. } => name,
            Self::Enum { name, .. } => name,
            Self::Function { name, .. } => name,
            Self::Array { name, .. } => name,
            Self::Unknown => "<unknown>",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CtfEnumerator {
    pub name: String,
    pub value: i32,
}

#[derive(Clone, Debug)]
pub struct CtfMember {
    pub name: String,
    pub type_id: MaybeOffset,
    pub offset_bits: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctf_type_info_unknown() {
        // kind=0, not root, vlen=0
        let info = ctf_type_info(CTF_K_UNKNOWN, false, 0);
        assert_eq!(info, 0);
    }

    #[test]
    fn test_ctf_type_info_integer_root() {
        // kind=1 (INTEGER), root=1, vlen=0
        let info = ctf_type_info(CTF_K_INTEGER, true, 0);
        // kind (5 bits) << 11 | root << 10 | vlen
        // 0b00001 << 11 | 1 << 10 | 0 = 0x0800 | 0x0400 = 0x0c00
        assert_eq!(info, 0x0c00);
    }

    #[test]
    fn test_ctf_type_info_struct_with_members() {
        // kind=6 (STRUCT), root=1, vlen=3 (3 members)
        let info = ctf_type_info(CTF_K_STRUCT, true, 3);
        // 0b00110 << 11 | 1 << 10 | 3 = 0x3000 | 0x0400 | 0x0003 = 0x3403
        assert_eq!(info, 0x3403);
    }

    #[test]
    fn test_ctf_type_info_vlen_max() {
        // vlen is masked to 10 bits (max 0x3ff = 1023)
        let info = ctf_type_info(CTF_K_STRUCT, true, 0xFFFF);
        let vlen = info & CTF_MAX_VLEN;
        assert_eq!(vlen, CTF_MAX_VLEN);
    }

    #[test]
    fn test_ctf_type_info_pointer_no_root() {
        // kind=3 (POINTER), root=0, vlen=0
        let info = ctf_type_info(CTF_K_POINTER, false, 0);
        // 0b00011 << 11 = 0x1800
        assert_eq!(info, 0x1800);
    }

    #[test]
    fn test_ctf_int_data_signed_32bit() {
        // encoding=SIGNED, offset=0, bits=32
        let data = ctf_int_data(CTF_INT_SIGNED, 0, 32);
        // 0x01 << 24 | 0 << 16 | 32 = 0x01000020
        assert_eq!(data, 0x01000020);
    }

    #[test]
    fn test_ctf_int_data_char() {
        // encoding=CHAR|SIGNED, offset=0, bits=8
        let data = ctf_int_data(CTF_INT_CHAR | CTF_INT_SIGNED, 0, 8);
        // 0x03 << 24 | 0 << 16 | 8 = 0x03000008
        assert_eq!(data, 0x03000008);
    }

    #[test]
    fn test_ctf_int_data_bool() {
        // encoding=BOOL, offset=0, bits=8
        let data = ctf_int_data(CTF_INT_BOOL, 0, 8);
        // 0x04 << 24 | 0 << 16 | 8 = 0x04000008
        assert_eq!(data, 0x04000008);
    }

    #[test]
    fn test_ctf_int_data_with_offset() {
        // encoding=0, offset=16, bits=16 (bitfield scenario)
        let data = ctf_int_data(0, 16, 16);
        // 0 << 24 | 16 << 16 | 16 = 0x00100010
        assert_eq!(data, 0x00100010);
    }

    #[test]
    fn test_ctf_type_name() {
        let int_type = CtfType::Integer {
            name: "int".to_string(),
            size: 4,
            encoding: 0,
        };
        assert_eq!(int_type.name(), "int");

        let ptr_type = CtfType::Pointer {
            name: "*mut u8".to_string(),
            target_type: MaybeOffset::Found(1),
        };
        assert_eq!(ptr_type.name(), "*mut u8");

        assert_eq!(CtfType::Unknown.name(), "<unknown>");
    }
}

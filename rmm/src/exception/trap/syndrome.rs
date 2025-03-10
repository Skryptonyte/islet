use aarch64_cpu::registers::*;

#[derive(Debug, Copy, Clone)]
pub enum Fault {
    AddressSize { level: u8 },
    Translation { level: u8 },
    AccessFlag { level: u8 },
    Permission { level: u8 },
    Alignment,
    TLBConflict,
    Other(u8),
}

const DFSC_MASK: u8 = 0x3f;
const ISS_BRK_CMT_MASK: u16 = 0xffff;

impl From<u32> for Fault {
    fn from(origin: u32) -> Self {
        let level = (origin & 0b11) as u8;
        let origin = origin as u8;
        match (origin & DFSC_MASK) >> 2 {
            0b0000 => Fault::AddressSize { level },
            0b0001 => Fault::Translation { level },
            0b0010 => Fault::AccessFlag { level },
            0b0011 => Fault::Permission { level },
            0b1000 => Fault::Alignment,
            0b1100 => Fault::TLBConflict,
            _ => Fault::Other(origin & DFSC_MASK),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Syndrome {
    Unknown,
    PCAlignmentFault,
    DataAbort(Fault),
    InstructionAbort(Fault),
    SPAlignmentFault,
    Brk(u16),
    HVC,
    SMC,
    SysRegInst,
    WFX,
    FPU,
    SVE,
    SME,
    Other(u32),
}

impl From<u32> for Syndrome {
    fn from(origin: u32) -> Self {
        match (origin >> ESR_EL2::EC.shift) & ESR_EL2::EC.mask as u32 {
            0b00_0000 => Syndrome::Unknown,
            0b00_0001 => Syndrome::WFX,
            0b00_0111 => Syndrome::FPU,
            0b01_0010 => Syndrome::HVC,
            0b01_0110 => Syndrome::HVC,
            0b01_0011 => Syndrome::SMC,
            0b01_0111 => Syndrome::SMC,
            0b01_1000 => Syndrome::SysRegInst,
            0b01_1001 => Syndrome::SVE,
            0b01_1101 => Syndrome::SME,
            0b10_0000 => {
                debug!("Instruction Abort from a lower Exception level");
                Syndrome::InstructionAbort(Fault::from(origin))
            }
            0b10_0001 => {
                debug!("Instruction Abort taken without a change in Exception level");
                Syndrome::InstructionAbort(Fault::from(origin))
            }
            0b10_0010 => Syndrome::PCAlignmentFault,
            0b10_0100 => {
                debug!("Data Abort from a lower Exception level");
                Syndrome::DataAbort(Fault::from(origin))
            }
            0b10_0101 => {
                debug!("Data Abort without a change in Exception level");
                Syndrome::DataAbort(Fault::from(origin))
            }
            0b10_0110 => Syndrome::SPAlignmentFault,
            0b11_1100 => Syndrome::Brk(origin as u16 & ISS_BRK_CMT_MASK),
            ec => Syndrome::Other(ec),
        }
    }
}

impl Into<u64> for Syndrome {
    fn into(self) -> u64 {
        match self {
            Syndrome::DataAbort(fault) => {
                let ec: u64 = 0b10_0100 << ESR_EL2::EC.shift;
                let iss: u64 = fault.into();
                ec | iss
            }
            _ => {
                panic!("Not implemented yet!");
            }
        }
    }
}

impl Into<u64> for Fault {
    fn into(self) -> u64 {
        match self {
            Fault::Translation { level } => (0b000100 | level) as u64,
            _ => {
                panic!("Not implemented yet!");
            }
        }
    }
}

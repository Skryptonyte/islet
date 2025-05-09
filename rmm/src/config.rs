pub const NUM_OF_CPU: usize = 8;
pub const NUM_OF_CLUSTER: usize = 2;
pub const NUM_OF_CPU_PER_CLUSTER: usize = NUM_OF_CPU / NUM_OF_CLUSTER;

pub const PAGE_BITS: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS; // 4KiB
pub const LARGE_PAGE_SIZE: usize = 1024 * 1024 * 2; // 2MiB
pub const HUGE_PAGE_SIZE: usize = 1024 * 1024 * 1024; // 1GiB

pub const RMM_STACK_GUARD_SIZE: usize = crate::granule::GRANULE_SIZE * 1;
pub const RMM_STACK_SIZE: usize = 1024 * 1024 - RMM_STACK_GUARD_SIZE;
pub const RMM_HEAP_SIZE: usize = 16 * 1024 * 1024;

pub const VM_STACK_SIZE: usize = 1 << 15;
pub const STACK_ALIGN: usize = 16;

// TODO: Acquire this address properly.
pub const RMM_SHARED_BUFFER_START: usize = 0xFFBFF000;

#[derive(Debug, Default)]
pub struct PlatformMemoryLayout {
    pub rmm_base: u64,
    pub rw_start: u64,
    pub rw_end: u64,
    pub stack_base: u64,
    pub uart_phys: u64,
}

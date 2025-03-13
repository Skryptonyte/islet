#![no_main]

use islet_rmm::rmi::{REC_ENTER, SUCCESS};
use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::{Run, REC_ENTRY_FLAG_EMUL_MMIO};
use islet_rmm::rec::context::set_reg;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target};

const DataAbort: usize = 2 << 4;

#[derive(Debug, arbitrary::Arbitrary)]
struct DataAbortFuzz {
    esr: u64,
    hsr: u64,
    hpfar: u64,
}

fuzz_target!(|data: DataAbortFuzz| {
    let rd = mock::host::realm_setup();

    let (rec1, run1) = (alloc_granule(IDX_REC1), alloc_granule(IDX_REC1_RUN));

    unsafe {
        let rec = &mut *(rec1 as *mut Rec<'_>);
        let run = &mut *(run1 as *mut Run);

        rec.context.sys_regs.esr_el2 = data.esr & !(1 << 21);

        emulate_realm_exit([DataAbort,
                            data.esr as usize,
                            data.hsr as usize,
                            data.hpfar as usize],
                            rec, run);

        run.set_entry_flags(REC_ENTRY_FLAG_EMUL_MMIO);
    }

    let _ret = rmi::<REC_ENTER>(&[rec1, run1]);

    mock::host::realm_teardown(rd);
});

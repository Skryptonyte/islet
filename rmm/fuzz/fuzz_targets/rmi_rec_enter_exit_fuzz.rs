#![no_main]

use islet_rmm::rmi::{REC_ENTER, SUCCESS};
use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::Run;
use islet_rmm::rec::context::set_reg;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target};

/* Fuzz exits outside or RSI and Data aborts */
#[derive(Debug, arbitrary::Arbitrary)]
enum ExitReason {
    IRQ = 1,
    FIQ = 2,
    PSCI = 3,
    SError = 4,
    InstAbort = 3 << 4,
}

#[derive(Debug, arbitrary::Arbitrary)]
struct DataAbortFuzz {
    command: ExitReason,
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

        emulate_realm_exit([data.command as usize,
                            data.esr as usize,
                            data.hsr as usize,
                            data.hpfar as usize],
                            rec, run);
    }

    let _ret = rmi::<REC_ENTER>(&[rec1, run1]);

    mock::host::realm_teardown(rd);
});

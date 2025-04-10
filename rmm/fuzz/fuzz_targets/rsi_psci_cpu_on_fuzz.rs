#![no_main]

use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::Run;
use islet_rmm::rmi::{PSCI_COMPLETE, REC_ENTER, SUCCESS, SUCCESS_REC_ENTER};
use islet_rmm::rsi::PSCI_CPU_ON;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target};

#[derive(Debug, arbitrary::Arbitrary)]
struct PSCICpuOnFuzz {
    target: u64,
    entrypoint: u64,
    context_id: u32,
    status: usize,
    target_runnable: bool,
}

fuzz_target!(|data: PSCICpuOnFuzz| {
    let rd = mock::host::realm_setup();
    let target = data.target as usize;
    let entrypoint = data.entrypoint as usize;
    let context_id = data.entrypoint as usize;
    let status = data.status;
    let target_runnable = data.target_runnable as u64;

    let (rec1, run1) = (alloc_granule(IDX_REC1), alloc_granule(IDX_REC1_RUN));

    let rec2 = alloc_granule(IDX_REC2);

    let ret = rmi::<REC_ENTER>(&[rec1, run1, PSCI_CPU_ON, target, entrypoint, context_id]);

    if ret[0] == SUCCESS {
        unsafe {
            let target_rec = &mut *(rec2 as *mut Rec<'_>);
            target_rec.set_runnable(target_runnable);
        }

        let _ret = rmi::<PSCI_COMPLETE>(&[rec1, rec2, status]);
    }

    mock::host::realm_teardown(rd);
});

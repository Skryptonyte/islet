#![no_main]

use islet_rmm::rmi::{REC_ENTER, PSCI_COMPLETE, SUCCESS, SUCCESS_REC_ENTER};
use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::Run;
use islet_rmm::rec::context::set_reg;
use islet_rmm::rsi::PSCI_AFFINITY_INFO;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target};

#[derive(Debug, arbitrary::Arbitrary)]
struct PSCIAffinityFuzz {
    target_affinity: u64,
    lowest_affinity_level: u32,
    status: usize,
    target_runnable: bool,
}

fuzz_target!(|data: PSCIAffinityFuzz| {
    let rd = mock::host::realm_setup();
    let target_affinity = data.target_affinity as usize;
    let lowest_affinity_level = data.lowest_affinity_level as usize;
    let status = data.status;
    let target_runnable = data.target_runnable as u64;

    let (rec1, run1) = (alloc_granule(IDX_REC1), alloc_granule(IDX_REC1_RUN));

    let _ret = rmi::<REC_ENTER>(&[rec1, run1]);

    let rec2 = alloc_granule(IDX_REC2);

    unsafe {
        let rec = &mut *(rec1 as *mut Rec<'_>);
        let run = &mut *(run1 as *mut Run);
        let target_rec = &mut *(rec2 as *mut Rec<'_>);

        target_rec.set_runnable(target_runnable);

        let ret = rsi::<PSCI_AFFINITY_INFO>(&[target_affinity, lowest_affinity_level], rec, run);

        if ret[0] != SUCCESS_REC_ENTER {
            let _ret = rmi::<PSCI_COMPLETE>(&[rec1, rec2, status]);
        }
    }

    mock::host::realm_teardown(rd);
});

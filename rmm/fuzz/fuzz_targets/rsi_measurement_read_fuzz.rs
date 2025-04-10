#![no_main]

use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::Run;
use islet_rmm::rmi::{REC_ENTER, SUCCESS};
use islet_rmm::rsi::MEASUREMENT_READ;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: u64| {
    let rd = mock::host::realm_setup();
    let measurement_index = data as usize;

    let (rec1, run1) = (alloc_granule(IDX_REC1), alloc_granule(IDX_REC1_RUN));

    let _ret = rmi::<REC_ENTER>(&[rec1, run1, MEASUREMENT_READ, measurement_index]);

    mock::host::realm_teardown(rd);
});

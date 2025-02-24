#![no_main]

use islet_rmm::rmi::{RTT_READ_ENTRY, RTT_INIT_RIPAS, DATA_CREATE_UNKNOWN, DATA_DESTROY,
                     RTT_MAP_UNPROTECTED, RTT_UNMAP_UNPROTECTED, GRANULE_DELEGATE,
                     GRANULE_UNDELEGATE, RTT_FOLD, SUCCESS};
use islet_rmm::granule::GRANULE_SIZE;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target, Corpus};

const L2_PAGE_COUNT: usize = L2_SIZE / L3_SIZE;

#[derive(Debug, Copy, Clone, PartialEq, arbitrary::Arbitrary)]
enum FoldType {
    UnassignedRam,
    AssignedRam,
    UnassignedNS,
    AssignedNS,
}

#[derive(Debug, arbitrary::Arbitrary)]
struct RTTFoldFuzz {
    base: u64,
    fold_type: FoldType
}

fn destroy_table(rd: usize, base: usize, fold_type: FoldType) {
    match fold_type {
        FoldType::AssignedRam => {
            for i in 0..L2_PAGE_COUNT {
                let ret = rmi::<DATA_DESTROY>(&[rd, base + i * L3_SIZE]);

                assert_eq!(ret[0], SUCCESS);

                let data_granule = alloc_granule(IDX_DATA_FOLD + i);
                let ret = rmi::<GRANULE_UNDELEGATE>(&[data_granule]);
                assert_eq!(ret[0], SUCCESS);
            }
        },
        FoldType::AssignedNS => {
            for i in 0..L2_PAGE_COUNT {
                let ret = rmi::<RTT_UNMAP_UNPROTECTED>(&[rd, base + i * L3_SIZE, MAP_LEVEL]);
                assert_eq!(ret[0], SUCCESS);
            }
        },
        _ => {}
    }
}

fn setup_table(rd: usize, base: usize, fold_type: FoldType) -> bool {
    let top = base + L2_SIZE;

    /* Trying to setup ASSIGNED_NS/UNASSIGNED_NS on protected IPA should be rejected */
    if top <= (1 << (IPA_WIDTH - 1)) &&
       (fold_type == FoldType::AssignedNS || fold_type == FoldType::UnassignedNS) {
        return false;
    }

    if fold_type == FoldType::UnassignedRam || fold_type == FoldType::AssignedRam {
        let ret = rmi::<RTT_INIT_RIPAS>(&[rd, base, top]);

        if ret[0] != SUCCESS {
            return false;
        }
    }

    match fold_type {
        FoldType::AssignedRam => {
            for i in 0..L2_PAGE_COUNT {
                let data_granule = alloc_granule(IDX_DATA_FOLD + i);
                let ret = rmi::<GRANULE_DELEGATE>(&[data_granule]);
                assert_eq!(ret[0], SUCCESS);

                let ret = rmi::<DATA_CREATE_UNKNOWN>(&[rd, data_granule, base + i * L3_SIZE]);
                assert_eq!(ret[0], SUCCESS);
            }
        },
        FoldType::AssignedNS => {
            for i in 0..L2_PAGE_COUNT {
                let ns = alloc_granule(IDX_NS_DESC);

                let ret = rmi::<RTT_MAP_UNPROTECTED>(&[rd, base + i * L3_SIZE, MAP_LEVEL, ns]);
                assert_eq!(ret[0], SUCCESS);
            }
        },
        FoldType::UnassignedNS => {
            for i in 0..L2_PAGE_COUNT {
                let ns = alloc_granule(IDX_NS_DESC);

                let ret = rmi::<RTT_MAP_UNPROTECTED>(&[rd, base + i * L3_SIZE, MAP_LEVEL, ns]);
                assert_eq!(ret[0], SUCCESS);

                let ret = rmi::<RTT_UNMAP_UNPROTECTED>(&[rd, base + i * L3_SIZE, MAP_LEVEL]);
                assert_eq!(ret[0], SUCCESS);
            }
        },
        _ => {}
    }

    true
}

fuzz_target!(|data: RTTFoldFuzz| -> Corpus {
    let base = (data.base as usize / L2_SIZE) * L2_SIZE;
    let top = match (data.base as usize).checked_add(L2_SIZE) {
        Some(x) => x,
        None => {
            return Corpus::Reject;
        }
    };
    let fold_type = data.fold_type;

    let rd = realm_create();

    /* Reject IPAs which cannot be mapped */
    let ret = rmi::<RTT_READ_ENTRY>(&[rd, base, MAP_LEVEL]);
    if ret[0] != SUCCESS {
        realm_destroy(rd);
        return Corpus::Reject;
    }

    mock::host::map(rd, base);

    let ret = setup_table(rd, base, fold_type);
    if !ret {
        mock::host::unmap(rd, base, false);
        realm_destroy(rd);
        return Corpus::Reject;
    }

    let ret = rmi::<RTT_FOLD>(&[rd, base, MAP_LEVEL]);

    destroy_table(rd, base, fold_type);

    if ret[0] == SUCCESS {
        mock::host::unmap(rd, base, true);
    } else {
        mock::host::unmap(rd, base, false);
    }

    realm_destroy(rd);
    Corpus::Keep
});

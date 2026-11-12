// SPDX-License-Identifier: Apache-2.0

//! Descriptor-ownership and protocol tests of the private syscall seam. Memfds
//! stand in for fscontext/root descriptors; these tests do not mount EROFS or
//! establish that a fake backend returned a valid filesystem view.

use super::*;
use nix::{
    fcntl::{fcntl, FcntlArg},
    sys::memfd::{memfd_create, MFdFlags},
};
use std::{
    cell::{Cell, RefCell},
    os::{fd::IntoRawFd, unix::fs::FileExt},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

const STEPS: [MountStep; 5] = [
    MountStep::Open,
    MountStep::ReadOnly,
    MountStep::Source,
    MountStep::Create,
    MountStep::Mount,
];
const PAYLOAD: &[u8] = b"descriptor fixture; not a filesystem image";

struct DescriptorStamp {
    number: i32,
    target: PathBuf,
}
impl DescriptorStamp {
    fn new(file: &File) -> Self {
        let number = file.as_raw_fd();
        let target = std::fs::read_link(format!("/proc/self/fd/{number}")).unwrap();
        Self { number, target }
    }
    fn is_live(&self) -> bool {
        std::fs::read_link(format!("/proc/self/fd/{}", self.number))
            .is_ok_and(|target| target == self.target)
    }
    fn assert_closed(&self) {
        // A different test can reuse the numeric FD. Unique memfd names make
        // this assertion about our resource rather than a recycled number.
        assert!(
            !self.is_live(),
            "descriptor remains open: {:?}",
            self.target
        );
    }
}
fn sentinel(role: &str) -> File {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let name = CString::new(format!(
        "mount-seam-{role}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
    .unwrap();
    File::from(memfd_create(name.as_c_str(), MFdFlags::MFD_CLOEXEC).unwrap())
}

struct FakeMountApi {
    calls: RefCell<Vec<MountStep>>,
    context: RefCell<Option<DescriptorStamp>>,
    root: RefCell<Option<DescriptorStamp>>,
    fail: Option<MountStep>,
    cancel_after: Option<MountStep>,
    cancelled: Cell<bool>,
    backing_number: i32,
}
impl FakeMountApi {
    fn new(backing: &SealedImageBytes) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            context: RefCell::new(None),
            root: RefCell::new(None),
            fail: None,
            cancel_after: None,
            cancelled: Cell::new(false),
            backing_number: backing.as_fd().as_raw_fd(),
        }
    }
    fn enter(&self, step: MountStep) -> io::Result<()> {
        let index = self.calls.borrow().len();
        assert_eq!(STEPS.get(index), Some(&step), "unexpected mount operation");
        self.calls.borrow_mut().push(step);
        if self.fail == Some(step) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if self.cancel_after == Some(step) {
            self.cancelled.set(true);
        }
        Ok(())
    }
    fn assert_context_live(&self, context: &File) {
        let held = self.context.borrow();
        let held = held.as_ref().expect("context was created");
        assert_eq!(context.as_raw_fd(), held.number);
        assert!(held.is_live());
        assert_ne!(
            fcntl(context, FcntlArg::F_GETFD).unwrap() & libc::FD_CLOEXEC,
            0
        );
    }
    fn assert_owned_descriptors_closed(&self) {
        if let Some(context) = self.context.borrow().as_ref() {
            context.assert_closed();
        }
        if let Some(root) = self.root.borrow().as_ref() {
            root.assert_closed();
        }
    }
    fn cancelled(&self) -> bool {
        // The post-fsmount cancellation boundary must run after the context
        // reconfiguration handle has been closed, even on late cancellation.
        if self.calls.borrow().last() == Some(&MountStep::Mount) && self.root.borrow().is_some() {
            self.context.borrow().as_ref().unwrap().assert_closed();
        }
        self.cancelled.get()
    }
}
impl MountApi for FakeMountApi {
    fn open(&self) -> io::Result<File> {
        self.enter(MountStep::Open)?;
        let context = sentinel("context");
        *self.context.borrow_mut() = Some(DescriptorStamp::new(&context));
        Ok(context)
    }
    fn config(
        &self,
        context: &File,
        command: libc::c_uint,
        key: Option<&CStr>,
        value: Option<&CStr>,
    ) -> io::Result<()> {
        self.assert_context_live(context);
        match self.calls.borrow().len() {
            1 => {
                assert_eq!(command, SET_FLAG);
                assert_eq!(key, Some(c"ro"));
                assert_eq!(value, None);
            }
            2 => {
                assert_eq!(command, SET_STRING);
                assert_eq!(key, Some(c"source"));
                assert_eq!(
                    value.unwrap().to_bytes(),
                    format!("/proc/self/fd/{}", self.backing_number).as_bytes()
                );
                // Reopen the exact supplied path to establish that this private
                // source refers to the still-live sealed input, not a caller path.
                let source = File::open(value.unwrap().to_str().unwrap()).unwrap();
                let mut bytes = vec![0; PAYLOAD.len()];
                source.read_exact_at(&mut bytes, 0).unwrap();
                assert_eq!(bytes, PAYLOAD);
                assert_ne!(
                    fcntl(&source, FcntlArg::F_GET_SEALS).unwrap() & libc::F_SEAL_WRITE,
                    0
                );
            }
            3 => {
                assert_eq!(command, CREATE_EXCLUSIVE);
                assert_eq!(key, None);
                assert_eq!(value, None);
            }
            other => panic!("unexpected config operation {other}"),
        }
        let step = STEPS[self.calls.borrow().len()];
        self.enter(step)
    }
    fn mount(&self, context: &File) -> io::Result<File> {
        self.assert_context_live(context);
        self.enter(MountStep::Mount)?;
        let root = sentinel("root");
        *self.root.borrow_mut() = Some(DescriptorStamp::new(&root));
        Ok(root)
    }
}
fn backing() -> SealedImageBytes {
    SealedImageBytes::from_bytes(PAYLOAD, 4096).unwrap()
}
fn assert_backing_unchanged(backing: &SealedImageBytes) {
    let file = File::from(backing.as_fd().try_clone_to_owned().unwrap());
    let mut bytes = vec![0; PAYLOAD.len()];
    file.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, PAYLOAD);
    assert_eq!(backing.byte_len(), PAYLOAD.len() as u64);
}

#[test]
fn syscall_seam_uses_fixed_owned_input_protocol_and_closes_context_before_success() {
    // Fixed Linux UAPI contract: exclusive creation, CLOEXEC and an executable
    // read-only/nosuid/nodev view. These are not caller-configurable options.
    assert_eq!(FS_CLOEXEC, 1);
    assert_eq!(CREATE_EXCLUSIVE, 8);
    assert_eq!(VIEW_ATTRS, 7);
    assert_eq!(VIEW_ATTRS & libc::MOUNT_ATTR_NOEXEC as u32, 0);
    let backing = backing();
    let api = FakeMountApi::new(&backing);
    let root = create_detached_root(&backing, &api, &|| api.cancelled()).unwrap();
    assert_eq!(*api.calls.borrow(), STEPS);
    api.context.borrow().as_ref().unwrap().assert_closed();
    assert!(api.root.borrow().as_ref().unwrap().is_live());
    assert_eq!(root.as_raw_fd(), api.root.borrow().as_ref().unwrap().number);
    assert_ne!(
        fcntl(&root, FcntlArg::F_GETFD).unwrap() & libc::FD_CLOEXEC,
        0
    );
    drop(root);
    api.assert_owned_descriptors_closed();
    assert_backing_unchanged(&backing);
}

#[test]
fn every_syscall_failure_closes_all_acquired_descriptors_and_preserves_step_errno() {
    for (index, step) in STEPS.into_iter().enumerate() {
        let backing = backing();
        let mut api = FakeMountApi::new(&backing);
        api.fail = Some(step);
        assert_eq!(
            create_detached_root(&backing, &api, &|| api.cancelled()).err(),
            Some(ErofsMountError::KernelRejected {
                step,
                errno: libc::EPERM
            })
        );
        assert_eq!(*api.calls.borrow(), STEPS[..=index]);
        api.assert_owned_descriptors_closed();
        assert_backing_unchanged(&backing);
    }
}

#[test]
fn cancellation_before_or_after_each_syscall_never_publishes_a_partial_root() {
    for completed in 0..=STEPS.len() {
        let backing = backing();
        let mut api = FakeMountApi::new(&backing);
        if completed == 0 {
            api.cancelled.set(true);
        } else {
            api.cancel_after = Some(STEPS[completed - 1]);
        }
        assert_eq!(
            create_detached_root(&backing, &api, &|| api.cancelled()).err(),
            Some(ErofsMountError::Cancelled)
        );
        assert_eq!(*api.calls.borrow(), STEPS[..completed]);
        api.assert_owned_descriptors_closed();
        assert_eq!(api.root.borrow().is_some(), completed == STEPS.len());
        assert_backing_unchanged(&backing);
    }
}

#[test]
fn kernel_error_retains_os_errno_and_sanitizes_non_os_errors() {
    assert_eq!(
        kernel_error(MountStep::Source, io::Error::from_raw_os_error(libc::EBADF)),
        ErofsMountError::KernelRejected {
            step: MountStep::Source,
            errno: libc::EBADF
        }
    );
    assert_eq!(
        kernel_error(MountStep::Create, io::Error::other("untrusted diagnostic")),
        ErofsMountError::KernelRejected {
            step: MountStep::Create,
            errno: libc::EIO
        }
    );
}

fn limits() -> ErofsMountLimits {
    ErofsMountLimits {
        view: MountedViewLimits {
            inodes: 16,
            live_file_bytes: 65536,
            path_bytes: 512,
            path_components: 16,
            directory_entry_bytes: 65536,
        },
        backing_bytes: 1 << 20,
        ramfs_data_bytes: 1 << 20,
        wall_time: Duration::from_secs(1),
    }
}
#[test]
fn every_mount_bound_is_validated_before_any_kernel_operation() {
    assert_eq!(limits().validate(), Ok(()));
    for value in [0, isize::MAX as usize + 1] {
        for field in 0..7 {
            let mut limits = limits();
            match field {
                0 => limits.backing_bytes = value,
                1 => limits.view.inodes = value,
                2 => limits.view.live_file_bytes = value,
                3 => limits.view.path_bytes = value,
                4 => limits.view.path_components = value,
                5 => limits.view.directory_entry_bytes = value,
                6 => limits.ramfs_data_bytes = value,
                _ => unreachable!(),
            }
            assert_eq!(limits.validate(), Err(ErofsMountError::InvalidLimits));
        }
    }
    for wall_time in [Duration::ZERO, Duration::MAX] {
        let mut limits = limits();
        limits.wall_time = wall_time;
        assert_eq!(limits.validate(), Err(ErofsMountError::InvalidLimits));
    }
}

#[test]
fn successful_syscall_fd_is_adopted_once_and_failed_fd_keeps_its_errno() {
    let original = sentinel("raw-result");
    let stamp = DescriptorStamp::new(&original);
    let raw = original.into_raw_fd();
    let adopted = owned_fd(raw.into()).unwrap();
    assert_eq!(adopted.as_raw_fd(), raw);
    assert!(stamp.is_live());
    drop(adopted);
    stamp.assert_closed();
    // SAFETY: -1 cannot name an open descriptor; this sets this thread's errno.
    assert_eq!(unsafe { libc::close(-1) }, -1);
    assert_eq!(owned_fd(-1).unwrap_err().raw_os_error(), Some(libc::EBADF));
}

#[test]
fn mounted_owner_has_no_clone_descriptor_export_or_arbitrary_file_adoption_traits() {
    // Adding a listed trait makes the inferred marker ambiguous.
    trait ForbiddenCapabilityTrait<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> ForbiddenCapabilityTrait<()> for T {}
    struct HasClone;
    impl<T: Clone> ForbiddenCapabilityTrait<HasClone> for T {}
    struct ExportsFd;
    impl<T: AsFd> ForbiddenCapabilityTrait<ExportsFd> for T {}
    struct AdoptsFile;
    impl<T: From<File>> ForbiddenCapabilityTrait<AdoptsFile> for T {}
    struct TriesFile;
    impl<T: TryFrom<File>> ForbiddenCapabilityTrait<TriesFile> for T {}
    let _ = <VerifiedMountedView as ForbiddenCapabilityTrait<_>>::check;
}

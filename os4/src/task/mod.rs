mod context;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use crate::loader::{get_app_data, get_num_app};
use crate::mm::{MapPermission, VirtAddr};
use crate::sync::UPSafeCell;
use crate::syscall::TaskInfo;
use crate::timer::{get_time_us};
use crate::trap::TrapContext;
use crate::config::PAGE_SIZE;
use alloc::vec::Vec;
use lazy_static::*;
use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus};

pub use context::TaskContext;

pub struct TaskManager {
    num_app: usize,
    inner: UPSafeCell<TaskManagerInner>,
}

struct TaskManagerInner {
    tasks: Vec<TaskControlBlock>,
    current_task: usize,
}

lazy_static! {
    pub static ref TASK_MANAGER: TaskManager = {
        info!("init TASK_MANAGER");
        let num_app = get_num_app();
        info!("num_app = {}", num_app);
        let mut tasks: Vec<TaskControlBlock> = Vec::new();
        for i in 0..num_app {
            tasks.push(TaskControlBlock::new(get_app_data(i), i));
        }
        TaskManager {
            num_app,
            inner: unsafe {
                UPSafeCell::new(TaskManagerInner {
                    tasks,
                    current_task: 0,
                })
            },
        }
    };
}

impl TaskManager {
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        let next_task = &mut inner.tasks[0];
        next_task.task_status = TaskStatus::Running;
        let next_task_cx_ptr = &next_task.task_cx as *const TaskContext;
        drop(inner);
        let mut _unused = TaskContext::zero_init();
        // before this, we should drop local variables that must be dropped manually
        unsafe {
            __switch(&mut _unused as *mut _, next_task_cx_ptr);
        }
        panic!("unreachable in run_first_task!");
    }

    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Ready;
    }

    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Exited;
    }

    fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        (current + 1..current + self.num_app + 1)
            .map(|id| id % self.num_app)
            .find(|id| inner.tasks[*id].task_status == TaskStatus::Ready)
    }

    fn get_current_token(&self) -> usize {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_user_token()
    }

    #[allow(clippy::mut_from_ref)]
    fn get_current_trap_cx(&self) -> &mut TrapContext {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_trap_cx()
    }

    fn run_next_task(&self) {
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[next].task_status = TaskStatus::Running;
            inner.current_task = next;
            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;
            drop(inner);
            // before this, we should drop local variables that must be dropped manually
            unsafe {
                __switch(current_task_cx_ptr, next_task_cx_ptr);
            }
            // go back to user mode
        } else {
            panic!("All applications completed!");
        }
    }
    
    fn update_task_info(&self, syscall_id: usize) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].syscall_times[syscall_id] += 1;
    }

    fn get_task_info(&self) -> TaskInfo {
        let inner = self.inner.exclusive_access();
        let current = &inner.tasks[inner.current_task];
        // println!("Get {} {}", get_time_us() / 1000, current.start_time);
        TaskInfo {
            status: current.task_status,
            syscall_times: current.syscall_times,
            time: get_time_us() / 1000 - current.start_time,
        }
    }
}

pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}

pub fn current_user_token() -> usize {
    TASK_MANAGER.get_current_token()
}

pub fn current_trap_cx() -> &'static mut TrapContext {
    TASK_MANAGER.get_current_trap_cx()
}

pub fn update_task_info(syscall_id: usize) {
    TASK_MANAGER.update_task_info(syscall_id);
}

pub fn get_task_info() -> TaskInfo {
    TASK_MANAGER.get_task_info()
}

pub fn memory_alloc(start: usize, len: usize, port: usize) -> isize {
    // println!("0x{:X} {}", start, len);
    if len == 0 {
        return 0;
    }
    if (len > 1073741824) || ((port & (!0x7)) != 0) || ((port & 0x7) == 0) || ((start % 4096) != 0) {
        return -1;
    }
    let mut inner = TASK_MANAGER.inner.exclusive_access();
    let current = inner.current_task;
    let l: VirtAddr = start.into();
    let r: VirtAddr = (start + len).into();
    let lvpn = l.floor();
    let rvpn = r.ceil();
    // println!("L:{:?} R:{:?}", L, R);
    for area in &inner.tasks[current].memory_set.areas {
        // println!("{:?} {:?}", area.vpn_range.l, area.vpn_range.r);
        if (lvpn <= area.vpn_range.get_start()) && (rvpn > area.vpn_range.get_start()) {
            return -1;
        }
    }
    let mut permission = MapPermission::from_bits((port as u8) << 1).unwrap();
    permission.set(MapPermission::U, true);
    // inner.tasks[current].memory_set.insert_framed_area(start.into(), (start + len).into(), permission);
    let mut start = start;
    let end = start + len;
    while start < end {
        let mut endr = start + PAGE_SIZE;
        if endr > end {
            endr = end;
        }
        inner.tasks[current].memory_set.insert_framed_area(start.into(), endr.into(), permission);
        start = endr;
    }
    0
}

pub fn memory_free(start: usize, len: usize) -> isize {
    if len == 0 {
        return 0;
    }
    if start % 4096 != 0 {
        return -1;
    }
    let mut inner = TASK_MANAGER.inner.exclusive_access();
    let current = inner.current_task;
    let l: VirtAddr = start.into();
    let r: VirtAddr = (start + len).into();
    let lvpn = l.floor();
    let rvpn = r.ceil();
    let mut cnt = 0;
    for area in &inner.tasks[current].memory_set.areas {
        if (lvpn <= area.vpn_range.get_start()) && (rvpn > area.vpn_range.get_start()) {
            cnt += 1;
        }
    }
    if cnt < rvpn.0-lvpn.0 {
        return -1;
    }
    for i in 0..inner.tasks[current].memory_set.areas.len() {
        let memory_set = &mut inner.tasks[current].memory_set;
        if !memory_set.areas.get(i).is_some() {
            continue;
        }
        if (lvpn <= memory_set.areas[i].vpn_range.get_start()) && (rvpn > memory_set.areas[i].vpn_range.get_start()) {
            memory_set.areas[i].unmap(&mut memory_set.page_table);
            memory_set.areas.remove(i);
        }
    }
    0
}

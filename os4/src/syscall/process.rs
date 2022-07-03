use crate::config::MAX_SYSCALL_NUM;
use crate::task::{
    exit_current_and_run_next, suspend_current_and_run_next, get_task_info,
    current_user_token, memory_alloc, memory_free, TaskStatus,
};
use crate::mm::{VirtAddr, PhysAddr, PageTable};
use crate::timer::{get_time_us};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    info!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let _us = get_time_us();
    let t = _us / 1000;
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    let va = VirtAddr::from(ts as usize);
    let vpn = va.floor();
    let ppn = page_table.translate(vpn).unwrap().ppn();
    let buf = ppn.get_bytes_array();
    let sec = t / 1000;
    let usec = t % 1000 * 1000;
    let offset = va.page_offset();

    buf[offset+0] = (sec & 0xff) as u8;
    buf[offset+1] = ((sec >> 8) & 0xff) as u8;
    buf[offset+2] = ((sec >> 16) & 0xff) as u8;
    buf[offset+3] = ((sec >> 24) & 0xff) as u8;

    buf[offset+8] = (usec & 0xff) as u8;
    buf[offset+9] = ((usec >> 8) & 0xff) as u8;
    buf[offset+10] = ((usec >> 16) & 0xff) as u8;
    buf[offset+11] = ((usec >> 24) & 0xff) as u8;
    0
}

// CLUE: 从 ch4 开始不再对调度算法进行测试~
pub fn sys_set_priority(_prio: isize) -> isize {
    -1
}

// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    memory_alloc(start, len, port)
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    memory_free(start, len)
}

pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    let va = VirtAddr::from(ti as usize);
    let vpn = va.floor();
    let ppn = page_table.translate(vpn).unwrap().ppn();
    let offset = va.page_offset();
    let pa: PhysAddr = ppn.into();
    unsafe {
        let task_info = ((pa.0 + offset) as *mut TaskInfo).as_mut().unwrap();
        let tmp = get_task_info();
        *task_info = tmp;
    }
    0
}

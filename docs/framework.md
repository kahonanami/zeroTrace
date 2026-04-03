# zeroTrace
## zt_main
zt_main 主要用于实现程序的初始化

从命令行参数获取待 hook 子进程的 pid/name，通过 ./ztrace -p [PID] / -n [NAME]

用 ptrace 调试进程，mmap 映射地址，并进行地址的初始化

将 stub.S 和 zt_payload.c 编译成 so 文件，并注入子进程中，代码可以参考[linux-inject](https://github.com/gaffe23/linux-inject)

1. 将 so 文件注入子进程，获取相关符号的地址

2. mmap 函数 thunk 空间，获取 thunk 空间地址，对 zt_thunk_manager 进行初始化

3. mmap 一段共享内存，用于存储 trace 中获取的参数和返回值，启用一个线程，不断输出获取的参数和返回值

基于现有代码需要改进的地方

1. zt_stub_handlers.c 需要将参数信息和返回值写入共享内存

> 关于交互
>
> 目前对想法是创建一个文件交互系统，用户通过 echo "command" > ztrace_cmd 将指令写入文件，ztrace 中启用一个监听线程，监听文件变化，如果发生变化，解析指令

## zt_injector

假如 zt_main 要求 trace function1

获取程序基地址和目标函数偏移，计算出函数准确地址（ASLR/PIE 兼容）

如果是 trace 函数解析函数开头的指令，先挂起目标所有线程，判断是否会被五字节截断，获取最小的不会被截断的字节码，判断是不是基于 rip 的寻址，如果是，先不处理

用 new_thunk 申请一个 thunk，获取 thunk 地址

修改函数开头为 

```asm
mov rax, thunk
jmp rax
```

如果是 untrace 函数，恢复函数开头，free_thunk

## zt_thunk_manager

维持一个 thunk_pool 实现如下函数

1. new_thunk

一个标准化的 thunk 结构如下

```asm
thunk_func1:
    push <function id>
    mov rax, entry_stub_addr
    call rax
    lea rsp, [rsp + 8]
    <func1 的原始机器码>
    jmp (func1 + ins_len)
```

由于寻址范围问题，可以有如上写法

new_thunk 需要参数 function_offset origin_inst origin_inst_len，根据以上参数从 pool 中申请并初始化一个 thunk，返回 thunk 的地址

new_thunk 自己维护一个 function offset-id 表，对于重复输入的函数不处理并输出 log

2. free_thunk

free_thunk 需要参数 thunk_addr，用 Bitmap 位图分配器进行分配和释放

## zt_monitor

监听共享内存，输出到 log

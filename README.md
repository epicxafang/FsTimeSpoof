# FsTimeSpoof

基于 [KernelPatch](https://github.com/bmax121/KernelPatch) 的 KPM，用于伪造文件和文件夹的修改时间。

## 技术原理

FsTimeSpoof 通过 **syscall hook** 拦截内核中的文件状态查询系统调用：

1. **拦截 `newfstatat`** — 大多数 `stat` / `lstat` / `fstatat` 系列函数最终都会走此 syscall
2. **拦截 `statx`** — Linux 4.11+ 引入的扩展文件属性查询接口

**Hook 流程**：

```
用户空间调用 stat(path)
    ↓
内核 newfstatat / statx syscall 入口
    ↓
[before 回调] 从参数提取路径 → 查找伪造规则表
    ↓
原始 syscall 执行，获取真实 stat 结构体
    ↓
[after 回调] 将 stat 结果从用户空间拷贝到内核 → 替换 atime/mtime/ctime → 写回用户空间
    ↓
返回伪造后的结果给调用者
```

**时间戳替换**：命中规则的文件的 `st_atim`、`st_mtim`、`st_ctim`（以及 statx 对应字段）被统一覆盖为预设值，其他字段不变。对未匹配的路径零开销——before 回调查表无结果后直接跳过 after 处理。

## 使用方法

```bash
# 加载并添加规则
sc_kpm_load key ./FsTimeSpoof.kpm "/data/app/com.example 1700000000"

# 运行时动态添加规则
sc_kpm_control key "FsTimeSpoof" "/sdcard/Download/test.txt 1700000000"
# 返回: "added 1"

# 清除所有规则
sc_kpm_control key "FsTimeSpoof" "clear"

# 卸载
sc_kpm_unload key "FsTimeSpoof"
```

## 构建

```bash
make
```

产物: `FsTimeSpoof.kpm`

## 许可证

[AGPLv3](LICENSE)

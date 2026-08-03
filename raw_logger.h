/*
 * raw_logger.h — code/rw/bl 三文件写入器
 *
 * 移植自 gumTest 的 RawMemoryLogger 设计：
 *   - 每文件一个匿名 mmap 缓存（1MB），writeCached 只写内存
 *   - 缓存满或周期性 check_and_flush 时一次性 write() 落盘
 *   - 输出到设备端，崩溃时最多丢一个缓存块，不影响已落盘部分
 *
 * 三文件对应 docs/TraceFormat.md 的 code.log / rw.log / bl.log，
 * 通过 code.log 的十六进制行号互相索引。
 */

#ifndef RAW_LOGGER_H
#define RAW_LOGGER_H

#include <cstddef>
#include <cstdint>

class RawMemoryLogger
{
    public:
	RawMemoryLogger();
	~RawMemoryLogger();

	// 打开输出文件（O_CREAT | O_TRUNC），分配匿名 mmap 缓存
	// 返回 0 成功，负值失败
	int init(const char *path);

	// 追加数据到缓存；缓存放不下时自动落盘。线程安全由调用方保证。
	void writeCached(const char *buf, size_t len);

	// 强制把缓存写盘
	void flush();

	// 关闭文件、释放缓存
	void close();

	// 已写入文件的总字节数
	uint64_t offset() const
	{
		return offset_;
	}

    private:
	int fd_;
	char *cache_; // 匿名 mmap 缓存
	size_t cacheSize_;
	size_t used_;
	uint64_t offset_; // 文件累计写入字节数
	bool inited_;
};

// 三个全局 logger（trace_impl 初始化）
extern RawMemoryLogger *g_raw_logger;
extern RawMemoryLogger *g_rw_logger;
extern RawMemoryLogger *g_bl_logger;

// C 风格便捷封装（带内部互斥锁）
int raw_logger_init(RawMemoryLogger *logger, const char *path);
void raw_logger_write_cached(RawMemoryLogger *logger, const char *buf, size_t len);

// 按行号节流 flush：每隔 0x1000 行把三个文件一起落盘
void raw_logger_check_and_flush(uint64_t lineNum);

// 强制 flush 三个文件
void raw_logger_flush_all(void);

#endif // RAW_LOGGER_H

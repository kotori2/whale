#include <sys/mman.h>
#include <errno.h>
#include "platform/memory.h"
#include "dbi/arm64/inline_hook_arm64.h"
#include "dbi/arm64/registers_arm64.h"
#include "dbi/arm64/instruction_rewriter_arm64.h"
#include "assembler/vixl/aarch64/macro-assembler-aarch64.h"
#include "base/align.h"
#include "base/logging.h"

#define __ masm.
extern int errno;
namespace whale {
namespace arm64 {

using namespace vixl::aarch64;  // NOLINT


void Arm64InlineHook::StartHook() {
    DCHECK(address_ != 0 && replace_ != 0);
    MacroAssembler masm;

    __ Mov(xTarget, GetReplaceAddress<u8>());
    __ Br(xTarget);

    masm.FinalizeCode();

    size_t backup_size = masm.GetSizeOfCodeGenerated();

    //change memory attr
    auto page = GetTarget<u4 *>();
    __android_log_print(ANDROID_LOG_INFO, "Whale", "MProtect address %p, length %zu", page, backup_size);
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    
    //align
    auto offset = reinterpret_cast<size_t>(page) % page_size;
    if(offset) {
        page = reinterpret_cast<u4 *>(reinterpret_cast<size_t>(page) - offset);
    }
    
    __android_log_print(ANDROID_LOG_INFO, "Whale", "MProtect paged address %p, length %zu", page, page_size);

    errno = 0;
    int stat = mprotect(page, page_size, PROT_READ|PROT_WRITE|PROT_EXEC);
    __android_log_print(ANDROID_LOG_INFO, "Whale", "MProtect result: %d", stat);
    if(stat != 0){
        __android_log_print(ANDROID_LOG_ERROR, "Whale", "MProtect error: %s", strerror(errno));
    }

    backup_code_ = new BackupCode(GetTarget<u4 *>(), backup_size);

    if (backup_ != nullptr) {
        intptr_t tail = address_ + backup_size;
        intptr_t trampoline = BuildTrampoline(static_cast<u8>(tail));
        *backup_ = trampoline;
    }

    ScopedMemoryPatch patch(
            GetTarget<void *>(),
            masm.GetBuffer()->GetStartAddress<void *>(),
            backup_size
    );
}

intptr_t
Arm64InlineHook::BuildTrampoline(u8 tail) {
    MacroAssembler masm;

    Arm64InstructionRewriter rewriter(&masm, backup_code_, GetTarget<u8>(), tail);
    rewriter.Rewrite();

    __ Mov(xTarget, tail);
    __ Br(xTarget);

    masm.FinalizeCode();

    size_t size = masm.GetBuffer()->GetSizeInBytes();

    trampoline_addr_ = mmap(nullptr, GetPageSize(), PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    memcpy(trampoline_addr_, masm.GetBuffer()->GetStartAddress<void *>(), size);
    mprotect(trampoline_addr_, GetPageSize(), PROT_READ | PROT_EXEC);

    return reinterpret_cast<intptr_t>(trampoline_addr_);
}


void Arm64InlineHook::StopHook() {
    size_t code_size = backup_code_->GetSizeInBytes();
    void *insns = backup_code_->GetInstructions<void>();
    ScopedMemoryPatch patch(GetTarget<void *>(), insns, code_size);
    memcpy(GetTarget<void *>(), insns, code_size);
    if (trampoline_addr_ != nullptr) {
        munmap(trampoline_addr_, GetPageSize());
    }
}

}  // namespace arm64
}  // namespace whale

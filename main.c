#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

typedef struct String
{
    char* ptr;
    size_t len;
} String;

#define STR(lit) (String){.ptr = lit, .len = (sizeof(lit)-1) }

#define ARRAY_INITIAL_CAPACITY 16

#define ARRAY_OF(TYPE) \
    struct             \
    {                  \
        TYPE *ptr;     \
        size_t len;    \
        size_t cap;    \
    }

#define array_full(a) ((a)->ptr ? ((a)->len >= (a)->cap) : 1)

#define array_push(a)                                                          \
    (array_full(a)                                                             \
         ? (a)->ptr = array_grow((a)->ptr, &(a)->cap, 0, sizeof(*((a)->ptr)))  \
         : 0,                                                                  \
     &(a)->ptr[(a)->len++])

#define array_pop(a) ((a)->len > 0 ? ((a)->len--, &(a)->ptr[(a)->len]) : NULL)

static void *
array_grow(void *ptr, size_t *cap, size_t wanted_cap, size_t item_size)
{
    if (!ptr)
    {
        size_t desired_cap =
            ((wanted_cap == 0) ? ARRAY_INITIAL_CAPACITY : wanted_cap);
        *cap = desired_cap;
        return malloc(item_size * desired_cap);
    }

    size_t desired_cap = ((wanted_cap == 0) ? ((*cap) * 2) : wanted_cap);
    *cap = desired_cap;
    return realloc(ptr, (desired_cap * item_size));
}

typedef struct AGModule AGModule;

typedef struct {
    AGModule* mod;
    uint32_t index;
} AGFunctionRef;

typedef struct {
    AGModule* mod;
    uint32_t func_index;
    uint16_t index;
} AGBlockRef;

typedef struct {
    AGModule* mod;
    uint32_t func_index;
    uint16_t block_index;
    uint16_t index;
} AGInstrRef;

typedef enum AGLinkage
{
    AG_LINKAGE_GLOBAL,
    AG_LINKAGE_EXTERN,
    AG_LINKAGE_LOCAL,
} AGLinkage;

typedef enum AGValueKind
{
    AG_VALUE_STACK,
    AG_VALUE_GLOBAL,
} AGValueKind;

typedef struct AGValue
{
    AGValueKind kind;
    bool is_lvalue;
    struct
    {
        size_t size;
        size_t addr;
    };
} AGValue;

typedef enum AGInstrType
{
    AG_INSTR_ALLOCA,
    AG_INSTR_STORE,
    AG_INSTR_JUMP,
    AG_INSTR_CALL,
} AGInstrType;

typedef struct AGInstr
{
    AGInstrType type;
    union
    {
        struct
        {
            size_t size;
            size_t stack_offset;
        } alloca;
        struct
        {
            uint64_t value;
        } load;
        struct
        {
            AGValue addr;
            uint64_t value;
        } store;
        struct
        {
            AGBlockRef dest;
        } jump;
        struct
        {
            AGFunctionRef func;
            AGValue *params;
            size_t param_count;
            AGValue result;
        } call;
    };
} AGInstr;
typedef ARRAY_OF(AGInstr) ArrayOfInstr;

typedef struct AGBlock
{
    size_t id;
    ArrayOfInstr instrs;
} AGBlock;
typedef ARRAY_OF(AGBlock) ArrayOfBlock;

typedef struct AGFunction
{
    String name;
    AGLinkage linkage;
    ArrayOfBlock blocks;

    size_t stack_offset;
} AGFunction;
typedef ARRAY_OF(AGFunction) ArrayOfFunc;

typedef struct AGGlobal
{
    size_t id;
    size_t size;
} AGGlobal;
typedef ARRAY_OF(AGGlobal) ArrayOfGlobal;

typedef struct AGModule
{
    char* asm_buf;
    size_t asm_cap;
    size_t asm_len;

    size_t block_counter;
    size_t global_counter;

    ArrayOfGlobal globals;
    ArrayOfFunc funcs;
} AGModule;

static void module_init(AGModule* mod)
{
    memset(mod, 0, sizeof(*mod));
}

static void module_grow(AGModule* mod, size_t additional_space)
{
    if (mod->asm_len + additional_space > mod->asm_cap)
    {
        if (mod->asm_cap == 0) mod->asm_cap = 1 << 14;
        mod->asm_cap = mod->asm_cap * 2 + additional_space;
        mod->asm_buf = realloc(mod->asm_buf, mod->asm_cap);
    }
}

static void module_append(AGModule* mod, String str)
{
    module_grow(mod, str.len);
    char* curr = &mod->asm_buf[mod->asm_len];
    memcpy(curr, str.ptr, str.len);
    mod->asm_len += str.len;
}

static void module_append_uint(AGModule* mod, uint64_t num)
{
    if (num == 0)
    {
        module_grow(mod, 1);
        mod->asm_buf[mod->asm_len++] = '0';
        return;
    }

    char* start = &mod->asm_buf[mod->asm_len];
    uint64_t iters = 0;
    while (num > 0)
    {
        uint64_t rest = num % 10;
        num /= 10;
        
        module_grow(mod, 1);
        mod->asm_len++;
        start[iters++] = '0' + rest;
    }

    for (size_t i = 0; i < iters/2; ++i)
    {
        char temp = start[i];
        start[i] = start[iters-i-1];
        start[iters-i-1] = temp;
    }
}

static inline AGInstrRef create_instr(AGBlockRef block_ref, AGInstrType type)
{
    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];

    AGInstr* instr = array_push(&block->instrs);
    memset(instr, 0, sizeof(*instr));
    instr->type = type;

    return (AGInstrRef) {
        .mod = mod, 
        .func_index = block_ref.func_index,
        .block_index = block_ref.index,
        .index = block->instrs.len-1 
    };
}

static void build_jump(AGBlockRef block_ref, AGBlockRef dest)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_JUMP);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    instr->jump.dest = dest;
}

static AGValue build_alloca(AGBlockRef block_ref, size_t size)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_ALLOCA);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    func->stack_offset += size;

    instr->alloca.size = size;
    instr->alloca.stack_offset = func->stack_offset;

    return (AGValue){.kind = AG_VALUE_STACK, .size = size, .addr = instr->alloca.stack_offset};
}

static void build_store(AGBlockRef block_ref, AGValue addr, uint64_t value)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_STORE);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    instr->store.addr = addr;
    instr->store.value = value;
}

static AGValue build_call(AGBlockRef block_ref, AGFunctionRef func_ref, AGValue* params, size_t param_count)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_CALL);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    instr->call.func = func_ref;
    instr->call.param_count = param_count;
    instr->call.params = malloc(sizeof(*params) * param_count);
    memcpy(instr->call.params, params, sizeof(*params) * param_count);

    // TODO: alloca size might not be this
    instr->call.result = build_alloca(block_ref, 8);
    instr->call.result.is_lvalue = true;

    return instr->call.result;
}

static AGFunctionRef module_add_func(AGModule* mod, String name, AGLinkage linkage)
{
    AGFunction* func = array_push(&mod->funcs);
    memset(func, 0, sizeof(*func));
    func->name = name;
    func->linkage = linkage;

    return (AGFunctionRef){ .mod = mod, .index = mod->funcs.len-1 };
}

static AGValue module_add_global(AGModule* mod, size_t size)
{
    AGGlobal* global = array_push(&mod->globals);
    memset(global, 0, sizeof(*global));
    global->id = mod->global_counter++;
    global->size = size;

    return (AGValue){.kind = AG_VALUE_GLOBAL, .size = size, .addr = global->id };
}

static AGBlockRef function_add_block(AGFunctionRef func_ref)
{
    AGModule *mod = func_ref.mod;
    AGFunction* func = &mod->funcs.ptr[func_ref.index];

    AGBlock* block = array_push(&func->blocks);
    memset(block, 0, sizeof(*block));
    block->id = mod->block_counter++;

    return (AGBlockRef){ .mod = mod, .func_index = func_ref.index, .index = func->blocks.len-1 };
}

static void generate_instr(AGInstrRef instr_ref)
{
    AGModule *mod = instr_ref.mod;
    AGFunction* func = &mod->funcs.ptr[instr_ref.func_index];
    AGBlock* block = &func->blocks.ptr[instr_ref.block_index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    switch (instr->type)
    {
        case AG_INSTR_ALLOCA:
        {
            break;
        }

        case AG_INSTR_STORE:
        {
            AGValue dest = instr->store.addr;

            switch (dest.kind)
            {
                case AG_VALUE_STACK:
                {
                    if (dest.is_lvalue)
                    {
                        module_append(mod, STR("\tlea rax, [rbp-"));
                        module_append_uint(mod, dest.addr);
                        module_append(mod, STR("]\n"));
                    }

                    module_append(mod, STR("\tmov "));
                    switch (dest.size)
                    {
                        case 1: module_append(mod, STR("byte ")); break;
                        case 2: module_append(mod, STR("word ")); break;
                        case 4: module_append(mod, STR("dword ")); break;
                        case 8: module_append(mod, STR("qword ")); break;
                        default: assert(0 && "Invalid alloca size"); break;
                    }

                    if (dest.is_lvalue)
                    {
                        module_append(mod, STR("[rax], "));
                    }
                    else
                    {
                        module_append(mod, STR("[rbp-"));
                        module_append_uint(mod, dest.addr);
                        module_append(mod, STR("], "));
                    }
                    module_append_uint(mod, instr->store.value);
                    module_append(mod, STR("\n"));
                    break;
                }

                case AG_VALUE_GLOBAL:
                {
                    module_append(mod, STR("\tmov "));
                    switch (dest.size)
                    {
                        case 1: module_append(mod, STR("byte ")); break;
                        case 2: module_append(mod, STR("word ")); break;
                        case 4: module_append(mod, STR("dword ")); break;
                        case 8: module_append(mod, STR("qword ")); break;
                        default: assert(0 && "Invalid alloca size"); break;
                    }

                    module_append(mod, STR("[global@"));
                    module_append_uint(mod, dest.addr);
                    module_append(mod, STR("], "));
                    module_append_uint(mod, instr->store.value);
                    module_append(mod, STR("\n"));
                    break;
                }
            }

            break;
        }

        case AG_INSTR_JUMP:
        {
            AGBlockRef dest_ref = instr->jump.dest;
            assert(dest_ref.mod == mod);
            assert(dest_ref.func_index == instr_ref.func_index);

            AGBlock* dest = &func->blocks.ptr[dest_ref.index];

            module_append(mod, STR("\tjmp "));
            module_append(mod, func->name);
            module_append(mod, STR("@"));
            module_append_uint(mod, dest->id);
            module_append(mod, STR("\n"));
            break;
        }

        case AG_INSTR_CALL:
        {
            AGFunctionRef func_ref = instr->call.func;
            assert(func_ref.mod == mod);

            AGFunction* called_func = &mod->funcs.ptr[func_ref.index];

            for (size_t i = 0; i < instr->call.param_count; ++i)
            {
                AGValue param = instr->call.params[i];

                switch (param.kind)
                {
                    case AG_VALUE_STACK:
                    {
                        if (param.is_lvalue)
                        {
                            module_append(mod, STR("\tmov rax, [rbp-"));
                            module_append_uint(mod, param.addr);
                            module_append(mod, STR("]\n"));
                        }

                        module_append(mod, STR("\tmov "));
                        switch (i)
                        {
                            case 0: module_append(mod, STR(" rdi, ")); break;
                            case 1: module_append(mod, STR(" rsi, ")); break;
                            case 2: module_append(mod, STR(" rdx, ")); break;
                            case 3: module_append(mod, STR(" rcx, ")); break;
                            case 4: module_append(mod, STR(" r8, ")); break;
                            case 5: module_append(mod, STR(" r9, ")); break;
                        }

                        if (param.is_lvalue)
                        {
                            module_append(mod, STR("rax\n"));
                        }
                        else
                        {
                            module_append(mod, STR("[rbp-"));
                            module_append_uint(mod, param.addr);
                            module_append(mod, STR("]\n"));
                        }
                        
                        break;
                    }

                    default: assert(0); break;
                }
            }

            module_append(mod, STR("\tcall "));
            module_append(mod, called_func->name);
            module_append(mod, STR("\n"));

            AGValue result = instr->call.result;
            assert(result.kind == AG_VALUE_STACK);

            module_append(mod, STR("\tmov "));
            switch (result.size)
            {
                case 1: module_append(mod, STR("byte ")); break;
                case 2: module_append(mod, STR("word ")); break;
                case 4: module_append(mod, STR("dword ")); break;
                case 8: module_append(mod, STR("qword ")); break;
                default: assert(0 && "Invalid alloca size"); break;
            }

            module_append(mod, STR("[rbp-"));
            module_append_uint(mod, result.addr);
            module_append(mod, STR("], rax\n"));

            break;
        }
    }
}

static void generate_block(AGBlockRef block_ref)
{
    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];

    module_append(mod, func->name);
    module_append(mod, STR("@"));
    module_append_uint(mod, block->id);
    module_append(mod, STR(":\n"));

    for (size_t i = 0; i < block->instrs.len; ++i)
    {
        generate_instr((AGInstrRef){
            .mod = mod,
            .func_index = block_ref.func_index,
            .block_index = block_ref.index,
            .index = i
        });
    }
}

static void generate_function(AGFunctionRef func_ref)
{
    AGModule* mod = func_ref.mod;
    AGFunction* func = &mod->funcs.ptr[func_ref.index];

    module_append(mod, func->name);
    module_append(mod, STR(":\n"));
    module_append(mod, STR("\tpush rbp\n"));
    module_append(mod, STR("\tmov rbp, rsp\n"));

    for (size_t i = 0; i < func->blocks.len; ++i)
    {
        generate_block((AGBlockRef){.mod = mod, .func_index = func_ref.index, .index = i});
    }

    module_append(mod, STR("\tpop rbp\n"));
    module_append(mod, STR("\tret\n"));
}

static void generate_module(AGModule* mod)
{
    for (size_t i = 0; i < mod->funcs.len; ++i)
    {
        AGFunction* func = &mod->funcs.ptr[i];

        switch (func->linkage)
        {
            case AG_LINKAGE_GLOBAL:
            {
                module_append(mod, STR("global "));
                module_append(mod, func->name);
                module_append(mod, STR("\n"));
                break;
            }

            case AG_LINKAGE_EXTERN:
            {
                module_append(mod, STR("extern "));
                module_append(mod, func->name);
                module_append(mod, STR("\n"));
                break;
            }

            case AG_LINKAGE_LOCAL: break;
        }
    }

    module_append(mod, STR("\n"));
    module_append(mod, STR("section .text\n\n"));

    for (size_t i = 0; i < mod->globals.len; ++i)
    {
        AGGlobal* global = &mod->globals.ptr[i];

        module_append(mod, STR("global@"));
        module_append_uint(mod, global->id);
        module_append(mod, STR(":\n"));
        module_append(mod, STR("\tdb "));
        for (size_t j = 0; j < global->size; ++j)
        {
            if (j != 0) module_append(mod, STR(", "));
            module_append(mod, STR("0"));
        }
        module_append(mod, STR("\n"));
    }

    module_append(mod, STR("\n"));

    for (size_t i = 0; i < mod->funcs.len; ++i)
    {
        AGFunction* func = &mod->funcs.ptr[i];
        
        switch (func->linkage)
        {
            case AG_LINKAGE_GLOBAL:
            case AG_LINKAGE_LOCAL:
            {
                generate_function((AGFunctionRef){.mod = mod, .index = i});
                break;
            }

            case AG_LINKAGE_EXTERN: break;
        }
    }
}

int main(int argc, char** argv)
{
    AGModule mod;
    module_init(&mod);

    module_add_func(&mod, STR("puts"), AG_LINKAGE_EXTERN);
    AGFunctionRef malloc_func = module_add_func(&mod, STR("malloc"), AG_LINKAGE_EXTERN);
    AGFunctionRef free_func = module_add_func(&mod, STR("free"), AG_LINKAGE_EXTERN);

    AGFunctionRef func = module_add_func(&mod, STR("main"), AG_LINKAGE_GLOBAL);
    AGBlockRef block = function_add_block(func);

    AGValue alloca = build_alloca(block, 8);
    build_store(block, alloca, 8);

    AGValue pointer = build_call(block, malloc_func, &alloca, 1);
    build_store(block, alloca, 32);

    build_call(block, free_func, &pointer, 1);

    generate_module(&mod);

    printf("%.*s", (int)mod.asm_len, mod.asm_buf);

    return 0;
}

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
    AG_VALUE_INVALID,
    AG_VALUE_CONST,
    AG_VALUE_TEMP,
    AG_VALUE_STACK,
    AG_VALUE_GLOBAL,
} AGValueKind;

typedef struct AGValue
{
    AGValueKind kind;
    union
    {
        struct
        {
            size_t size;
            size_t addr;
        };
        struct
        {
            uint64_t constant;
        };
    };
} AGValue;

typedef enum AGInstrType
{
    AG_INSTR_ALLOCA,
    AG_INSTR_STORE,
    AG_INSTR_LOAD,
    AG_INSTR_JUMP,
    AG_INSTR_CALL,
    AG_INSTR_SYSCALL,
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
            AGValue ptr;
            AGValue value;
        } store;
        struct
        {
            AGValue ptr;
            AGValue result;
        } load;
        struct
        {
            AGBlockRef dest;
        } jump;
        struct
        {
            union
            {
                uint64_t id;
                AGFunctionRef func;
            };
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
    uint8_t* initializer;
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

AGValue create_const(uint64_t value)
{
    return (AGValue) {
        .kind = AG_VALUE_CONST,
        .constant = value,
    };
}

AGValue create_temp(AGFunction *func, size_t size)
{
    func->stack_offset += size;
    return (AGValue){.kind = AG_VALUE_TEMP, .size = size, .addr = func->stack_offset};
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

void build_jump(AGBlockRef block_ref, AGBlockRef dest)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_JUMP);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    instr->jump.dest = dest;
}

AGValue build_alloca(AGBlockRef block_ref, size_t size)
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

void build_store(AGBlockRef block_ref, AGValue ptr, AGValue value)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_STORE);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    assert(ptr.kind != AG_VALUE_CONST);

    instr->store.ptr = ptr;
    instr->store.value = value;
}

AGValue build_call(AGBlockRef block_ref, AGFunctionRef func_ref, AGValue* params, size_t param_count)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_CALL);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    // TODO: alloca size might not be this
    AGValue result = create_temp(func, 8);

    instr->call.func = func_ref;
    instr->call.param_count = param_count;
    instr->call.params = malloc(sizeof(*params) * param_count);
    memcpy(instr->call.params, params, sizeof(*params) * param_count);

    instr->call.result = result;

    return instr->call.result;
}

AGValue build_load(AGBlockRef block_ref, AGValue ptr)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_LOAD);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    // TODO: alloca size might not be this
    AGValue result;
    if (ptr.kind == AG_VALUE_STACK)
    {
        result = ptr;
        result.kind = AG_VALUE_TEMP;
    }
    else
    {
        result = create_temp(func, 8);
    }

    instr->load.ptr = ptr;

    instr->load.result = result;

    return instr->load.result;
}

AGValue build_syscall(AGBlockRef block_ref, uint64_t id, AGValue* params, size_t param_count)
{
    AGInstrRef instr_ref = create_instr(block_ref, AG_INSTR_SYSCALL);

    AGModule* mod = block_ref.mod;
    AGFunction* func = &mod->funcs.ptr[block_ref.func_index];
    AGBlock* block = &func->blocks.ptr[block_ref.index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    // TODO: alloca size might not be this
    AGValue result = create_temp(func, 8);

    instr->call.id = id;
    instr->call.param_count = param_count;
    instr->call.params = malloc(sizeof(*params) * param_count);
    memcpy(instr->call.params, params, sizeof(*params) * param_count);

    instr->call.result = result;

    return instr->call.result;
}

AGFunctionRef module_add_func(AGModule* mod, String name, AGLinkage linkage)
{
    AGFunction* func = array_push(&mod->funcs);
    memset(func, 0, sizeof(*func));
    func->name = name;
    func->linkage = linkage;

    return (AGFunctionRef){ .mod = mod, .index = mod->funcs.len-1 };
}

AGValue module_add_global(AGModule* mod, size_t size, uint8_t* initializer)
{
    AGGlobal* global = array_push(&mod->globals);
    memset(global, 0, sizeof(*global));
    global->id = mod->global_counter++;
    global->size = size;
    if (initializer)
    {
        global->initializer = malloc(size);
        memcpy(global->initializer, initializer, size);
    }

    return (AGValue){.kind = AG_VALUE_GLOBAL, .size = size, .addr = global->id };
}

AGBlockRef function_add_block(AGFunctionRef func_ref)
{
    AGModule *mod = func_ref.mod;
    AGFunction* func = &mod->funcs.ptr[func_ref.index];

    AGBlock* block = array_push(&func->blocks);
    memset(block, 0, sizeof(*block));
    block->id = mod->block_counter++;

    return (AGBlockRef){ .mod = mod, .func_index = func_ref.index, .index = func->blocks.len-1 };
}

static void asm_value(AGModule* mod, AGValue *value)
{
    switch (value->kind)
    {
        case AG_VALUE_INVALID: assert(0); break;

        case AG_VALUE_CONST:
        {
            module_append_uint(mod, value->constant);
            break;
        }

        case AG_VALUE_STACK:
        {
            module_append(mod, STR("rbp-"));
            module_append_uint(mod, value->addr);
            break;
        }

        case AG_VALUE_TEMP:
        {
            module_append(mod, STR("[rbp-"));
            module_append_uint(mod, value->addr);
            module_append(mod, STR("]"));
            break;
        }

        case AG_VALUE_GLOBAL:
        {
            module_append(mod, STR("__@"));
            module_append_uint(mod, value->addr);
            break;
        }
    }
}

static void generate_instr(AGInstrRef instr_ref)
{
    AGModule *mod = instr_ref.mod;
    AGFunction* func = &mod->funcs.ptr[instr_ref.func_index];
    AGBlock* block = &func->blocks.ptr[instr_ref.block_index];
    AGInstr* instr = &block->instrs.ptr[instr_ref.index];

    switch (instr->type)
    {
        case AG_INSTR_ALLOCA: break;

        case AG_INSTR_STORE:
        {
            AGValue dest = instr->store.ptr;

            module_append(mod, STR("\t; begin store\n"));

            switch (dest.kind)
            {
                case AG_VALUE_STACK:
                {
                    module_append(mod, STR("\tmov "));
                    switch (dest.size)
                    {
                        case 1: module_append(mod, STR("byte ")); break;
                        case 2: module_append(mod, STR("word ")); break;
                        case 4: module_append(mod, STR("dword ")); break;
                        case 8: module_append(mod, STR("qword ")); break;
                        default: assert(0 && "Invalid stack var size"); break;
                    }

                    module_append(mod, STR("[rbp-"));
                    module_append_uint(mod, dest.addr);
                    module_append(mod, STR("], "));

                    break;
                }

                case AG_VALUE_TEMP:
                {
                    module_append(mod, STR("\tmov rax, [rbp-"));
                    module_append_uint(mod, dest.addr);
                    module_append(mod, STR("]\n"));

                    module_append(mod, STR("\tmov "));
                    switch (dest.size)
                    {
                        case 1: module_append(mod, STR("byte ")); break;
                        case 2: module_append(mod, STR("word ")); break;
                        case 4: module_append(mod, STR("dword ")); break;
                        case 8: module_append(mod, STR("qword ")); break;
                        default: assert(0 && "Invalid stack var size"); break;
                    }

                    module_append(mod, STR("[rax], "));
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
                        default: assert(0 && "Invalid stack var size"); break;
                    }

                    module_append(mod, STR("[__@"));
                    module_append_uint(mod, dest.addr);
                    module_append(mod, STR("], "));
                    break;
                }

                case AG_VALUE_INVALID:
                case AG_VALUE_CONST:
                {
                    assert(0 && "Invalid value to store to");
                    break;
                }
            }

            asm_value(mod, &instr->store.value);
            module_append(mod, STR("\n"));

            module_append(mod, STR("\t; end store\n"));

            break;
        }

        case AG_INSTR_LOAD:
        {
            AGValue ptr = instr->load.ptr;
            AGValue result = instr->load.result;

            if (ptr.kind == AG_VALUE_STACK)
            {
                break;
            }

            module_append(mod, STR("\t; begin load\n"));

            module_append(mod, STR("\tmov rax, [rbp-"));
            module_append_uint(mod, ptr.addr);
            module_append(mod, STR("]\n"));

            module_append(mod, STR("\tmov rax, [rax]\n"));

            module_append(mod, STR("\tmov [rbp-"));
            module_append_uint(mod, result.addr);
            module_append(mod, STR("], rax\n"));

            module_append(mod, STR("\t; end load\n"));
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

                String reg;
                switch (i)
                {
                    case 0: reg = STR("rdi"); break;
                    case 1: reg = STR("rsi"); break;
                    case 2: reg = STR("rdx"); break;
                    case 3: reg = STR("rcx"); break;
                    case 4: reg = STR("r8"); break;
                    case 5: reg = STR("r9"); break;
                    default: assert(0 && "Invalid parameter count"); break;
                }

                module_append(mod, STR("\tmov "));
                module_append(mod, reg);
                module_append(mod, STR(", "));
                asm_value(mod, &param);
                module_append(mod, STR("\n"));
            }

            module_append(mod, STR("\tcall "));
            module_append(mod, called_func->name);
            module_append(mod, STR("\n"));

            AGValue result = instr->call.result;

            module_append(mod, STR("\tmov "));
            switch (result.size)
            {
                case 1: module_append(mod, STR("byte ")); break;
                case 2: module_append(mod, STR("word ")); break;
                case 4: module_append(mod, STR("dword ")); break;
                case 8: module_append(mod, STR("qword ")); break;
                default: assert(0 && "Invalid stack var size"); break;
            }

            module_append(mod, STR("[rbp-"));
            module_append_uint(mod, result.addr);
            module_append(mod, STR("], rax\n"));

            break;
        }

        case AG_INSTR_SYSCALL:
        {
            uint64_t syscall_id = instr->call.id;

            for (size_t i = 0; i < instr->call.param_count; ++i)
            {
                AGValue param = instr->call.params[i];

                String reg;
                switch (i)
                {
                    case 0: reg = STR("rdi"); break;
                    case 1: reg = STR("rsi"); break;
                    case 2: reg = STR("rdx"); break;
                    case 3: reg = STR("rcx"); break;
                    case 4: reg = STR("r8"); break;
                    case 5: reg = STR("r9"); break;
                    default: assert(0 && "Invalid parameter count"); break;
                }

                module_append(mod, STR("\tmov "));
                module_append(mod, reg);
                module_append(mod, STR(", "));
                asm_value(mod, &param);
                module_append(mod, STR("\n"));
            }

            module_append(mod, STR("\tmov rax, "));
            module_append_uint(mod, syscall_id);
            module_append(mod, STR("\n"));
            module_append(mod, STR("\tsyscall\n"));

            AGValue result = instr->call.result;

            module_append(mod, STR("\tmov "));
            switch (result.size)
            {
                case 1: module_append(mod, STR("byte ")); break;
                case 2: module_append(mod, STR("word ")); break;
                case 4: module_append(mod, STR("dword ")); break;
                case 8: module_append(mod, STR("qword ")); break;
                default: assert(0 && "Invalid stack var size"); break;
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

    size_t reserved_stack_space = func->stack_offset;

    // Align stack size to 16 bytes
    size_t rest = reserved_stack_space % 16;
    if (rest > 0) reserved_stack_space += (16 - rest);

    if (reserved_stack_space > 0 )
    {
        module_append(mod, STR("\tsub rsp, "));
        module_append_uint(mod, reserved_stack_space);
        module_append(mod, STR("\n"));
    }

    for (size_t i = 0; i < func->blocks.len; ++i)
    {
        generate_block((AGBlockRef){.mod = mod, .func_index = func_ref.index, .index = i});
    }

    module_append(mod, STR("\tnop\n"));
    module_append(mod, STR("\tleave\n"));
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

        module_append(mod, STR("__@"));
        module_append_uint(mod, global->id);
        module_append(mod, STR(":\n"));
        if (global->initializer)
        {
            module_append(mod, STR("\tdb "));
            for (size_t j = 0; j < global->size; ++j)
            {
                if (j != 0) module_append(mod, STR(", "));
                module_append_uint(mod, (uint64_t)global->initializer[j]);
            }
        }
        else
        {
            module_append(mod, STR("\tresb "));
            module_append_uint(mod, global->size);
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

static void build_print(AGBlockRef block, char* string)
{
    AGModule* mod = block.mod;

    AGValue string_value = module_add_global(mod, strlen(string) + 1, (uint8_t*)string);

    AGValue stream = create_const(1); // stdout
    AGValue size = create_const(strlen(string) + 1);
    AGValue params[3] = {stream, string_value, size};
    build_syscall(block, 1, params, 3);
}

int main(int argc, char** argv)
{
    AGModule mod;
    module_init(&mod);

    AGFunctionRef malloc_func = module_add_func(&mod, STR("malloc"), AG_LINKAGE_EXTERN);
    AGFunctionRef free_func = module_add_func(&mod, STR("free"), AG_LINKAGE_EXTERN);
    AGFunctionRef print_num_func = module_add_func(&mod, STR("print_num"), AG_LINKAGE_EXTERN);

    AGFunctionRef func = module_add_func(&mod, STR("main"), AG_LINKAGE_GLOBAL);
    AGBlockRef block = function_add_block(func);

    build_print(block, "Hello, world!\n");

    AGValue malloc_size = create_const(8);
    AGValue pointer = build_call(block, malloc_func, &malloc_size, 1);
    build_store(block, pointer, create_const(32));

    AGValue loaded;

    AGValue alloca = build_alloca(block, 8);
    build_store(block, alloca, create_const(48));
    loaded = build_load(block, alloca);
    build_print(block, "Stack var: ");
    build_call(block, print_num_func, &loaded, 1);

    build_print(block, "Loaded malloc ptr: ");
    loaded = build_load(block, pointer);
    build_call(block, print_num_func, &loaded, 1);

    build_print(block, "malloc ptr: ");
    build_call(block, print_num_func, &pointer, 1);

    build_call(block, free_func, &pointer, 1);

    {
        // exit syscall
        AGValue exit_code = create_const(1);

        AGValue params[1] = {exit_code};
        build_syscall(block, 60, params, 1);
    }

    generate_module(&mod);

    printf("%.*s", (int)mod.asm_len, mod.asm_buf);

    return 0;
}

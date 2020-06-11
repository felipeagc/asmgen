global main
extern puts

section .text

main:
	push rbp
	mov rbp, rsp

	mov word [rbp-1], 1

	mov byte [global@0], 1

	mov r8, 3
	cmp r8, 3
	je _true
_false:
	jmp _merge
_true:
	mov rdi, message
	call puts
	jmp _merge
_merge:
	pop rbp
	ret

message:
	db "Hello, world", 0

global@0:
	db 0, 0, 0

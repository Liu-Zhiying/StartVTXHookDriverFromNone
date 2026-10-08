.code

SetRegsAndVmCallCore Proc
push rcx
push rdx
push r8
push r9
mov rax, [rcx]
mov rbx, [rdx]
mov rcx, [r8]
mov rdx, [r9]

vmcall

push rax
push rbx
push rcx
push rdx

mov rax, [rsp + 20h]
pop [rax]
mov rax, [rsp + 20h]
pop [rax]
mov rax, [rsp + 20h]
pop [rax]
mov rax, [rsp + 20h]
pop [rax]

pop r9
pop r8
pop rdx
pop rcx

ret

SetRegsAndVmCallCore Endp

End
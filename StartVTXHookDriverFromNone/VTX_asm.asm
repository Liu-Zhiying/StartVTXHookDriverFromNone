extern VmExitHandler : Proc
extern FillMachineFrame: Proc

.code

BACKUP_REGISTERS Macro baseAddrReg
	movaps xmmword ptr [baseAddrReg + 000h], xmm0
	movaps xmmword ptr [baseAddrReg + 010h], xmm1
	movaps xmmword ptr [baseAddrReg + 020h], xmm2
	movaps xmmword ptr [baseAddrReg + 030h], xmm3
	movaps xmmword ptr [baseAddrReg + 040h], xmm4
	movaps xmmword ptr [baseAddrReg + 050h], xmm5
	movaps xmmword ptr [baseAddrReg + 060h], xmm6
	movaps xmmword ptr [baseAddrReg + 070h], xmm7
	movaps xmmword ptr [baseAddrReg + 080h], xmm8
	movaps xmmword ptr [baseAddrReg + 090h], xmm9
	movaps xmmword ptr [baseAddrReg + 0A0h], xmm10
	movaps xmmword ptr [baseAddrReg + 0B0h], xmm11
	movaps xmmword ptr [baseAddrReg + 0C0h], xmm12
	movaps xmmword ptr [baseAddrReg + 0D0h], xmm13
	movaps xmmword ptr [baseAddrReg + 0E0h], xmm14
	movaps xmmword ptr [baseAddrReg + 0F0h], xmm15
	mov [baseAddrReg + 100h], r15
	mov [baseAddrReg + 108h], r14
	mov [baseAddrReg + 110h], r13
	mov [baseAddrReg + 118h], r12
	mov [baseAddrReg + 120h], r11
	mov [baseAddrReg + 128h], r10
	mov [baseAddrReg + 130h], r9
	mov [baseAddrReg + 138h], r8
	mov [baseAddrReg + 140h], rbp
	mov [baseAddrReg + 148h], rsi
	mov [baseAddrReg + 150h], rdi
	mov [baseAddrReg + 158h], rdx
	mov [baseAddrReg + 160h], rcx
	mov [baseAddrReg + 168h], rbx
Endm

RESTORE_REGISTERS Macro baseAddrReg
	movaps xmm0, xmmword ptr [baseAddrReg + 000h]
	movaps xmm1, xmmword ptr [baseAddrReg + 010h]
	movaps xmm2, xmmword ptr [baseAddrReg + 020h]
	movaps xmm3, xmmword ptr [baseAddrReg + 030h]
	movaps xmm4, xmmword ptr [baseAddrReg + 040h]
	movaps xmm5, xmmword ptr [baseAddrReg + 050h]
	movaps xmm6, xmmword ptr [baseAddrReg + 060h]
	movaps xmm7, xmmword ptr [baseAddrReg + 070h]
	movaps xmm8, xmmword ptr [baseAddrReg + 080h]
	movaps xmm9, xmmword ptr [baseAddrReg + 090h]
	movaps xmm10, xmmword ptr [baseAddrReg + 0A0h]
	movaps xmm11, xmmword ptr [baseAddrReg + 0B0h] 
	movaps xmm12, xmmword ptr [baseAddrReg + 0C0h] 
	movaps xmm13, xmmword ptr [baseAddrReg + 0D0h]
	movaps xmm14, xmmword ptr [baseAddrReg + 0E0h]
	movaps xmm15, xmmword ptr [baseAddrReg + 0F0h]
	mov r15, [baseAddrReg + 100h]
	mov r14, [baseAddrReg + 108h]
	mov r13, [baseAddrReg + 110h]
	mov r12, [baseAddrReg + 118h]
	mov r11, [baseAddrReg + 120h]
	mov r10, [baseAddrReg + 128h]
	mov r9, [baseAddrReg + 130h] 
	mov r8, [baseAddrReg + 138h]
	mov rbp, [baseAddrReg + 140h]
	mov rsi, [baseAddrReg + 148h] 
	mov rdi, [baseAddrReg + 150h]
	mov rdx, [baseAddrReg + 158h]
	mov rcx, [baseAddrReg + 160h]
	mov rbx, [baseAddrReg + 168h]
Endm

ALLOC_STACK_AND_CALL Macro functionName, stackSize

sub rsp, stackSize
call functionName
add rsp, stackSize

Endm

_mysgdt Proc
	;ִ�д洢�Ĵ�������ֻ��Ҫ10���ֽڣ����﷽��һ��
	sub rsp, 10h
	sgdt [rsp]
	;ȡlimit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;ȡbase
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;��ԭջ
	add rsp, 10h
	ret
_mysgdt Endp

_mysidt Proc
;ִ�д洢�Ĵ�������ֻ��Ҫ10���ֽڣ����﷽��һ��
	sub rsp, 10h
	sidt [rsp]
	;ȡlimit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;ȡbase
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;��ԭջ
	add rsp, 10h
	ret
_mysidt Endp
	
_mysldt Proc
	sldt ax
	mov word ptr [rcx], ax
	ret
_mysldt Endp

_mystr Proc
	str ax
	mov word ptr [rcx], ax
	ret
_mystr Endp

_cs_selector Proc
	mov ax,cs
	ret
_cs_selector Endp

_ds_selector Proc
	mov ax,ds
	ret
_ds_selector Endp

_es_selector Proc
	mov ax,es
	ret
_es_selector Endp

_fs_selector Proc
	mov ax,fs
	ret
_fs_selector Endp

_gs_selector Proc
	mov ax,gs
	ret
_gs_selector Endp

_ss_selector Proc
	mov ax,ss
	ret
_ss_selector Endp

_save_or_load_regs Proc	
	BACKUP_REGISTERS rcx
	
	;ȡ��ǰRflags
	pushfq
	mov rax, [rsp]
	mov [rcx + 178h], rax
	popfq

	;��ripָ���ж��Ƿ�load�Ĵ�����λ��
	mov rax, offset if_load_regs
	mov [rcx + 180h], rax
	
	;ȡ��������֮��ĵ�һ����ַ
	;����ǽ������⻯֮��ִ�е�if_load_regsʱ���������Ϊload�Ĵ���֮���ִ�е�ַ
	mov rax, [rsp]
	mov [rcx + 190h], rax

	;ȡ��������֮���rsp����8����callѹ��ķ��ص�ַ
	;����ǽ������⻯֮��ִ�е�if_load_regsʱ���������Ϊ���ԭ��rsp
	mov rax, rsp
	add rax, 8h
	mov [rcx + 188h], rax

	push 0
if_load_regs:
	pop rax
	test rax, rax
	jz return

	RESTORE_REGISTERS rax

	;rax ����ԭ
	;mov rax, [rcx + 170h]

	;��ԭrflags
	push qword ptr [rcx + 178h]
	popfq
	;��ԭrsp
	mov rsp, [rax + 188h]
	;��ԭrax
	mov rax, [rax + 170h]
	jmp qword ptr [rcx + 190h]

return:
	;��ԭrax
	mov rax, [rcx + 170h]
	ret
_save_or_load_regs Endp

VmEntry Proc Frame
.pushframe
.allocstack 18h
.endprolog
mov [rsp + 10h], rax
mov rax, [rsp]
BACKUP_REGISTERS rax
mov rax, [rsp + 10h]
mov rcx, [rsp]
mov [rcx + 170h], rax

mov rax, rsp
add rax, 18h
mov rcx, rax
mov rdx, [rsp]
mov r8, [rsp + 8h]

ALLOC_STACK_AND_CALL FillMachineFrame, 28h

mov rcx, [rsp + 8h]
mov rdx, [rsp]

ALLOC_STACK_AND_CALL VmExitHandler, 28h

mov rax, [rsp]
RESTORE_REGISTERS rax

;�ж��Ƿ��Ѿ��˳����⻯����Ҫ��ת��guest����һ��ָ��
mov rax, [rsp]
mov rax, [rax + 190h]
test rax, rax
mov rax, [rsp]
;�����ʱ��ת���˳�vmm�ķ�֧rax��ֵ����&pVMMVirtCpuInfo->regsBackup.genericRegisters1
jnz exit_virtualization

push [rax + 170h]
pop rax
vmresume

exit_virtualization:
;�л����ͻ���ջ
mov rsp, [rax + 188h]
;push �ͻ���nRip
push [rax + 198h]
;push �ͻ���rax
push [rax + 170h]
;push �ͻ���rflags
push [rax + 178h]
;��ԭrflags
popfq
;��ԭrax
pop rax
;���ؿͻ���nRipִ��
ret

VmEntry Endp

_invvpid Proc
    invvpid rcx, OWORD PTR [rdx]
    ret
_invvpid Endp

_invept Proc
    invept rcx, OWORD PTR [rdx]
    ret
_invept Endp

End
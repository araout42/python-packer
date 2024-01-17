
_start:
    ; Écriture du message "Hello, World!"
    mov rax, 0xAA          ; GET THE KEY
    mov rcx, 0xEEEEEEEE           ; GET THE LEN
    call .next_i
    .next_i:
    pop rsi
    mov r9, 0xCCCCCCCCCCCCCCCC
    add rsi, r9   ;ADRRESS OF TEXT SECTION
    .loop:
    mov r8b, byte[rsi]        ; GET THE CHAR
    xor r8b, al           ; XOR THE CHAR
    mov byte[rsi], r8b      ; WRITE THE CHAR
    inc rsi            ; NEXT CHAR
    dec rcx            ; DECREMENT THE LEN
    jnz .loop                      ;LOOP UNTIL LEN IS 0

; #########################################################################

      .386
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################

      include d:\masm32\include\windows.inc
      include d:\masm32\include\user32.inc
      include d:\masm32\include\kernel32.inc

      includelib d:\masm32\lib\user32.lib
      includelib d:\masm32\lib\kernel32.lib

; #########################################################################
    ; --------------------------------------------------------
.data
      szDlgTitle    db "Minimum MASM",0
      szMsg         db "  --- Assembler Pure and Simple ---  ",0
    .code
start:
    ; --------------------------------------------------------
    ; script
    push MB_OK
    push offset szDlgTitle
    push offset szMsg
    push 0
    call MessageBox

    ; --------------------------------------------------------
    ; idacall
    push -2
    call ExitProcess

end start
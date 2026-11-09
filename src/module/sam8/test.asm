
        CHIP DEF\S3C8454.DEF

LOOP    EQU 030H

loc0:
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
zp_test:
        dw 0100H
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

	org 0100H

        adc R1,R2
        adc R1, @R2
        adc 01H, 02H
        adc 01H, @02H
        adc 01H, #11H

        add R1, R2
        add R1, @R2
        add 01H, 02H
        add 01H, @02H
        add 01H, #25H

        and R1, R2
        and R1, @R2
        and 01H, 02H
        and 01H, @02H
        and 01H, #25H

        band R1, 01H.1
        band 01H.1, R1

        bcp R1, 01H.1

        bitc R1.1

testback:
        bitr R1.1

        bits R1.3

        bor R1, 01H.1
        bor 01H.2, R1

        btjrf testback, R1.3
        btjrf testforward, R1.3

        btjrt testback, R1.1
        btjrt testforward, R1.2


        bxor R1, 01H.1
        bxor 01H.2, R1

testforward:

        
        call testback
        call testforward
        call @RR0
        call #loc0
        call #40H
        call 4000H

        ccf

        clr 00H
        clr @01H

        com R1
        com @R1

testback2:
        cp R1, R2
        cp R1, @R2
        cp 01H, 02H
        cp 01H, @02H
        cp 01H, #25H

        cpije R1, @R2, testback2
        cpije R1, @R2, testforward2

        cpijne R1, @R2, testback2
        cpijne R1, @R2, testforward2

        da R1
        da @R1
testforward2:

        dec R1
        dec @R1
        
        decw RR0
        decw @R2
        
        di

        div RR0, R2
        div RR0, @R2
        div RR0, #20H
        div 20H, #20H

        djnz R1, testback
        djnz R1, testforward_big

        ei

        enter
        
        exit

        idle
        
        inc R0
        inc 00H
        inc @R0

        incw RR0
        incw @20H

        iret
        ret

testback3
        jp f, testforward_big
        jp t, testforward_big
        jp c, testforward_big
        jp nc, testforward_big
        jp z, testforward_big
        jp nz, testforward_big
        jp pl, testforward_big
        jp mi, testforward_big
        jp ov, testforward_big
        jp nov, testforward_big
        jp eq, testforward_big
        jp ne, testback
        jp ge, testback
        jp lt, testback
        jp gt, testback
        jp le, testback
        jp uge, testback
        jp ult, testback
        jp ugt, testback
        jp ule, testback
        jp @00H

        jr f, testforward_big
        jr t, testforward_big
        jr c, testforward_big
        jr nc, testforward_big
        jr z, testforward_big
        jr nz, testforward_big
        jr pl, testforward_big
        jr mi, testforward_big
        jr ov, testforward_big
        jr nov, testforward_big
        jr eq, testback3
        jr ne, testback3
        jr ge, testback3
        jr lt, testback3
        jr gt, testback3
        jr le, testback3
        jr uge, testback3 
        jr ult, testback3 
        jr ugt, testback3 
        jr ule, testback3 

testforward_big: di

        ld R0, #10H
        ld R0, 01H
        ld 01H, R0
        ld R1, @R0
        ld @R0, R1
        ld 00H, 01H
        ld 02H, @00H
        ld 00H, #0AH
        ld @00H, #10H
        ld @00H, 02H
        ld R0, #LOOP[R1]
        ld #LOOP[R0], R1

        ldb R0, 00H.2
        ldb 00H.0, R0

        ldc R0, @RR2
        ldc @RR2, R0
        ldc R0, #01H[RR2]
        ldc #01H[RR2], R0
        ldc R0, #1000H[RR2]
        ldc R0, 1104H
        ldc 1005H, R0
        ldc R0, #-20[RR2]
        ldc R0, #9000H[RR2]

        lde R0, @RR2
        lde @RR2, R0
        lde R0, #01H[RR2]
        lde #01H[RR2], R0
        lde R0, #1000H[RR2]
        lde R0, 1104H
        lde 1005H, R0
        lde R0, #-20[RR2]

        ldcd R8, @RR6

        lded R8, @RR6

        ldci R8, @RR6

        ldei R8, @RR6

        ldcpd @RR6, R0

        ldepd @RR6, R0

        ldcpi @RR6, R0

        ldepi @RR6, R0

        ldw RR6, RR4
        ldw 00H, 02H
        ldw RR2, @R7
        ldw 04H, @01H
        ldw RR6, #1234H
        ldw 02H, #0FEDH

        mult 00H, 02H
        mult 00H, @01H
        mult 00H, #30H
        mult RR0, #30H
        
        next

        nop

        or R1, R2
        or R1, @R2
        or 01H, 02H
        or 01H, @02H
        or 01H, #25H        
        
        pop 00H
        pop @00H
        
        popud 02H, @00H
        
        popui 02H, @00H

        push 040H

        push @40H

        pushud @00H, 01H

        pushui @00H, 01H

        rcf
        
        ret

        rl 00H
        rl @01H

        rlc 00H
        rlc @01H

        rr 00H
        rr @01H

        rrc 00H
        rrc @01H

        sb0

        sb1

        sbc R1,R2
        sbc R1, @R2
        sbc 01H, 02H
        sbc 01H, @02H
        sbc 01H, #11H

        scf

        sra 00H
        sra @02H

        srp #40H
        srp0 #50H
        srp1 #60H

        stop

        sub R1,R2
        sub R1, @R2
        sub 01H, 02H
        sub 01H, @02H
        sub 01H, #11H
        
        swap 00H
        swap @02H

        tcm R1,R2
        tcm R1, @R2
        tcm 01H, 02H
        tcm 01H, @02H
        tcm 01H, #11H

        tm R1,R2
        tm R1, @R2
        tm 01H, 02H
        tm 01H, @02H
        tm 01H, #11H
        
        wfi

        xor R1,R2
        xor R1, @R2
        xor 01H, 02H
        xor 01H, @02H
        xor 01H, #11H

testcall: ret

        END

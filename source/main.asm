; Contributor A 1000000
;First the lcd shpw "sheet length" so the user write the length of it in cm
; max is 220
; them the lcd fo to the next line and ask num sheets?
; the user enter how many sheets to cut
; then the lcd show start:1 stop:0 and back to menu :3
; so 1 to start, 0 to stop, 3 to change
; when start 1 pressed, the strecher motor work and unroll the sheet
; and the encoder count 
; when the count reach, thhe motor sop
; then the blade cut the sheet, move left or right, 
;it stop when it hit the limit switch
; then the encoder restart and strch motor start again
;the repeat till the user number reached
; the lcd shows the progrss 
;if anything is wrong , machine stop to be safe,

;;the cases::
; if user enter more that 220 cm or than 99 sheet it doesnt starts
; if the big roll s done, the machine stop
; of the blade motor didnt reach the switck, it will be stucl
; if the user press 3, the values reset
; if the encoder not count or stcl, the machine stop
; if th euser press 0 any time, its stop workig

org 0x00
start
call initlcd

; enter sheet length
call get_key
movwf len1
call get_key
movwf len2
call get_key
movwf len3

; enter number of sheets
call get_key
movwf num1
call get_key
movwf num2

; encoder part
enc_loop
btfss encoder_pin
goto enc_loop
incf counter, f
movf counter, w
subwf target_len, w
btfss STATUS,Z
goto enc_loop

; blade motor
movlw 0x01
movwf motor_port
call delay
clrf motor_port

end


rule Tampering_Win32_EDRFreeze_A{
	meta:
		description = "Tampering:Win32/EDRFreeze.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 50 50 4c 20 70 72 6f 63 65 73 73 2e } //Failed to create PPL process.  1
		$a_80_1 = {50 52 4f 54 45 43 54 49 4f 4e 5f 4c 45 56 45 4c 5f 57 49 4e 54 43 42 5f 4c 49 47 48 54 } //PROTECTION_LEVEL_WINTCB_LIGHT  1
		$a_80_2 = {4b 69 6c 6c 20 57 45 52 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e 20 50 49 44 3a } //Kill WER successfully. PID:  1
		$a_80_3 = {2f 65 6e 63 66 69 6c 65 } ///encfile  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
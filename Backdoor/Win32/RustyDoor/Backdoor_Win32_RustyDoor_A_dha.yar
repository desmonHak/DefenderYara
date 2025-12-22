
rule Backdoor_Win32_RustyDoor_A_dha{
	meta:
		description = "Backdoor:Win32/RustyDoor.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4d 55 49 54 72 61 6e 73 66 65 72 } //1 GetMUITransfer
		$a_01_1 = {24 23 34 3a 32 14 52 19 10 03 01 18 24 2a 04 11 13 01 7f 18 04 4b 00 0b 0c } //1
		$a_01_2 = {16 01 15 53 09 16 56 19 43 03 0d 06 1d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
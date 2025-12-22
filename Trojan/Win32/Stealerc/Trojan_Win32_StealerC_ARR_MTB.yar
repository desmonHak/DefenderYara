
rule Trojan_Win32_StealerC_ARR_MTB{
	meta:
		description = "Trojan:Win32/StealerC.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 64 61 74 61 00 00 00 ac df 03 00 00 a0 08 } //10
		$a_01_1 = {74 61 00 00 7e 8f 01 00 00 10 07 } //3
		$a_01_2 = {64 86 09 00 ab ea c9 68 00 00 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=15
 
}
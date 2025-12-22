
rule Backdoor_Win32_Oadway_C_dha{
	meta:
		description = "Backdoor:Win32/Oadway.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f be 08 83 f1 ?? 8b 55 08 03 55 f8 88 0a eb db } //5
		$a_00_1 = {83 e0 47 31 f8 31 d8 81 f3 a0 00 00 00 21 fb 35 a4 00 00 00 09 c3 80 f3 c6 } //5
		$a_00_2 = {88 d6 80 f6 ce 89 d3 80 e3 b0 80 f3 30 80 f2 7e 20 f2 08 da 88 14 08 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5) >=5
 
}
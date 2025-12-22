
rule Trojan_Win32_LambRing_A_dha{
	meta:
		description = "Trojan:Win32/LambRing.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {64 6f 63 78 78 6c 73 78 6c 73 ?? 70 70 74 70 70 74 78 70 64 66 74 78 74 64 6f 63 } //1
		$a_01_1 = {56 1a 19 07 1d 16 04 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
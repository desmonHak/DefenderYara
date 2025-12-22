
rule Trojan_Win32_Diple_KK_MTB{
	meta:
		description = "Trojan:Win32/Diple.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 83 c0 10 bb 31 9d 24 1f 31 18 83 c0 04 e2 f9 } //20
		$a_01_1 = {11 7f 18 a6 9e b4 14 32 65 e8 2b 70 9e b2 10 32 6b d4 93 8f 73 cd } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
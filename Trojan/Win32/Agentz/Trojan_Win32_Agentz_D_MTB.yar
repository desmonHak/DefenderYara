
rule Trojan_Win32_Agentz_D_MTB{
	meta:
		description = "Trojan:Win32/Agentz.D!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff cb 44 8b 14 9e 4d 03 d3 66 45 39 2a 75 54 45 8b cc 41 b8 f3 e7 50 b5 49 8b c2 0f 1f 44 00 00 0f b7 00 41 8b c8 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
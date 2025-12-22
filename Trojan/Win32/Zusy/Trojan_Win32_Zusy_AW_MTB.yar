
rule Trojan_Win32_Zusy_AW_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 9c c1 83 f8 09 88 d5 0f 9f c4 30 d1 30 e2 08 e5 88 d0 20 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win32_Cerber_MK_MTB{
	meta:
		description = "Trojan:Win32/Cerber.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d fc 88 01 8b 55 fc 83 c2 01 } //15
		$a_01_1 = {0f b6 05 a4 8a 43 00 83 f0 08 a2 ca e2 42 00 8a 0d a4 8a 43 00 80 e9 01 88 0d a4 8a 43 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}
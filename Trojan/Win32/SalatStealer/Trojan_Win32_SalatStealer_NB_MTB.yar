
rule Trojan_Win32_SalatStealer_NB_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 5f 04 8d 84 30 00 e0 b7 00 01 f3 50 83 c7 08 ff 96 28 e0 b7 00 95 8a 07 47 } //2
		$a_01_1 = {ff 96 30 e0 b7 00 09 c0 74 07 89 03 83 c3 04 eb e1 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
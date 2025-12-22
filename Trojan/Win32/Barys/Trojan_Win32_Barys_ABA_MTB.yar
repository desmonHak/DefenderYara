
rule Trojan_Win32_Barys_ABA_MTB{
	meta:
		description = "Trojan:Win32/Barys.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 4e c6 40 44 00 8a 06 84 c0 74 05 3a 46 ff 74 22 ff 15 ?? ?? ?? ?? 99 b9 07 00 00 00 f7 f9 8b 45 08 40 83 f8 0f 89 45 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
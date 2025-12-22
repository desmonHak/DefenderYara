
rule Trojan_Win32_Rugmi_HM_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_23_0 = {8b ec 81 ec 90 01 03 00 c7 45 90 02 ff 8b 90 02 ff 8b 90 01 01 3c 90 00 14 } //20
		$a_55_1 = {ec 81 ec 90 01 03 00 c7 45 90 01 01 90 01 04 8b 45 90 1b 01 90 00 00 00 5d 04 00 00 18 18 07 80 5c 2f 00 } //6144
	condition:
		((#a_23_0  & 1)*20+(#a_55_1  & 1)*6144) >=20
 
}
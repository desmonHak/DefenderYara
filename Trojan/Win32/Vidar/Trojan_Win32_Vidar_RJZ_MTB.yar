
rule Trojan_Win32_Vidar_RJZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 37 2c 05 34 53 88 04 37 46 57 e8 ?? ?? ?? ?? 59 3b f0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}

rule Trojan_Win32_Rugmi_HF_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 48 3c 89 4d ?? 8b 45 90 1b 00 8b 4d ?? 03 48 2c [0-80] 66 89 04 4a 8b 45 f0 40 89 45 f0 [0-50] 50 ff 55 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
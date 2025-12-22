
rule Trojan_Win32_Neoreblamy_NPS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 40 89 45 ec 83 7d ec 01 7d 10 8b 45 ec } //1
		$a_03_1 = {6a 1c 58 6b c0 03 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}
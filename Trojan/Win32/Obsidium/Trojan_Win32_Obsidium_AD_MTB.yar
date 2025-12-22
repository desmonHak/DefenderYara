
rule Trojan_Win32_Obsidium_AD_MTB{
	meta:
		description = "Trojan:Win32/Obsidium.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 91 ab 19 61 a9 d4 a6 7b 62 09 b2 b1 32 2c 61 26 41 fb 56 9e 1c b2 33 1d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
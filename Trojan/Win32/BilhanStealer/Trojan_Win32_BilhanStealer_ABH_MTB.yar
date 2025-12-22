
rule Trojan_Win32_BilhanStealer_ABH_MTB{
	meta:
		description = "Trojan:Win32/BilhanStealer.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 18 62 40 00 68 0c 62 40 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 b9 0e 00 00 00 33 c0 8d 7c 24 08 f3 ab 8b 44 24 44 8d 4c 24 04 51 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
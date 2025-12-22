
rule Trojan_Win32_Stealer_MKN_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 7d 98 33 f6 2b c7 74 ?? 66 0f 1f 44 00 00 e8 f8 ?? 02 00 30 04 37 46 8b 45 9c 8b 7d 98 2b c7 3b f0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
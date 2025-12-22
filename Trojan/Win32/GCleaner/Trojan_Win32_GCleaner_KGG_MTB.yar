
rule Trojan_Win32_GCleaner_KGG_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.KGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 03 f7 6a 00 ?? ?? ?? ?? ff 2b f0 8b 45 e0 31 30 83 c3 04 83 45 e0 04 3b 5d dc 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
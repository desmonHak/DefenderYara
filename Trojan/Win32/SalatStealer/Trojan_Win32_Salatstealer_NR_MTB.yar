
rule Trojan_Win32_Salatstealer_NR_MTB{
	meta:
		description = "Trojan:Win32/Salatstealer.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4e ed 26 8b eb 82 f6 ?? 17 ec 1f 30 71 ?? 4a eb b4 43 } //2
		$a_01_1 = {f6 30 95 13 c3 43 46 49 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
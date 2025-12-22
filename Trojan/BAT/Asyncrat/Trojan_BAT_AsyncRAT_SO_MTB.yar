
rule Trojan_BAT_AsyncRAT_SO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {06 07 06 07 93 1f 70 65 66 61 02 61 d1 9d 07 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 58 59 25 0b 20 93 05 ab 0d 20 93 05 ab 0d 61 1d 63 2f d4 } //1
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
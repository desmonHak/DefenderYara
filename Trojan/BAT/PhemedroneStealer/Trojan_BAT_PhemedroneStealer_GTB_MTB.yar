
rule Trojan_BAT_PhemedroneStealer_GTB_MTB{
	meta:
		description = "Trojan:BAT/PhemedroneStealer.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {68 61 63 6b 65 72 36 36 36 6c 67 62 74 2f 62 69 6e 61 72 69 65 73 } //hacker666lgbt/binaries  1
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //1 DownloadFileAsync
		$a_01_2 = {50 68 65 6d 65 64 72 6f 6e 65 2d 53 74 65 61 6c 65 72 } //1 Phemedrone-Stealer
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
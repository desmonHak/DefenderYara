
rule Trojan_Linux_SAgnt_AH_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.AH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 48 6f 6d 65 43 68 65 63 6b 65 72 } //1 main.HomeChecker
		$a_01_1 = {6d 61 69 6e 2e 66 69 6e 64 57 72 69 74 61 62 6c 65 44 69 72 } //1 main.findWritableDir
		$a_01_2 = {6d 61 69 6e 2e 52 65 61 6c 43 68 65 63 6b } //1 main.RealCheck
		$a_01_3 = {6d 61 69 6e 2e 48 69 64 64 65 6e 48 6f 6d 65 } //1 main.HiddenHome
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
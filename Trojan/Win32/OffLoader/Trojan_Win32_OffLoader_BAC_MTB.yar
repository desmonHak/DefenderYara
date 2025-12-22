
rule Trojan_Win32_OffLoader_BAC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 70 61 73 73 65 6e 67 65 72 77 65 61 74 68 65 72 2e 69 6e 66 6f 2f 67 72 78 73 2e 70 68 70 3f } //://passengerweather.info/grxs.php?  4
		$a_80_1 = {3a 2f 2f 61 63 74 69 6f 6e 63 6c 6f 74 68 2e 78 79 7a 2f 67 72 78 73 73 2e 70 68 70 3f } //://actioncloth.xyz/grxss.php?  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}
rule Trojan_Win32_OffLoader_BAC_MTB_2{
	meta:
		description = "Trojan:Win32/OffLoader.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 73 65 6c 65 63 74 69 6f 6e 73 63 61 72 65 63 72 6f 77 2e 69 6e 66 6f 2f 61 77 61 73 2e 70 68 70 3f } //://selectionscarecrow.info/awas.php?  4
		$a_80_1 = {3a 2f 2f 65 61 72 74 68 6b 69 74 74 65 6e 73 2e 78 79 7a 2f 61 77 61 73 73 2e 70 68 70 3f } //://earthkittens.xyz/awass.php?  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}
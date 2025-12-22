
rule Trojan_Win32_GuLoader_RBO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 6f 63 61 2d 43 6f 6c 61 20 45 6e 74 65 72 70 72 69 73 65 73 20 49 6e 63 2e } //1 Coca-Cola Enterprises Inc.
		$a_81_1 = {4f 75 74 62 61 63 6b 20 53 74 65 61 6b 68 6f 75 73 65 20 49 6e 63 2e } //1 Outback Steakhouse Inc.
		$a_81_2 = {4d 61 78 69 6d 20 49 6e 74 65 67 72 61 74 65 64 20 50 72 6f 64 75 63 74 73 20 49 6e 63 2e } //1 Maxim Integrated Products Inc.
		$a_81_3 = {64 69 6d 69 6e 69 73 68 6d 65 6e 74 2e 65 78 65 } //1 diminishment.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_GuLoader_RBO_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 61 6c 6b 61 6e 6c 61 6e 64 20 70 61 72 61 6d 65 74 65 72 66 72 65 6d 73 74 69 6c 6c 69 6e 67 65 72 73 20 66 6f 72 61 6e 6e 76 6e 74 } //1 balkanland parameterfremstillingers forannvnt
		$a_81_1 = {73 70 69 6c 64 65 76 61 6e 64 73 62 65 6b 65 6e 64 74 67 72 65 6c 73 65 6e 73 20 6e 6f 6e 6c 69 71 75 69 64 61 74 69 6e 67 } //1 spildevandsbekendtgrelsens nonliquidating
		$a_81_2 = {6b 76 6c 6c 65 72 6e 65 73 20 73 70 6f 6e 64 69 61 73 20 6d 6f 6c 65 6e 64 69 6e 61 72 79 } //1 kvllernes spondias molendinary
		$a_81_3 = {62 61 63 6b 62 75 72 6e } //1 backburn
		$a_81_4 = {61 6e 67 69 6f 6e 6f 6d 61 2e 65 78 65 } //1 angionoma.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
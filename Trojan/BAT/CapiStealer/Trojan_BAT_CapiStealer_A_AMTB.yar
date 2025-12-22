
rule Trojan_BAT_CapiStealer_A_AMTB{
	meta:
		description = "Trojan:BAT/CapiStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_81_0 = {39 31 2e 32 32 33 2e 37 35 2e 39 36 } //2 91.223.75.96
		$a_81_1 = {53 2d 31 2d 35 2d 33 32 2d 35 34 34 } //1 S-1-5-32-544
		$a_81_2 = {56 6d 44 65 74 65 63 74 6f 72 } //1 VmDetector
		$a_81_3 = {70 65 72 73 69 73 74 31 } //1 persist1
		$a_81_4 = {6b 69 6c 6c 63 6c 69 65 6e 74 } //1 killclient
		$a_81_5 = {66 66 70 72 6f 66 69 6c 65 5f 73 61 66 65 2e 7a 69 70 } //1 ffprofile_safe.zip
		$a_81_6 = {43 68 65 63 6b 47 75 65 73 74 52 65 67 69 73 74 72 79 53 74 72 6f 6e 67 } //1 CheckGuestRegistryStrong
		$a_81_7 = {43 68 65 63 6b 53 6d 62 69 6f 73 4d 61 72 6b 65 72 73 } //1 CheckSmbiosMarkers
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=7
 
}
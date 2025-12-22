
rule Trojan_Linux_Slapstick_AMTB{
	meta:
		description = "Trojan:Linux/Slapstick!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 73 } //%-23s %-23s %-23s %-23s %-23s %s  1
		$a_80_1 = {70 61 6d 5f 73 6d 5f 61 75 74 68 65 6e 74 69 63 61 74 65 } //pam_sm_authenticate  1
		$a_80_2 = {48 49 53 54 46 49 4c 45 3d 2f 64 65 76 2f 6e 75 6c 6c } //HISTFILE=/dev/null  1
		$a_80_3 = {25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 } //%-23s %-23s %-23s  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
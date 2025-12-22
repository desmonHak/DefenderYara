
rule Trojan_Win64_Mikey_PCW_MTB{
	meta:
		description = "Trojan:Win64/Mikey.PCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 } //1 netsh advfirewall firewall add rule name
		$a_81_1 = {73 63 68 61 6e 6e 65 6c 3a 20 66 61 69 6c 65 64 20 74 6f 20 64 65 63 72 79 70 74 20 64 61 74 61 2c 20 6e 65 65 64 20 6d 6f 72 65 20 64 61 74 61 } //1 schannel: failed to decrypt data, need more data
		$a_81_2 = {45 4d 4f 54 45 20 2f 20 41 56 41 54 41 52 20 48 41 43 4b 20 28 20 4f 4e 20 2e 20 4f 46 46 20 29 } //1 EMOTE / AVATAR HACK ( ON . OFF )
		$a_81_3 = {4d 41 48 4f 4e 20 46 52 45 45 20 56 52 53 2e 70 64 62 } //1 MAHON FREE VRS.pdb
		$a_81_4 = {43 41 4d 45 52 41 20 48 41 43 4b } //1 CAMERA HACK
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
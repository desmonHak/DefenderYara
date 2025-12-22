
rule Ransom_Linux_Inc_B_MTB{
	meta:
		description = "Ransom:Linux/Inc.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 4e 43 64 69 72 65 63 74 6f 72 79 64 69 72 45 6e 63 72 79 70 74 69 6f 6e 20 64 69 72 65 63 74 6f 72 79 } //1 INCdirectorydirEncryption directory
		$a_01_1 = {65 73 78 69 73 6b 69 70 66 61 73 74 73 6c 6f 77 25 69 64 25 45 6e 63 72 79 70 74 69 6f 6e 20 6f 66 20 66 69 6c 65 } //1 esxiskipfastslow%id%Encryption of file
		$a_01_2 = {65 74 63 2f 6d 6f 74 64 76 69 6d 2d 63 6d 64 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 } //1 etc/motdvim-cmdvmsvc/getallvms
		$a_01_3 = {76 6d 73 76 63 2f 70 6f 77 65 72 2e 6f 66 66 76 6d 73 76 63 2f 73 6e 61 70 73 68 6f 74 2e 72 65 6d 6f 76 65 61 6c 6c 73 72 63 } //1 vmsvc/power.offvmsvc/snapshot.removeallsrc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
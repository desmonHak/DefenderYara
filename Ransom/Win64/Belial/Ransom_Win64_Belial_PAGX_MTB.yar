
rule Ransom_Win64_Belial_PAGX_MTB{
	meta:
		description = "Ransom:Win64/Belial.PAGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 c1 ba 1f 85 eb 51 89 c8 f7 ea c1 fa 05 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 64 29 c1 89 c8 83 c0 01 89 85 0c 0f 00 00 83 85 2c 0f 00 00 01 } //2
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 56 4d 77 61 72 65 2c 49 6e 63 2e 5c 56 4d 77 61 72 65 20 54 6f 6f 6c 73 } //1 SOFTWARE\VMware,Inc.\VMware Tools
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4f 72 61 63 6c 65 5c 56 69 72 74 75 61 6c 42 6f 78 20 47 75 65 73 74 20 41 64 64 69 74 69 6f 6e 73 } //1 SOFTWARE\Oracle\VirtualBox Guest Additions
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win64_Tedy_MCN_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 2e 64 6c 6c 00 4c 6f 61 64 50 6f 77 65 72 50 6f 69 6e 74 48 6f 6f 6b 00 55 6e 4c 6f 61 64 50 6f 77 65 72 50 6f 69 6e 74 48 6f 6f 6b 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 00 64 62 6b 46 43 61 6c 6c 57 72 61 70 70 65 72 41 64 64 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_O97M_EncDoc_RR_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.RR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 22 61 70 70 64 61 74 61 22 29 [0-0f] 3d 90 1b 00 26 22 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 73 74 61 72 74 6d 65 6e 75 5c 70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 75 70 5c 6b 65 66 65 2e 62 61 74 22 [0-05] 3d 22 71 67 76 6a 61 67 38 67 62 32 7a 6d 64 71 70 7a 78 6d 6e 6f 78 6e 72 65 79 76 35 7a 78 6d 74 65 63 79 61 76 79 33 6a 6c 79 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
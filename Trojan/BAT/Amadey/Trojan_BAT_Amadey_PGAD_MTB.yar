
rule Trojan_BAT_Amadey_PGAD_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PGAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 64 34 61 63 61 38 35 63 2d 37 31 32 34 2d 34 37 33 64 2d 61 32 65 63 2d 32 36 39 35 66 64 66 30 38 38 38 65 } //1 $d4aca85c-7124-473d-a2ec-2695fdf0888e
		$a_01_1 = {6b 6f 69 00 44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e 65 78 65 } //1
		$a_03_2 = {44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e [0-08] 2e 72 65 73 } //1
		$a_01_3 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //1 LzmaDecoder
		$a_01_4 = {42 69 74 54 72 65 65 44 65 63 6f 64 65 72 } //1 BitTreeDecoder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
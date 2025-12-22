
rule Trojan_BAT_ClipBanker_NIA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {35 33 33 31 62 64 33 34 2d 34 30 32 37 2d 34 36 35 37 2d 62 32 62 66 2d 62 31 61 36 39 36 62 31 62 31 62 37 } //2 5331bd34-4027-4657-b2bf-b1a696b1b1b7
		$a_81_1 = {28 78 72 62 5f 7c 6e 61 6e 6f 5f 29 5b 31 33 34 35 36 37 38 39 61 62 63 64 65 66 67 68 69 6a 6b 6d 6e 6f 70 71 72 73 74 75 77 78 79 7a 5d } //1 (xrb_|nano_)[13456789abcdefghijkmnopqrstuwxyz]
		$a_81_2 = {28 4e 41 7c 4e 42 7c 4e 43 7c 4e 44 29 5b 61 2d 7a 41 2d 7a 30 2d 39 5d 7b 33 38 7d } //1 (NA|NB|NC|ND)[a-zA-z0-9]{38}
		$a_81_3 = {28 74 65 72 72 61 31 29 5b 30 2d 39 61 2d 7a 5d 7b 33 38 7d } //1 (terra1)[0-9a-z]{38}
		$a_81_4 = {28 63 6f 73 6d 6f 73 31 29 5b 30 2d 39 61 2d 7a 5d 7b 33 38 7d } //1 (cosmos1)[0-9a-z]{38}
		$a_81_5 = {28 62 69 74 63 6f 69 6e 63 61 73 68 3a 29 3f 28 71 7c 70 29 5b 61 2d 7a 30 2d 39 5d } //1 (bitcoincash:)?(q|p)[a-z0-9]
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}
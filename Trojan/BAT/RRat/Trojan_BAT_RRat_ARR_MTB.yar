
rule Trojan_BAT_RRat_ARR_MTB{
	meta:
		description = "Trojan:BAT/RRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 5f 64 33 31 63 37 33 34 65 61 65 34 63 34 38 63 30 62 64 62 32 31 30 33 37 61 37 35 61 38 32 66 66 } //5 m_d31c734eae4c48c0bdb21037a75a82ff
		$a_01_1 = {3c 4d 6f 64 75 6c 65 3e 7b 39 65 61 38 33 36 37 30 2d 38 31 66 35 2d 34 32 62 39 2d 39 30 63 32 2d 37 34 39 66 32 32 66 35 65 34 39 36 7d } //3 <Module>{9ea83670-81f5-42b9-90c2-749f22f5e496}
		$a_01_2 = {43 75 73 74 6f 6d 65 72 2e 44 65 73 63 72 69 70 74 6f 72 } //2 Customer.Descriptor
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}
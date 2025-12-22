
rule Trojan_Win32_Zusy_GAPJ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GAPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 44 54 48 4e 71 43 51 47 49 56 74 30 4b 46 51 55 68 39 4e 79 72 48 58 4b 47 51 37 6a 2f 61 61 45 2f 53 4e 4b 41 73 7a 45 6f 79 5a 77 58 36 56 62 37 47 4a 67 67 4c 35 2f 4b 42 4c 4d 31 34 72 53 4d 71 73 47 78 52 41 2b 75 63 4c 6a 53 73 41 4e 4e 4c 46 65 51 3d 3d } //8 iDTHNqCQGIVt0KFQUh9NyrHXKGQ7j/aaE/SNKAszEoyZwX6Vb7GJggL5/KBLM14rSMqsGxRA+ucLjSsANNLFeQ==
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
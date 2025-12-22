
rule Trojan_Win32_Zusy_HAQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_01_0 = {51 7a 70 63 56 32 6c 75 5a 47 39 33 63 31 78 7a 65 58 4e 30 5a 57 30 7a 4d 6c 78 6a 62 57 51 75 5a 58 68 6c } //20 QzpcV2luZG93c1xzeXN0ZW0zMlxjbWQuZXhl
		$a_01_1 = {2e 73 72 63 20 3d 20 61 74 6f 62 28 } //1 .src = atob(
		$a_01_2 = {3c 66 6f 72 6d 20 61 63 74 69 6f 6e 3d } //5 <form action=
		$a_01_3 = {74 79 70 65 3d 27 74 65 78 74 27 20 6e 61 6d 65 3d 27 70 61 73 73 77 6f 72 64 27 } //4 type='text' name='password'
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4) >=30
 
}
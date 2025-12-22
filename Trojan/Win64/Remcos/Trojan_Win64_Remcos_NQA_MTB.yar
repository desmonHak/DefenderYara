
rule Trojan_Win64_Remcos_NQA_MTB{
	meta:
		description = "Trojan:Win64/Remcos.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 33 4c d8 10 4c 89 09 4c 8b 0a 49 c1 c1 03 4c 33 09 } //1
		$a_81_1 = {2a 21 2a 25 2a 29 2a 2d 2a 31 2a 35 2a 39 2a 3d 2a 41 2a 45 2a 49 2a 4d 2a 51 2a 55 2a 59 2a 5d 2a 61 2a 65 2a 69 2a 6d 2a 71 2a 75 2a 79 2a } //2 *!*%*)*-*1*5*9*=*A*E*I*M*Q*U*Y*]*a*e*i*m*q*u*y*
		$a_81_2 = {4f 70 65 6e 52 65 6d 6f 74 65 42 61 73 65 4b 65 79 } //1 OpenRemoteBaseKey
		$a_81_3 = {44 65 70 65 6e 64 65 6e 63 79 49 6e 6a 65 63 74 69 6f 6e } //1 DependencyInjection
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}
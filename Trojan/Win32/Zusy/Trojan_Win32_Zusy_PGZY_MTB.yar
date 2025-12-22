
rule Trojan_Win32_Zusy_PGZY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 db 74 01 ea 31 ?? ?? ?? 81 c3 04 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zusy_PGZY_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.PGZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 48 5f 4e 2e 52 20 71 69 5f 47 39 20 79 64 73 5f 46 2e 42 5f 5a 2e 7a 20 56 20 65 2e 41 5d 5f 74 20 64 2e 77 3a 77 5f 42 7a 52 20 55 30 20 6a 2e 66 5f 6a 5f 55 46 2e 38 20 74 5f 4e 2e 44 2e 73 2e 7a 2e 6d } //5 _H_N.R qi_G9 yds_F.B_Z.z V e.A]_t d.w:w_BzR U0 j.f_j_UF.8 t_N.D.s.z.m
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
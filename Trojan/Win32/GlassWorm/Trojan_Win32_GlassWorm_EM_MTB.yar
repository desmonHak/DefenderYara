
rule Trojan_Win32_GlassWorm_EM_MTB{
	meta:
		description = "Trojan:Win32/GlassWorm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {67 65 6e 65 72 61 74 65 5f 73 65 63 72 65 74 5f 6b 65 79 5f 68 76 6e 63 2e 70 64 62 } //1 generate_secret_key_hvnc.pdb
		$a_81_1 = {67 65 6e 65 72 61 74 65 5f 73 65 63 72 65 74 5f 6b 65 79 5f 68 76 6e 63 2e 64 6c 6c } //1 generate_secret_key_hvnc.dll
		$a_81_2 = {6e 61 70 69 5f 72 65 67 69 73 74 65 72 5f 6d 6f 64 75 6c 65 5f 76 31 } //1 napi_register_module_v1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
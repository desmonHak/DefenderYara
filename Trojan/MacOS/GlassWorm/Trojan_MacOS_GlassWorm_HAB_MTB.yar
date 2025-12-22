
rule Trojan_MacOS_GlassWorm_HAB_MTB{
	meta:
		description = "Trojan:MacOS/GlassWorm.HAB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,20 00 20 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 69 62 2e 72 73 64 65 63 6f 64 65 67 65 6e 65 72 61 74 65 5f 73 65 63 72 65 74 5f 6b 65 79 5f 68 76 6e 63 3a 3a 64 65 63 6f 64 65 2f } //30 /lib.rsdecodegenerate_secret_key_hvnc::decode/
		$a_01_1 = {6e 61 70 69 5f 72 75 6e 5f 73 63 72 69 70 74 6e 61 70 69 5f 63 72 65 61 74 65 5f 61 73 79 6e 63 } //1 napi_run_scriptnapi_create_async
		$a_01_2 = {2f 65 6e 74 72 79 2e 72 73 2f 72 75 73 74 63 2f } //1 /entry.rs/rustc/
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=32
 
}
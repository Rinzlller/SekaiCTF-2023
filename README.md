# SekaiCTF-2023
Writeups from SekaiCTF 2023 (exactly for PWN tasks)

**PWN category [solved by me] :**
- Network Tools
- Cosmic Ray

## Cosmic Ray | 1 lvl.
**Vuln**: 1-bit write primitive

**Solution**: So, as you can see above, there is 1-bit write primitive supposed by author. It allows us to change an arbitrary memory in process memory (data, instructions).

There is one interesting fact about the assembler representation of instructions. The difference between **JZ** and **JNZ** commands is just one bit - **JZ is 0x74**, and **JNZ is 0x75**. Thanks that, we are able to invert the canary check behavior and then perform a buffer overflow wihout any problems.

To get the flag, it is enough to replace the return address with the address of the win function.

## Network Tools | 2 lvl.
**Vuln**: BoF

**Solution**: In this task, we need to read the Rust code that performs some network operations (ping and so on). One of them (ip_lookup) is supposed to read a hostname that can't be longer than 0x400 characters, but for thease data, there are only 400 bytes on the stack => BoF. But not yet...

    fn ip_lookup(){
	    let mut input: [u8; 400] = [0; 400];

	    print!("Hostname: ");
	    io::stdout().flush().unwrap();
	    let size = read(&mut input, 0x400);
	    let (hostname, _) = input.split_at(size as usize);
	    ...

The split_at() function will fail with a size larger than the input size (400 bytes exactly). But, fortunately, the read() function also has some logical vulnerability - it reads data up to b'\x0a', but counts it up to b'\x00'. It's weird, isn't it?)

Within BoF we get ROP. There is only one complication, we need to push the /bin/sh string on the stack, however Rust, even without a library, puts a lot of gadgets in executable files for this.

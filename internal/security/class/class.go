// Package securityclass holds the security-relevant API knowledge base.
//
// Classification philosophy: membership in a category is an OBSERVATION of
// capability surface ("this binary imports process-execution APIs"), never a
// vulnerability claim. Whether a dangerous API is actually reachable with
// attacker-controlled input is the job of later data-flow and validation
// stages (spec sections 8 and 19).
package class

import "strings"

// Category names shown to users.
const (
	CatMemory      = "memory"
	CatExec        = "process_execution"
	CatFS          = "filesystem"
	CatNet         = "networking"
	CatDynamicLoad = "dynamic_loading"
	CatPrivilege   = "privilege"
	CatCrypto      = "cryptography"
	CatAuth        = "authentication"
	CatIPC         = "ipc"
	CatEnv         = "environment"
)

var kb map[string]string

func init() {
	kb = map[string]string{}
	add := func(cat string, names ...string) {
		for _, n := range names {
			kb[n] = cat
		}
	}

	add(CatMemory,
		"strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf",
		"snprintf", "gets", "memcpy", "memmove", "memset", "malloc", "calloc",
		"realloc", "free", "alloca", "mempcpy", "stpcpy", "wcscpy", "wcsncpy")
	add(CatExec,
		"system", "popen", "execl", "execlp", "execle", "execv", "execvp",
		"execvpe", "execve", "fork", "posix_spawn", "posix_spawnp", "daemon",
		"CreateProcess", "WinExec")
	add(CatFS,
		"open", "openat", "fopen", "freopen", "unlink", "unlinkat", "rename",
		"renameat", "chmod", "fchmod", "chown", "mktemp", "mkstemp", "tmpnam",
		"tempnam", "remove", "mkdir", "rmdir", "creat", "truncate", "link",
		"symlink", "readlink", "stat", "lstat", "access")
	add(CatNet,
		"socket", "socketpair", "connect", "bind", "listen", "accept",
		"accept4", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg",
		"gethostbyname", "getaddrinfo", "inet_addr", "inet_aton", "select",
		"poll", "WSAStartup")
	add(CatDynamicLoad,
		"dlopen", "dlsym", "dlmopen", "LoadLibraryA", "LoadLibraryW",
		"GetProcAddress", "dladdr")
	add(CatPrivilege,
		"setuid", "seteuid", "setreuid", "setresuid", "setgid", "setegid",
		"setregid", "setresgid", "setgroups", "initgroups", "capset", "capget")
	add(CatCrypto,
		"MD5_Init", "MD5_Update", "MD5_Final", "SHA1_Init", "SHA256_Init",
		"SHA512_Init", "AES_set_encrypt_key", "AES_set_decrypt_key",
		"EVP_EncryptInit", "EVP_DecryptInit", "RSA_public_encrypt",
		"RSA_private_decrypt", "RAND_bytes", "DES_ecb_encrypt", "RC4",
		"mbedtls_md5", "gcry_md_hash_buffer")
	add(CatAuth,
		"crypt", "crypt_r", "getspnam", "pam_authenticate", "getpwnam",
		"PAM_start", "LogonUser")
	add(CatIPC,
		"pipe", "pipe2", "shm_open", "shmget", "shmat", "msgget", "msgsnd",
		"msgrcv", "sem_open", "semget")
	add(CatEnv,
		"getenv", "putenv", "setenv", "unsetenv")
}

// Category returns the security category for name, or "" when the symbol is
// not in the knowledge base.
func Category(name string) string {
	if cat, ok := kb[name]; ok {
		return cat
	}
	// Versioned glibc symbols arrive pre-split; handle residual suffixes.
	if i := strings.IndexByte(name, '@'); i > 0 {
		return kb[name[:i]]
	}
	return ""
}

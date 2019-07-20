/*
	eCryptFS Token Decoder tool
	(C) 2019 Taddy Snow fotonix@pm.me
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <linux/types.h>

#define ECRYPTFS_SIG_SIZE 8
#define ECRYPTFS_SIG_SIZE_HEX (ECRYPTFS_SIG_SIZE*2)
#define ECRYPTFS_PASSWORD_SIG_SIZE ECRYPTFS_SIG_SIZE_HEX
#define ECRYPTFS_MAX_KEY_BYTES 64
#define ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES 512
#define ECRYPTFS_SALT_SIZE 8
#define ECRYPTFS_MAX_KEY_MOD_NAME_BYTES 16

enum ecryptfs_token_types {ECRYPTFS_PASSWORD, ECRYPTFS_PRIVATE_KEY};

struct ecryptfs_private_key {
	uint32_t key_size;
	uint32_t data_len;
	uint8_t signature[ECRYPTFS_PASSWORD_SIG_SIZE + 1];
	char key_mod_alias[ECRYPTFS_MAX_KEY_MOD_NAME_BYTES + 1];
	uint8_t data[];
};

struct ecryptfs_session_key {
#define ECRYPTFS_USERSPACE_SHOULD_TRY_TO_DECRYPT 0x00000001
#define ECRYPTFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT 0x00000002
#define ECRYPTFS_CONTAINS_DECRYPTED_KEY 0x00000004
#define ECRYPTFS_CONTAINS_ENCRYPTED_KEY 0x00000008
	int32_t flags;
	int32_t encrypted_key_size;
	int32_t decrypted_key_size;
	uint8_t encrypted_key[ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES];
	uint8_t decrypted_key[ECRYPTFS_MAX_KEY_BYTES];
};

struct ecryptfs_password {
	int32_t password_bytes;
	int32_t hash_algo;
	int32_t hash_iterations;
	int32_t session_key_encryption_key_bytes;
#define ECRYPTFS_PERSISTENT_PASSWORD             0x01
#define ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET  0x02
	uint32_t flags;
	/* Iterated-hash concatenation of salt and passphrase */
	uint8_t session_key_encryption_key[ECRYPTFS_MAX_KEY_BYTES];
	uint8_t signature[ECRYPTFS_PASSWORD_SIG_SIZE + 1];
	/* Always in expanded hex */
	uint8_t salt[ECRYPTFS_SALT_SIZE];
};

struct ecryptfs_auth_tok {
	uint16_t version; /* 8-bit major and 8-bit minor */
	uint16_t token_type;
#define ECRYPTFS_ENCRYPT_ONLY 0x00000001
	uint32_t flags;
	struct ecryptfs_session_key session_key;
	uint8_t reserved[32];
	union {
		struct ecryptfs_password password;
		struct ecryptfs_private_key private_key;
	} token;
}  __attribute__ ((packed));

struct ecryptfs_auth_tok tok;


ph(char *txt, void *buf, int len, char *txtend)
{
	int i;
	unsigned char *p = buf;
	
	printf("%s", txt);
	
	for (i = 0; i < len; i++)
		printf("%02X", p[i]);
	
	printf("%s", txtend);
}

int main(int argc, char **argv)
{
	int f, ret, size = sizeof(tok);

	if (argc < 2) {
		printf("Input file name missing\n");
		return 1;
	}
	
	f = open(argv[1], O_RDONLY);
	ret = read(f, &tok, size);
	close(f);
	
	printf("Read %d (ret=%d)\n", size, ret);
	
	printf("VERSION: %04X\n", tok.version);
	printf("TTYPE  : %s\n", (tok.token_type == ECRYPTFS_PASSWORD)?"PASSWORD":"PRIVATE_KEY");
	printf("EKS    : %d\n", tok.session_key.encrypted_key_size);
	printf("DKS    : %d\n", tok.session_key.decrypted_key_size);
	printf("PLEN   : %d\n", tok.token.password.password_bytes);
	
	printf("HASHALG: %s\n", (tok.token.password.hash_algo & 0x0A)?"PGP_DIGEST_ALGO_SHA512":"?");
	printf("H-IETR : %d\n", tok.token.password.hash_iterations);
	printf("FLAGS  : %02X %s\n\n", tok.token.password.flags, (tok.token.password.flags & 2)?"SESION/ENCRYPTION KEY SET":"");
	
	printf("SES KEYLEN : %d\n", tok.token.password.session_key_encryption_key_bytes);
	ph("SESION KEY : ", &tok.token.password.session_key_encryption_key, tok.token.password.session_key_encryption_key_bytes, "\n");
	ph("SIGNATURE  : ", &tok.token.password.signature, ECRYPTFS_PASSWORD_SIG_SIZE, " -- ");
	printf("[%s]\n", tok.token.password.signature);
	ph("SALT       : ", &tok.token.password.salt, ECRYPTFS_SALT_SIZE, "\n");
	
	return 0;
}

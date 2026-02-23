 #ifndef WOODY_H
 #define WOODY_H

 #include "libft.h"
 #include <errno.h>
 #include <fcntl.h>
 #include <sys/mman.h>
 #include <sys/syscall.h>
 #include <stdio.h>
 #include <elf.h>
 #include <stdarg.h>
 #include <string.h>

 //global pour le verbose
 extern int verbose;

 //type de personnaluses
 typedef uint16_t t_arch;
 typedef uint16_t t_endian;
 //t_arch et t_endian c'est le type pour stocker l architecrture (32 ou 64 bites) et l endianess (little or big)

//valeur de elf.h pour savoir comment lire les entree dans elf
#define LENDIAN ELFDATA2LSB
#define BENDIAN ELFDATA2MSB

//definetion des codes de decryptage
#define DECRYPTION_CODE "\x50\x56\x57\x52\x51\x41\x50\x41\x51\xeb\x55\x5e\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x0e\x00\x00\x00\x0f\x05\xb9\x2b\x00\x00\x00\xbe\x04\x00\x00\x00\x48\x8d\x15\x09\x00\x00\x00\x4d\x31\xc0\x48\x31\xc0\xeb\x3d\x5f\x42\x8a\x04\x07\x00\xe0\x30\x02\x48\xff\xc2\x49\xff\xc0\x49\x39\xf0\x75\x06\x80\xc4\x2a\x4d\x31\xc0\xe2\xe5\x41\x59\x41\x58\x59\x5a\x5f\x5e\x58\xe9\x26\x00\x00\x00\xe8\xa6\xff\xff\xff\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\xe8\xbe\xff\xff\xff" //64bites
#define DECRYPTION_CODE_32 "\x50\x56\x57\x52\x51\x53\xeb\x50\x5e\x89\xf1\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xba\x0e\x00\x00\x00\xcd\x80\xb9\x2b\x00\x00\x00\xbe\x04\x00\x00\x00\xe8\x00\x00\x00\x00\x5a\x81\xc2\x0b\x0b\x0b\x0b\x31\xdb\x31\xc0\xeb\x33\x5f\x8a\x04\x1f\x00\xe0\x30\x02\x42\x43\x39\xf3\x75\x05\x80\xc4\x2a\x31\xdb\xe2\xec\x5b\x59\x5a\x5f\x5e\x58\xe9\xd2\xff\xff\xff\xe8\xab\xff\xff\xff\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\xe8\xc8\xff\xff\xff" //32bites
#define CODE_SIZE sizeof(DECRYPTION_CODE) - 1 + KEY_SIZE
#define CODE_SIZE_32 sizeof(DECRYPTION_CODE_32) - 1 + KEY_SIZE
define KEY_SIZE 32
// decryption code: c est le code assembleur injecter dans l elf pour dechiffrer le programme a l execution
//code size = taille du code injecte + taille de la cle de chiffrement
// deux version : 64 bits (Decription_code) et l autre 32 bits

//erreur
#define ERRNO 0
#define ERRNO_PH_TRUNC 1
#define ERROR_TEXT_TRUNC 2
#define ERROR_ARGS 3

//structure principale repersentant un fichier elf ouvert et mappe en memoire
typedef struct s_elf_file
{
    void *base_addr; //debut du fichier mmap (strat of mapped file)
    void *end_addr; //fin du fichier mmap
    void *section_sex; //segement .text
    void *note_section //segemet .note
    char taille_key[KEY_SIZE]; //cle de chiffrement (encryption key)
    off_t file_size; //taille du fichier
    t_arch arch_type //32 ou 64 bits
    t_endian endian_type // little or big endian
    int file_fd; //descripteur de fichier
    int is_key_provided; //1 si cle fournie par l utilisateur, 0 aleatoire
}t_elf_file;




//structure contenant le code a injecter et ses metadonnees
typedef struct s_injection_payload
{
    char *payload_code; //code a injecter
    size_t payload_size; //taille du code
    uint16_t offset_text_size; //offset pour la taille du segement .text
    uint16_t offset_key_size; //offset pour la taille de la cle
    uint16_t offset_text; //offset du segement .text
    uint16_t offset_key; //offset de la cle
    uint16_t offset_jump; //offset du saut (jump)
}t_injection_payload;

//structure pour localiser les segments ou injecter le code dans l elf
typedef struct s_elf_segments
{
    void *base_ptr; //base pointer oh the mapper ELF
    size_t total_size; //total size of the mapped elf
    Elf64_Phdr *data_segement; //premier segement LOAD 6 bits
    Elf64_Phdr *last_segement; //dernier segment LOAD 64 bits
    Elf32_Phdr *data_segement_32; // premier segement LOAD 32 bits
    Elf32_Phdr *last_segement_32; //dernier segement LOAD 32 bits
}t_elf_segements;


//utiliser s_elf_segements pour les pointeurs sur la structure , pas le typedef  t_elf_segements
extern void encryptitation(void *data, uint32_t data_len, void *text, uint32_t len_text);
void encryptitation_code(t_elf_fichier *file);
int parse_key_form_string(const char *key_str, char *key_buffer);
void cle_aleatoire(t_elf_file *file);

//gestion de l endian
uint16_t get_uint16(uint16_t bite, t_endian endian);
int32_t get_uint32(int32_t bite, t_endian endian);
uint32_t get_uint32(uint32_t bite, t_endian endian);
uint64_t get_uint64(uint64_t bite, t_endian endian);
//les fonctions pour lire correctement selon le type de l endian de l elf

//fonctions pour ecrire en gerant l endian
void set_uint16(uint16_t *ptr, uint16_t value, t_endian endian);
void set_uint32(uint32_t *ptr, uint32_t value, t_endian endian);
void set_uint64(uint64_t *ptr, uint64_t value, t_endian endian);

//verbose
void verbose(const char *format, ...);

//manipulation des segements elf
Elf64_Phdr *segement(t_elf_file *file, int (*f)(Elf64_Phdr *));
Elf64_Phdr *last_load_segement(t_elf_file *file);
Elf32_Phdr *segement_32(t_elf_file *file);
Elf32_Phdr *seg_get32(t_elf_file *file, int (*filt)(Elf32_Phdr *));
Elf32_Phdr *get_last_load_segement_32(t_elf_file *file);
//chercher des segement specifique .text .data dans l elf 32 ou 64
int is_text(Elf64_Phdr *phdr);
int is_data(Elf64_Phdr *phdr);
int is_text_32(Elf32_Phdr *phdr);
int is_data_32(Elf32_Phdr *phdr);
//fonctions filtre pour savoir si un segement est .text ou .data


//injection
void injectitation(t_elf_file *file, t_injection_payload *payload);
//injecter le payload (code + cle) dans l elf

//parsing
int paaarsiiing(const char *filename, t_elf_file *file);
void error_w(t_elf_file *file, t_injection_payload *payload, t_elf_segements *segements, int code);


#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Hardcoded credentials
const char* password = "admin1234";
const char* api_key = "sk-cpp-secret-key-xyz";

// Buffer overflow via strcpy
void copy_username(char* input) {
    char buffer[64];
    strcpy(buffer, input);
}

// gets() - removed from C11, always vulnerable
void read_input() {
    char buf[128];
    gets(buf);
}

// sprintf without bounds checking
void build_query(char* user_input) {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", user_input);
}

// Format string vulnerability
void log_message(char* user_input) {
    printf(user_input);
}

// Command injection via system()
void run_scan(char* filename) {
    char cmd[256];
    sprintf(cmd, "scan %s", filename);
    system(cmd);
}

// strcat without bounds checking
void append_path(char* base, char* user_path) {
    strcat(base, user_path);
}

// Unchecked malloc return value
void allocate_buffer(int size) {
    char* buf = malloc(size);
    buf[0] = 'A';
}

// Weak randomness
int generate_token() {
    return rand();
}

// memcpy with potentially unsafe size
void copy_data(char* dst, char* src, int user_size) {
    memcpy(dst, src, user_size);
}
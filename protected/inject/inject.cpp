#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h> // For MD5 hashing
#pragma comment(lib, "bcrypt.lib")

#define MARKER_START "--MD5_START--"
#define MARKER_END "--MD5_END--"
#define MARKER_TOTAL_SIZE 128  // Including marker delimiters and MD5 hashes

// Function prototypes
long find_marker_position(size_t fileSize);
int inject_md5(const char* file);
void calculate_md5(const char* data, size_t size, char* md5_out);
int verify_md5(const char* file);

int main(int argc, char* argv[]) {
    
        printf("Injecting MD5 hash into Project1.exe\n");
        int result = inject_md5(argv[1]);
     
   
    return 0;
}

long find_marker_position(size_t fileSize) {
    return fileSize - MARKER_TOTAL_SIZE; // Place the marker at the end of the file
}

int inject_md5(const char* file) {
    HANDLE hFile = CreateFileA(file, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        perror("Error opening file");
        return -1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        perror("Error creating file mapping");
        return -1;
    }

    char* data = (char*)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!data) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        perror("Error mapping file to memory");
        return -1;
    }

    size_t fileSize = GetFileSize(hFile, NULL);

    // Step 1: Calculate MD5 of the file excluding the marker
    char original_md5[33] = { 0 };
    calculate_md5(data, fileSize - MARKER_TOTAL_SIZE, original_md5);
    printf("Original MD5: %s\n", original_md5);

    // Step 2: Prepare the marker content
    char marker_content[MARKER_TOTAL_SIZE + 1] = { 0 };
    snprintf(marker_content, MARKER_TOTAL_SIZE, "%s%s%s%s", MARKER_START, original_md5, MARKER_END, "\0");

    // Step 3: Inject the marker at the end of the file
    long offset = find_marker_position(fileSize);
    memcpy(data + offset, marker_content, MARKER_TOTAL_SIZE);

    UnmapViewOfFile(data);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}

void calculate_md5(const char* data, size_t size, char* md5_out) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashLength = 0, resultLength = 0;
    unsigned char hash[16]; // MD5 produces 16-byte hashes

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0) != 0) {
        fprintf(stderr, "Failed to open MD5 algorithm provider.\n");
        return;
    }

    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLength, sizeof(DWORD), &resultLength, 0) != 0) {
        fprintf(stderr, "Failed to get MD5 hash length.\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
        fprintf(stderr, "Failed to create MD5 hash object.\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    if (BCryptHashData(hHash, (PUCHAR)data, size, 0) != 0) {
        fprintf(stderr, "Failed to hash data.\n");
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    if (BCryptFinishHash(hHash, hash, hashLength, 0) != 0) {
        fprintf(stderr, "Failed to finish MD5 hash computation.\n");
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    // Convert the hash to a hex string
    for (DWORD i = 0; i < hashLength; i++) {
        snprintf(&md5_out[i * 2], 3, "%02x", hash[i]); // Use snprintf instead of sprintf
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

int verify_md5(const char* file) {
    HANDLE hFile = CreateFileA(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        perror("Error opening file");
        return -1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        perror("Error creating file mapping");
        return -1;
    }

    char* data = (char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!data) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        perror("Error mapping file to memory");
        return -1;
    }

    size_t fileSize = GetFileSize(hFile, NULL);

    // Step 1: Locate the marker and extract the stored MD5
    long offset = find_marker_position(fileSize);
    char marker_content[MARKER_TOTAL_SIZE + 1] = { 0 };
    strncpy_s(marker_content, MARKER_TOTAL_SIZE + 1, data + offset, MARKER_TOTAL_SIZE);

    // Step 2: Verify the marker delimiters
    char* start = strstr(marker_content, MARKER_START);
    char* end = strstr(marker_content, MARKER_END);
    if (!start || !end || end <= start) {
        printf("Marker not found or corrupted.\n");
        UnmapViewOfFile(data);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return -1;
    }

    // Step 3: Extract and verify the original MD5
    char stored_md5[33] = { 0 };
    strncpy_s(stored_md5, 33, start + strlen(MARKER_START), 32);

    char calculated_md5[33] = { 0 };
    calculate_md5(data, fileSize - MARKER_TOTAL_SIZE, calculated_md5);
    printf("Stored MD5: %s\n", stored_md5);
    printf("Calculated MD5: %s\n", calculated_md5);

    if (strcmp(stored_md5, calculated_md5) == 0) {
        printf("MD5 verification successful.\n");
        UnmapViewOfFile(data);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    else {
        printf("MD5 verification failed.\n");
        UnmapViewOfFile(data);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return -1;
    }
}

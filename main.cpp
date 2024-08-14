#include <filesystem>
#include <iostream>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <fstream>

struct Processor {
    std::filesystem::path storage;
    std::filesystem::path assets;


    void processFolder(std::filesystem::path folder = "") {
        for(auto f : std::filesystem::directory_iterator(folder)) {
            if(f.is_directory()) {
                processFolder(f.path());
            } else {
                processFile(f.path());
            }
        }
    }

    void processFile(std::filesystem::path file = "") {
        std::ifstream i(file);

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

        if (!EVP_DigestInit_ex2(mdctx, EVP_get_digestbynid(NID_sha512), NULL)) {
            printf("Message digest initialization failed.\n");
            EVP_MD_CTX_free(mdctx);
            exit(1);
        }

        char buf[8192];
        while(i.good()) {
            i.read(buf, sizeof(buf));
            auto cnt = i.gcount();
            if (!EVP_DigestUpdate(mdctx, buf, cnt)) {
                printf("Message digest finalization failed.\n");
                EVP_MD_CTX_free(mdctx);
                exit(1);
            }
        }

        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len)) {
            printf("Message digest finalization failed.\n");
            EVP_MD_CTX_free(mdctx);
            exit(1);
        }

        std::string sha(2*md_len, '0');
        auto l = sha.length();
        for (int i = 0; i < md_len; i++) {
            snprintf(sha.data() + 2 * i, 3, "%02x", md_value[i]);
        }
        EVP_MD_CTX_free(mdctx);
        std::cout << file << ": " << sha << "\n";
        i.close();
        std::error_code code;
        if(std::filesystem::hard_link_count(storage / sha, code) <= 0 || code.value() != 0) {
            std::filesystem::create_hard_link(file, storage / sha);
            std::cout << file << ": store hardlink to asset\n";
        } else if (!std::filesystem::equivalent(storage / sha, file)) {
            std::cout << file << ": replacing file by hardlink to free up space\n";
            std::filesystem::remove(file);
            std::filesystem::create_hard_link(storage / sha, file);
        }
    }
};

int main(int argc, char** argv) {
    if(argc != 3) {
        return 1;
    }
    std::filesystem::path storage(argv[1]);
    std::filesystem::path assets(argv[2]);
    std::cout << "storage: " << storage.c_str() << "\n";
    std::cout << "assets: " << assets.c_str() << "\n";

    Processor proc;
    proc.assets = assets;
    proc.storage = storage;

    proc.processFolder(assets);
    
    return 0;
}

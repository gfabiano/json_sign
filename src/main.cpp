#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

using json = nlohmann::json;

constexpr size_t PUBLIC_KEY_SIZE = crypto_sign_PUBLICKEYBYTES;
constexpr size_t SECRET_KEY_SIZE = crypto_sign_SECRETKEYBYTES;
constexpr size_t SIGNATURE_SIZE = crypto_sign_BYTES;

std::string to_hex(const std::vector<uint8_t>& data) {
    std::string hex(data.size() * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), data.data(), data.size());
    hex.pop_back(); // Remove null terminator
    return hex;
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    // La dimensione massima possibile in byte è metà dell'input hex
    std::vector<uint8_t> bytes(hex.size() / 2);

    size_t bin_len = 0;
    int ret = sodium_hex2bin(
        bytes.data(),            // output buffer
        bytes.size(),            // max size of output buffer
        hex.c_str(),             // input hex string
        hex.size(),              // hex length
        nullptr,                 // ignora caratteri speciali
        &bin_len,                // lunghezza reale prodotta
        nullptr                  // ignorato
    );

    if (ret != 0) {
        spdlog::error("Invalid hex string for sodium_hex2bin");
        return {};
    }

    bytes.resize(bin_len);
    return bytes;
}

std::string to_base64(const std::vector<uint8_t>& data) {
    size_t b64_len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string b64(b64_len, '\0');
    sodium_bin2base64(b64.data(), b64_len, data.data(), data.size(), sodium_base64_VARIANT_ORIGINAL);
    b64.pop_back(); // Remove null terminator
    return b64;
}

std::vector<uint8_t> from_base64(const std::string& b64) {
    std::vector<uint8_t> data(b64.size()); // Max possible size
    size_t bin_len;
    if (sodium_base642bin(data.data(), data.size(), b64.c_str(), b64.size(),
                         nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        spdlog::error("Invalid base64 string");
        return {};
    }
    data.resize(bin_len);
    return data;
}

// Canonicalize JSON by dumping with sorted keys and no spaces
std::string canonicalize_json(const json& j) {
    // Remove signature field if present for canonicalization
    json canonical = j;
    if (canonical.contains("signature")) {
        canonical.erase("signature");
    }
    
    // Dump with sorted keys, no spaces
    return canonical.dump(-1, ' ', false, json::error_handler_t::strict);
}

struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

KeyPair generate_keypair() {
    KeyPair keypair;
    keypair.public_key.resize(PUBLIC_KEY_SIZE);
    keypair.secret_key.resize(SECRET_KEY_SIZE);
    
    if (crypto_sign_keypair(keypair.public_key.data(), keypair.secret_key.data()) != 0) {
        spdlog::error("Failed to generate keypair");
        keypair.public_key.clear();
        keypair.secret_key.clear();
    }
    
    return keypair;
}

std::vector<uint8_t> sign_data(const std::vector<uint8_t>& data, const std::vector<uint8_t>& secret_key) {
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    unsigned long long sig_len;
    
    if (crypto_sign_detached(signature.data(), &sig_len, data.data(), data.size(), secret_key.data()) != 0) {
        spdlog::error("Failed to sign data");
        return {};
    }
    
    return signature;
}

bool verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, 
                     const std::vector<uint8_t>& public_key) {
    return crypto_sign_verify_detached(signature.data(), data.data(), data.size(), public_key.data()) == 0;
}

bool sign_manifest(const std::string& manifest_path, const std::string& key_path, 
                   const std::string& output_path) {
    // Read or generate keypair
    std::vector<uint8_t> secret_key;
    std::vector<uint8_t> public_key;
    
    std::string secret_key_path = key_path + ".secret";
    std::string public_key_path = key_path + ".public";
    
    std::ifstream secret_file(secret_key_path);
    if (secret_file) {
        spdlog::info("Using existing keypair from: {}.*", key_path);
        std::string hex_secret((std::istreambuf_iterator<char>(secret_file)), {});
        hex_secret.erase(std::remove_if(hex_secret.begin(), hex_secret.end(), ::isspace), hex_secret.end());
        secret_key = from_hex(hex_secret);
        
        if (secret_key.empty()) {
            spdlog::error("Failed to read secret key from: {}", secret_key_path);
            return false;
        }
        
        std::ifstream public_file(public_key_path);
        if (!public_file) {
            spdlog::error("Public key file not found: {}", public_key_path);
            return false;
        }
        std::string hex_public((std::istreambuf_iterator<char>(public_file)), {});
        hex_public.erase(std::remove_if(hex_public.begin(), hex_public.end(), ::isspace), hex_public.end());
        public_key = from_hex(hex_public);
        
        if (public_key.empty()) {
            spdlog::error("Failed to read public key from: {}", public_key_path);
            return false;
        }
    } else {
        spdlog::info("Generating new Ed25519 keypair...");
        auto keypair = generate_keypair();
        if (keypair.secret_key.empty() || keypair.public_key.empty()) {
            return false;
        }
        secret_key = keypair.secret_key;
        public_key = keypair.public_key;
        
        std::ofstream out_secret(secret_key_path);
        if (!out_secret) {
            spdlog::error("Cannot write secret key to: {}", secret_key_path);
            return false;
        }
        out_secret << to_hex(secret_key);
        spdlog::info("Secret key saved to: {}", secret_key_path);
        
        std::ofstream out_public(public_key_path);
        if (!out_public) {
            spdlog::error("Cannot write public key to: {}", public_key_path);
            return false;
        }
        out_public << to_hex(public_key);
        spdlog::info("Public key saved to: {}", public_key_path);
    }
    
    // Read and parse JSON manifest
    std::ifstream manifest_file(manifest_path);
    if (!manifest_file) {
        spdlog::error("Cannot open manifest file: {}", manifest_path);
        return false;
    }
    
    json manifest;
    try {
        manifest_file >> manifest;
    } catch (const json::exception& e) {
        spdlog::error("Invalid JSON in manifest: {}", e.what());
        return false;
    }
    
    // Canonicalize JSON (remove signature fields if present)
    std::string canonical = canonicalize_json(manifest);
    spdlog::debug("Canonical JSON: {}", canonical);
    
    // Sign the canonical JSON
    std::vector<uint8_t> data(canonical.begin(), canonical.end());
    auto signature = sign_data(data, secret_key);
    
    if (signature.empty()) {
        return false;
    }
    
    // Attach signature to JSON
    manifest["signature"] = to_base64(signature);
    
    // Write signed manifest
    std::ofstream output_file(output_path);
    if (!output_file) {
        spdlog::error("Cannot write output file: {}", output_path);
        return false;
    }
    output_file << manifest.dump(2) << std::endl;
    
    spdlog::info("✓ Manifest signed successfully!");
    spdlog::info("Public key: {}", to_hex(public_key));
    spdlog::info("Signature: {}", to_hex(signature));
    spdlog::info("Signed manifest written to: {}", output_path);
    
    return true;
}

bool verify_manifest(const std::string& signed_manifest_path, const std::string& key_path) {
    // Read and parse signed JSON manifest
    std::ifstream manifest_file(signed_manifest_path);
    if (!manifest_file) {
        spdlog::error("Cannot open manifest file: {}", signed_manifest_path);
        return false;
    }
    
    json manifest;
    try {
        manifest_file >> manifest;
    } catch (const json::exception& e) {
        spdlog::error("Invalid JSON in manifest: {}", e.what());
        return false;
    }
    
    // Check for signature field
    if (!manifest.contains("signature")) {
        spdlog::error("Manifest does not contain a signature field");
        return false;
    }
    
    // Get signature
    std::string sig_b64 = manifest["signature"];
    auto signature = from_base64(sig_b64);
    
    if (signature.empty()) {
        spdlog::error("Failed to decode signature from manifest");
        return false;
    }
    
    // Read public key from file
    std::string public_key_path = key_path + ".public";
    std::ifstream key_file(public_key_path);
    if (!key_file) {
        spdlog::error("Public key file not found: {}", public_key_path);
        return false;
    }
    spdlog::info("Using public key from: {}", public_key_path);
    std::string hex_key((std::istreambuf_iterator<char>(key_file)), {});
    hex_key.erase(std::remove_if(hex_key.begin(), hex_key.end(), ::isspace), hex_key.end());
    auto public_key = from_hex(hex_key);
    
    if (public_key.empty()) {
        spdlog::error("Failed to read public key from: {}", public_key_path);
        return false;
    }
    
    // Canonicalize JSON (removes signature field)
    std::string canonical = canonicalize_json(manifest);
    spdlog::debug("Canonical JSON: {}", canonical);
    
    // Verify signature
    std::vector<uint8_t> data(canonical.begin(), canonical.end());
    
    spdlog::info("Verifying signature...");
    spdlog::info("Public key: {}", to_hex(public_key));
    spdlog::info("Signature: {}", to_hex(signature));
    
    if (verify_signature(data, signature, public_key)) {
        spdlog::info("✓ Signature verification PASSED");
        spdlog::info("The manifest is authentic and unmodified.");
        return true;
    } else {
        spdlog::error("✗ Signature verification FAILED");
        spdlog::error("The manifest may have been tampered with!");
        return false;
    }
}

int main(int argc, char** argv) {
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    CLI::App app{"Manifest Signing Tool - Ed25519 signatures with JSON"};
    
    std::string manifest_file;
    std::string key_file = "manifest.key";
    std::string output_file = "manifest.signed.json";
    
    // Sign subcommand
    auto sign_cmd = app.add_subcommand("sign", "Sign a JSON manifest file");
    sign_cmd->add_option("manifest", manifest_file, "JSON manifest file to sign")
        ->required()
        ->check(CLI::ExistingFile);
    sign_cmd->add_option("-k,--key", key_file, "Key file prefix (generates .secret and .public)")
        ->default_val("manifest.key");
    sign_cmd->add_option("-o,--output", output_file, "Output signed manifest file")
        ->default_val("manifest.signed.json");
    
    // Verify subcommand
    auto verify_cmd = app.add_subcommand("verify", "Verify a signed JSON manifest");
    verify_cmd->add_option("manifest", manifest_file, "Signed JSON manifest file to verify")
        ->required()
        ->check(CLI::ExistingFile);
    verify_cmd->add_option("-k,--key", key_file, "Key file prefix (reads .public)")
        ->required();
    
    app.require_subcommand(1);
    
    CLI11_PARSE(app, argc, argv);
    
    try {
        if (sign_cmd->parsed()) {
            sign_manifest(manifest_file, key_file, output_file);
        } else if (verify_cmd->parsed()) {
            verify_manifest(manifest_file, key_file);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

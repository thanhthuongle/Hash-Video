#include <../cryptopp/sha.h>
#include <../cryptopp/filters.h>
#include <../cryptopp/hex.h>
#include <fstream>
#include <vector>
#include <iostream>

using namespace CryptoPP;
using namespace std;

// Hàm tính giá trị băm h0 của file
string computeFileHash(const string& filePath) {
    fstream file(filePath, fstream::in | fstream::binary | fstream::ate);
    if (!file.is_open()) {
        throw runtime_error("Không thể mở file");
    }

    int fileSize = file.tellg();
    int numBlocks = (fileSize + 1023) / 1024; // Tính số lượng khối
    string hashValue = ""; // Giá trị băm cuối cùng

    for (int i = numBlocks - 1; i >= 0; --i) {
        file.seekg(i * 1024);
        vector<char> block(1024);
        if (i == numBlocks - 1) { // Khối cuối cùng có thể ngắn hơn
            block.resize(fileSize % 1024 ? fileSize % 1024 : 1024);
        }
        file.read(block.data(), block.size());

        // Thêm giá trị băm của khối trước (nếu có) vào dữ liệu hiện tại
        string data(block.begin(), block.end());
        data += hashValue;

        // Tính giá trị băm mới
        SHA256 hash;
        byte digest[SHA256::DIGESTSIZE];
        hash.CalculateDigest(digest, (const byte*)data.data(), data.size());
        hashValue.assign((char*)digest, SHA256::DIGESTSIZE);
    }

    // Chuyển giá trị băm cuối cùng sang dạng hex để dễ đọc
    string hexHash;
    HexEncoder encoder;
    encoder.Attach(new StringSink(hexHash));
    encoder.Put((const byte*)hashValue.data(), hashValue.size());
    encoder.MessageEnd();

    return hexHash;
}

string normalizePath(const string& filepath) {
    std::string normalizedPath = filepath;
    // Thay thế backslash bằng slash
    for (auto& ch : normalizedPath) {
        if (ch == '\\') {
            ch = '/';
        }
    }
    return normalizedPath;
}

int main() {
    string filePath; // = "birthday.mp4"; // Đường dẫn tới file video
    cout << "Nhập đường dẫn tới video: ";
    getline(cin, filePath);
    filePath = normalizePath(filePath);
    try {
        string fileHash = computeFileHash(filePath);
        cout << "Giá trị băm h0 của file là: " << fileHash << endl;
    }
    catch (const exception& e) {
        cerr << "Lỗi: " << e.what() << endl;
    }

    return 0;
}
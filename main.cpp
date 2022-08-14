#include "iostream"
#include <iostream>
#include <string>
#include "cpr/cpr.h"
#include "cstring"

using namespace std;

char text[120];

vector<string> registration(const string& key)  {
    sprintf(text,R"({"key":"value"})", key.c_str());
    cpr::Response r = cpr::Post(cpr::Url{"You URL =)"},
                                cpr::Body{text},
                                cpr::Header{{"Content-Type", "application/json"}});
    vector<string>aqua;
    if (r.text[21] == 't'){
        int private_key_n = r.text.find("private_key");
        int server_public_key_n = r.text.find("server_public_key");
        int public_key_n = r.text.find("\"public_key");
        int server_address_n = r.text.find("serverAddress");
        int ip_client_n = r.text.find("ip-client");
        int allowed_ips_n = r.text.find("allowed-ips");

        int pk = r.text.substr(private_key_n+14).find('\"');
        string private_key = r.text.substr(private_key_n+14,pk);
        aqua.push_back(private_key);

        int pub_k = r.text.substr(public_key_n+14).find('\"');
        string public_key = r.text.substr(public_key_n+14,pub_k);
        aqua.push_back(public_key);

        int spk = r.text.substr(server_public_key_n+20).find('\"');
        string server_public_key = r.text.substr(server_public_key_n+20,spk);
        aqua.push_back(server_public_key);

        int sa = r.text.substr(server_address_n+20).find('\"');
        string server_address = r.text.substr(server_address_n+20,sa);
        aqua.push_back(server_address);

        int ic = r.text.substr(ip_client_n+20).find('\"');
        string ip_client = r.text.substr(ip_client_n+12,sa);
        aqua.push_back(ip_client);

        int ai = r.text.substr(allowed_ips_n+20).find('\"');
        string allowed_ips = r.text.substr(allowed_ips_n+16,sa);
        aqua.push_back(allowed_ips);


        return aqua;
    }else{
        cout << "Регистрация завершилась ошибкой!" << endl;
    }
    return {};
}

void create_file(const string& private_key){
    std::ofstream outfile ("/home/privatekey");
    outfile << private_key << std::endl;
    outfile.close();
}

void authorization(const string& ip,const basic_string<char>& deviceId){
    sprintf(text,R"({"key":"%s","ip":"%s"})", deviceId.c_str(),ip.c_str());
    cpr::Response r = cpr::Post(cpr::Url{"You URL =)"},
                                cpr::Body{text},
                                cpr::Header{{"Content-Type", "application/json"}});
    if (r.text[21] == 't'){
        cout << "Авторизация прошла успешно!" << endl;
    }else{
        cout << "Авторизация завершилась ошибкой!" << endl;
    }
}

basic_string<char> readConfig(const string& path){
    ifstream file (path);
    string line;
    if ( file.is_open() ) {
        while ( file ) {
            std::getline (file, line);
            if (line.length() > 8){
                if(line[0] == 's' && line[1] == 'e' && line[2] =='r' && line[6] == 'n'){
                    string serialNum = line.erase(0, 9);
                    cout << serialNum << endl;
                    return serialNum;
                }
            }
        }
    }
    return {};
}

string fileFind(){
    string path = "Camera config";
    basic_string<char> serialNum = readConfig(path);
    if (!serialNum.empty()){
        cout << "Пришло: " << serialNum << endl;
        return serialNum;
    }else{
        cout << "Серийный номер не был получен [Неправильный адрес]" << endl;
    }
    return {};
}

std::string execCommand(const std::string& cmd, int& out_exitStatus)
{
    out_exitStatus = 0;
    auto pPipe = ::popen(cmd.c_str(), "r");
    if(pPipe == nullptr)
    {
        throw std::runtime_error("Cannot open pipe");
    }
    std::array<char, 256> buffer{};
    std::string result;
    while(not std::feof(pPipe))
    {
        auto bytes = std::fread(buffer.data(), 1, buffer.size(), pPipe);
        result.append(buffer.data(), bytes);
    }
    auto rc = ::pclose(pPipe);
    if(WIFEXITED(rc))
    {
        out_exitStatus = WEXITSTATUS(rc);
    }
    return result;
}

void runBin(vector<string> data) {
    int exitStatus = 0;
    string command = "Root for VPN " + data[0] + data[1] + "ip" + "allowed-ips" + data[4];
    auto result = execCommand(command, exitStatus);
    cout << result;
}

int main() {
    std::string serialNum = fileFind();
    vector<string> camId = registration("Camera number");
    for (auto elem : camId){
        cout << elem << endl;
    }
    if (!camId.empty()){
        runBin(camId);
        authorization(camId,serialNum);
    }
    return 0;
}



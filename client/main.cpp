
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <unordered_map>
#include <algorithm>

#include "ServerConnection.h"
#include "FileConfig.h"
#include "Protocol.h"
#include "Encryption.h"
#include "Message.h"
#include "Utils.h"

// Every other user will be saved in RAM with his:
// UUID, public-key, symetric key
struct PeerInfo
{
    Uuid id{};
    std::string publicKeyBase64;
    std::array<uint8_t, 16> symmetricKey{};
    bool hasSymmetricKey = false;
};

//maping of username and PeerInfo
static std::unordered_map<std::string, PeerInfo> g_peers;

// ------------------------- UI -------------------------

static void showMenu()
{
    std::cout << "\n-----------------------------------------\n";
    std::cout << "MessageU client at your service.\n\n"
                 "110) Register\n"
                 "120) Request for clients list\n"
                 "130) Request for public key\n"
                 "140) Request for waiting messages\n"
                 "150) Send a text message\n"
                 "151) Send a request for symmetric key\n"
                 "152) Send your symmetric key\n"
                 "0)   Exit client\n";
}

// ------------------------- Helpers -------------------------

// handles a complete request–response exchange with a server using a binary protocol
// conn- the socket
// req- raw bytes of the request to send
// hdr- output parameter (header)
// payload- output parameter (body)
// returns true if operation succeeded or false if not
static bool sendAndRecv(ServerConnection &conn,
                        const std::vector<uint8_t> &req,
                        ServerReply &hdr,
                        std::vector<uint8_t> &payload)
{
    if (!conn.sendAll(req))
        return false;

    uint8_t h[7];
    if (!conn.recvExact(h, 7))
        return false;
    hdr = Protocol::parseServerReplyHeader(h);

    payload.clear();
    if (hdr.payloadSize)
    {
        payload.resize(hdr.payloadSize);
        if (!conn.recvExact(payload.data(), static_cast<int>(payload.size())))
            return false;
    }
    return true;
}

// Try to find a username by its 16-byte client id from our cache
static bool tryFindNameById(const Uuid &id, std::string &outName)
{
    for (const auto &kv : g_peers)
    {
        if (kv.second.id == id)
        {
            outName = kv.first;
            return true;
        }
    }
    return false;
}

//This function requests and updates the local list of registered clients (users) from the server.
// It ensures the global g_peers map (which holds known users, their IDs, and possibly public/symmetric keys) is synchronized with the latest data from the server.
// Asks the server for the list of registered users
// Receives and verifies the reply
//parse the list of users (userrname,UUID)
// update local cache g_peers with that info
// returns true if successful
static bool refreshClientsList(ServerConnection &conn, const Uuid &myId)
{
    auto req = Protocol::buildClientsListReq(myId);

    ServerReply reply{};
    std::vector<uint8_t> payload;
    if (!sendAndRecv(conn, req, reply, payload) ||
        !Protocol::isOk(reply, CODE_CLIENTS_LIST_OK))
    {
        return false;
    }

    auto entries = Protocol::parseClientsListPayload(payload);
    for (const auto &e : entries)
    {
        auto it = g_peers.find(e.name);
        if (it == g_peers.end())
        {
            PeerInfo pi;
            pi.id = e.id;
            g_peers.emplace(e.name, std::move(pi));
        }
        else
        {
            it->second.id = e.id; // update id; keep existing pub/symmetric keys
        }
    }
    return true;
}

// ------------------------- Main -------------------------

int main()
{
    // 1) read server address
    std::string serverIp;
    unsigned short serverPort = 0;
    try
    {
        auto srv = FileConfig::readServerInfo();
        serverIp = srv.first;
        serverPort = srv.second;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Failed to read server.info: " << ex.what() << "\n";
        return 1;
    }

    // 2) connect
    ServerConnection conn(serverIp, serverPort);
    if (!conn.connectToServer())
    {
        std::cerr << "Unable to connect to " << serverIp << ":" << serverPort << "\n";
        return 1;
    }
    std::cout << "Connected to " << serverIp << ":" << serverPort << "\n";

    // 3) menu loop
    for (;;)
    {
        showMenu();
        std::cout << "\n> ";
        std::string choice;
        if (!std::getline(std::cin, choice))
            break;

            //EXIT
        if (choice == "0")
        {
            std::cout << "Bye.\n";
            break;
        }

        // 110) Register
        else if (choice == "110")
        {
            if (FileConfig::myInfoExists())
            {
                std::cerr << "Already registered. 'my.info' exists.\n";
                continue;
            }

            std::cout << "Enter username (ASCII, <=255): ";
            std::string username;
            if (!std::getline(std::cin, username) || username.empty())
            {
                std::cerr << "Invalid username.\n";
                continue;
            }

            if (username.size() > REG_NAME_LEN)
            {
                std::cout << "[INFO] Username longer than " << REG_NAME_LEN
                          << " chars; it will be truncated on registration.\n";
            }

            // Prepare registration
            Uuid zero{};
            zero.fill(0);

            auto kp = Encryption::GenerateRsaKeypair1024(); // produce private key and public key
            //build request protocol
            auto req = Protocol::buildRegistration(zero, username, kp.publicKeyBase64);

            ServerReply reply{};
            std::vector<uint8_t> payload;
            //sending the message to the server
            if (!sendAndRecv(conn, req, reply, payload))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            //check the reposinse from the server
            if (Protocol::isOk(reply, CODE_REGISTRATION_OK) && payload.size() == CLIENT_ID_LEN)
            {
                Uuid myId{};
                //fetching id
                std::copy_n(payload.data(), CLIENT_ID_LEN, myId.data());
                try
                {
                    //save in my.info
                    FileConfig::writeMyInfo(username, myId, kp.privateKeyBase64);
                    std::cout << "Registration successful. my.info created.\n";
                }
                catch (const std::exception &ex)
                {
                    std::cerr << "Registration succeeded but saving key failed: " << ex.what() << "\n";
                }
            }
            else
            {
                std::cerr << "Server responded with error or unexpected payload.\n";
            }
        }

        // 120) Request for clients list
        else if (choice == "120")
        {
            std::array<uint8_t, 16> myId{};
            //fetching my UUID
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Not registered. Please run 110 first.\n";
                continue;
            }

            //prepare request for server
            auto req = Protocol::buildClientsListReq(myId);

            ServerReply reply{};
            std::vector<uint8_t> payload;
            //sending
            if (!sendAndRecv(conn, req, reply, payload) ||
                !Protocol::isOk(reply, CODE_CLIENTS_LIST_OK))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            auto entries = Protocol::parseClientsListPayload(payload);
            g_peers.clear();

            if (entries.empty())
            {
                std::cout << "No other clients registered.\n";
            }
            else
            {
                std::cout << "Registered clients:\n";
                for (const auto &e : entries)
                {
                    PeerInfo pi;
                    pi.id = e.id;
                    g_peers[e.name] = pi;
                    std::cout << " - " << e.name << "\n";
                }
            }
        }

        // 130) Request for public key
        else if (choice == "130")
        {
            std::array<uint8_t, 16> myId{};
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Not registered. Please run 110 first.\n";
                continue;
            }

            std::cout << "Enter destination username: ";
            std::string toName;
            if (!std::getline(std::cin, toName) || toName.empty())
                continue;

            auto it = g_peers.find(toName);
            if (it == g_peers.end())
            {
                std::cerr << "Unknown user. Run 120 to refresh the clients list.\n";
                continue;
            }
            auto targetId = it->second.id;

            auto req = Protocol::buildPublicKeyReq(myId, targetId);

            ServerReply reply{};
            std::vector<uint8_t> payload;
            if (!sendAndRecv(conn, req, reply, payload))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            if (!Protocol::isOk(reply, CODE_PUBLIC_KEY_OK) ||
                payload.size() != (CLIENT_ID_LEN + RESP_PUBKEY_LEN))
            {

                std::cerr << "server responded with an error\n";
                continue;
            }

            // payload: [16B clientId][400B base64-ascii + NUL padding]
            std::string b64(reinterpret_cast<const char *>(payload.data() + 16),
                            RESP_PUBKEY_LEN);
            auto nullPos = b64.find('\0');
            if (nullPos != std::string::npos)
                b64.erase(nullPos);

            it->second.publicKeyBase64 = b64;
            std::cout << "Public key cached for " << toName << ".\n";
        }

        // 140) Request for waiting messages (pull inbox)
        else if (choice == "140")
        {
            std::array<uint8_t, 16> myId{};
            std::string myName;
            std::string myPrivB64;
            // reading my info
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
                myPrivB64 = std::get<2>(me);
            }
            catch (...)
            {
                std::cerr << "Not registered. Please run 110 first.\n";
                continue;
            }

            auto req = Protocol::buildPullWaitingReq(myId);

            ServerReply rep{};
            std::vector<uint8_t> payload;
            //sending to server
            if (!sendAndRecv(conn, req, rep, payload) ||
                !Protocol::isOk(rep, CODE_PULL_WAITING_OK))
            {

                std::cerr << "server responded with an error\n";
                continue;
            }

            auto messages = Protocol::parseWaitingMessagesPayload(payload);
            for (const auto &wm : messages)
            {
                std::string fromName;
                // see if you can find the username by the id
                bool haveName = tryFindNameById(wm.fromId, fromName);
                if (!haveName)
                {
                    // Auto-refresh the clients list once
                    // if it cant find the username it apply the request for users list (option 120)
                    if (!refreshClientsList(conn, myId) || !tryFindNameById(wm.fromId, fromName))
                    {
                        fromName = toHex32(wm.fromId);
                        std::cout << "From: " << fromName << "  [warning: username was not found]\nContent:\n";
                    }
                    else
                    {
                        std::cout << "From: " << fromName << "\nContent:\n";
                    }
                }
                else
                {
                    std::cout << "From: " << fromName << "\nContent:\n";
                }

                // Analyzing the messages
                if (wm.type == 1)
                {
                    std::cout << "Request for symmetric key\n";
                }
                // symetric key was sent
                else if (wm.type == 2)
                {
                    bool ok = false;
                    // decrypt it with the private key
                    auto recovered = Encryption::RsaDecryptOaepWithBase64Priv(myPrivB64, wm.content, ok);
                    if (!ok || recovered.size() < 16)
                    {
                        std::cerr << "Failed to decrypt symmetric key.\n";
                    }
                    else
                    {
                        auto &peer = g_peers[fromName]; // creates if not exists
                        std::copy_n(recovered.begin(), 16, peer.symmetricKey.begin());
                        peer.hasSymmetricKey = true;
                        std::cout << "Symmetric key stored for " << fromName << ".\n";
                    }
                }
                // text message was sent
                else if (wm.type == 3)
                {
                    auto it = g_peers.find(fromName);
                    if (it == g_peers.end() || !it->second.hasSymmetricKey)
                    {
                        std::cout << "can't decrypt message\n";
                    }
                    else
                    {
                        bool ok = false;
                        //decrypt with symetric key
                        auto plain = Encryption::AesCbcDecryptZeroIV(it->second.symmetricKey, wm.content, ok);
                        if (ok)
                        {
                            std::string text(plain.begin(), plain.end());
                            std::cout << text << "\n";
                        }
                        else
                        {
                            std::cout << "can't decrypt message\n";
                        }
                    }
                }
                else
                {
                    std::cout << "(unknown type)\n";
                }
                std::cout << "------<EOM>-------\n\n";
            }
        }

        // 150) Send a text message
        else if (choice == "150")
        {
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Not registered. Please run 110 first.\n";
                continue;
            }

            std::cout << "Enter destination username: ";
            std::string toName;
            if (!std::getline(std::cin, toName) || toName.empty())
                continue;

            auto it = g_peers.find(toName);
            if (it == g_peers.end())
            {
                std::cerr << "User not found. Please run option 120 to refresh list.\n";
                continue;
            }
            auto targetId = it->second.id;

            if (!it->second.hasSymmetricKey)
            {
                std::cerr << "No symmetric key with " << toName << ". Use 151/152 first.\n";
                continue;
            }

            std::cout << "Enter message text: ";
            std::string text;
            if (!std::getline(std::cin, text))
                continue;

            std::vector<uint8_t> plain(text.begin(), text.end());
            auto cipher = Encryption::AesCbcEncryptZeroIV(it->second.symmetricKey, plain);

            auto req = Protocol::buildSendMessageReq(myId, targetId, 3 /*text*/, cipher);

            ServerReply rep{};
            std::vector<uint8_t> payload;
            if (!sendAndRecv(conn, req, rep, payload) ||
                !Protocol::isSendAck(rep))
            {

                std::cerr << "server responded with an error\n";
                continue;
            }
            std::cout << "Message sent to " << toName << ".\n";
        }

        // 151) Send a request for symmetric key
        else if (choice == "151")
        {
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Not registered. Please run 110 first.\n";
                continue;
            }

            std::cout << "Enter destination username: ";
            std::string toName;
            if (!std::getline(std::cin, toName) || toName.empty())
                continue;

            auto it = g_peers.find(toName);
            if (it == g_peers.end())
            {
                std::cerr << "Unknown user. Run 120 to refresh the clients list.\n";
                continue;
            }
            auto toId = it->second.id;

            std::vector<uint8_t> empty;
            auto req = Protocol::buildSendMessageReq(myId, toId, 1, empty);

            ServerReply rep{};
            std::vector<uint8_t> payload;
            if (!sendAndRecv(conn, req, rep, payload) ||
                !Protocol::isSendAck(rep))

            {

                std::cerr << "server responded with an error\n";
                continue;
            }
            std::cout << "Symmetric key request sent to " << toName << ".\n";
        }

        // 152) Send your symmetric key
        else if (choice == "152")
        {
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Not registered. Please run 110 first.\n";
                continue;
            }

            std::cout << "Enter destination username: ";
            std::string toName;
            if (!std::getline(std::cin, toName) || toName.empty())
                continue;

            auto it = g_peers.find(toName);
            if (it == g_peers.end())
            {
                std::cerr << "Unknown user. Run 120 to refresh the clients list.\n";
                continue;
            }
            auto toId = it->second.id;

            if (it->second.publicKeyBase64.empty())
            {
                std::cerr << "No public key for " << toName << ". Run 130 first.\n";
                continue;
            }

            // ensure we have a symmetric key for this peer (generate once)
            if (!it->second.hasSymmetricKey)
            {
                it->second.symmetricKey = Encryption::GenerateAesKey();
                it->second.hasSymmetricKey = true;
            }

            // encrypt the 16B AES key with peer's RSA public key (base64)
            std::vector<uint8_t> keyRaw(it->second.symmetricKey.begin(), it->second.symmetricKey.end());
            auto keyEnc = Encryption::RsaEncryptOaepWithBase64Pub(it->second.publicKeyBase64, keyRaw);

            dumpHexPrefix(keyEnc, 16);
            std::cout << "\n";

            auto req = Protocol::buildSendMessageReq(myId, toId, 2 , keyEnc);

            ServerReply rep{};
            std::vector<uint8_t> payload;
            if (!sendAndRecv(conn, req, rep, payload) ||
                !Protocol::isSendAck(rep))
            {

                std::cerr << "server responded with an error\n";
                continue;
            }
            std::cout << "Symmetric key sent to " << toName << ".\n";
        }

        else
        {
            std::cout << "Unknown option.\n";
        }
    }

    return 0;
}

/**
 * Copyright (C) 2019 Xilinx, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <string>
#include <cstring>
#include <iostream>
#include <map>
#include <functional>
#include <getopt.h>

#include "flasher.h"
#include "core/pcie/linux/scan.h"
#include "core/common/sensor.h"
#include "xbmgmt.h"

// For backward compatibility
const char *subCmdXbutilFlashDesc = "";
const char *subCmdXbutilFlashUsage =
    "[-d mgmt-bdf] -m primary_mcs [-n secondary_mcs] [-o bpi|spi]\n"
    "[-d mgmt-bdf] -a <all | shell> [-t timestamp]\n"
    "[-d mgmt-bdf] -p msp432_firmware\n"
    "scan [-v]\n";

const char *subCmdFlashDesc = "Update SC firmware or shell on the device";
const char *subCmdFlashUsage =
    "--scan [--verbose|--json]\n"
    "--update [--shell name [--id id]] [--card bdf] [--force]\n"
    "--factory_reset [--card bdf]\n\n"
    "Experts only:\n"
    "--shell --path file --card bdf [--type flash_type]\n"
    "--sc_firmware --path file --card bdf";

#define fmt_str		"    "
#define DEV_TIMEOUT	60

static int scanDevices(bool verbose, bool json)
{
    unsigned total = pcidev::get_dev_total(false);

    if (total == 0) {
        std::cout << "No card is found!" << std::endl;
        return 0;
    }

    for(unsigned i = 0; i < total; i++) {
        Flasher f(i);
        if (!f.isValid())
            continue;

        DSAInfo board = f.getOnBoardDSA();
        std::vector<DSAInfo> installedDSA = f.getInstalledDSA();
        BoardInfo info;
        const auto getinfo_res = f.getBoardInfo(info);
        if (json) {
            const std::string card = "card" + std::to_string(i);
            if (!installedDSA.empty()) {
                std::stringstream shellpackage;
                for (auto& d : installedDSA)
                    shellpackage << d << "; ";
                sensor_tree::put(card + ".shellpackage", shellpackage.str());
            }
            if (getinfo_res == 0) {
                sensor_tree::put(card + ".name", info.mName);
                sensor_tree::put(card + ".serial", info.mSerialNum);
                sensor_tree::put(card + ".config_mode", info.mConfigMode);
                sensor_tree::put(card + ".fan_presence", info.mFanPresence);
                sensor_tree::put(card + ".max_power", info.mMaxPower);
                sensor_tree::put(card + ".mac0", info.mMacAddr0);
                sensor_tree::put(card + ".mac1", info.mMacAddr1);
                sensor_tree::put(card + ".mac2", info.mMacAddr2);
                sensor_tree::put(card + ".mac3", info.mMacAddr3);
            }
        } else {
            std::cout << "Card [" << f.sGetDBDF() << "]" << std::endl;
            std::cout << fmt_str << "Card type:\t\t" << board.board << std::endl;
            std::cout << fmt_str << "Flash type:\t\t" << f.sGetFlashType() << std::endl;
            std::cout << fmt_str << "Flashable partition running on FPGA:" << std::endl;
            std::cout << fmt_str << fmt_str << board << std::endl;

            if (!board.uuids.empty() && verbose)
            {
                std::cout << fmt_str << fmt_str << fmt_str << "Logic UUID:" << std::endl;
                std::cout << fmt_str << fmt_str << fmt_str << board.uuids[0] << std::endl;
            }
            std::cout << fmt_str << "Flashable partitions installed in system:\t";
            if (!installedDSA.empty()) {
                for (auto& d : installedDSA)
                {
                    std::cout << std::endl << fmt_str << fmt_str << d;
                    if (!d.uuids.empty() && verbose)
                    {
                        std::cout << std::endl;
                        std::cout << fmt_str << fmt_str << fmt_str << "Logic UUID:" << std::endl;
                        std::cout << fmt_str << fmt_str << fmt_str << d.uuids[0];
                    }
                }
            } else {
                std::cout << "(None)";
            }
            std::cout << std::endl;
            if (verbose && getinfo_res == 0) {
                std::cout << fmt_str << "Card name\t\t\t" << info.mName << std::endl;
#if 0   // Do not print out rev until further notice
                std::cout << "\tCard rev\t\t" << info.mRev << std::endl;
#endif
                std::cout << fmt_str << "Card S/N: \t\t\t" << info.mSerialNum << std::endl;
                std::cout << fmt_str << "Config mode: \t\t" << info.mConfigMode << std::endl;
                std::cout << fmt_str << "Fan presence:\t\t" << info.mFanPresence << std::endl;
                std::cout << fmt_str << "Max power level:\t\t" << info.mMaxPower << std::endl;
                std::cout << fmt_str << "MAC address0:\t\t" << info.mMacAddr0 << std::endl;
                std::cout << fmt_str << "MAC address1:\t\t" << info.mMacAddr1 << std::endl;
                std::cout << fmt_str << "MAC address2:\t\t" << info.mMacAddr2 << std::endl;
                std::cout << fmt_str << "MAC address3:\t\t" << info.mMacAddr3 << std::endl;
            }
            std::cout << std::endl;
        }
    }

    if (json)
        sensor_tree::json_dump( std::cout );

    return 0;
}

static int writeSCImage(Flasher &flasher, const char *file)
{
    int ret = 0;

    std::shared_ptr<firmwareImage> bmc =
       std::make_shared<firmwareImage>(file, BMC_FIRMWARE);
    if (bmc->fail()) {
        ret = -EINVAL;
    } else {
        ret = flasher.upgradeBMCFirmware(bmc.get());
    }
    return ret;
}

// Update SC firmware on the board.
static int updateSC(unsigned index, const char *file)
{
    int ret = 0;
    Flasher flasher(index);
    if(!flasher.isValid())
        return -EINVAL;

    auto mgmt_dev = pcidev::get_dev(index, false);
    std::shared_ptr<pcidev::pci_device> dev;
    bool is_mfg = false;
    std::string errmsg;

    mgmt_dev->sysfs_get<bool>("", "mfg", errmsg, is_mfg, false);
    if (is_mfg) {
        return writeSCImage(flasher, file);
    }

    int i = 0;
    for (dev = pcidev::get_dev(i, true); dev; dev = pcidev::get_dev(i, true)) {
        if(dev->domain == mgmt_dev->domain &&
            dev->bus == mgmt_dev->bus &&
            dev->dev == mgmt_dev->dev) {
                break;
        }
        i++;
    }
    dev = pcidev::get_dev(i, true);
    if (!dev) {
        std::cout << "ERROR: User function is not found. " <<
            "This is probably due to user function is running in virtual machine or user driver is not loaded. " << std::endl;
        return -ECANCELED;
    }

    std::cout << "Stopping user function..." << std::endl;

    dev->sysfs_put("", "shutdown", errmsg, "1\n");
    if (!errmsg.empty()) {
        std::cout << "Shutdown user function failed." << std::endl;
        return -EINVAL;
    }

    /* Poll till shutdown is done */
    int shutdownStatus = 0;
    for (int wait = 0; wait < DEV_TIMEOUT; wait++) {
        dev->sysfs_get<int>("", "shutdown", errmsg, shutdownStatus, EINVAL);
        if (!errmsg.empty()) {
            std::cout << errmsg << std::endl;
            return -EINVAL;
        }

        if (shutdownStatus == 1){
            /* Shutdown is done successfully. Returning from here */
            break;
        }
        sleep(1);
    }

    if (!shutdownStatus) {
        std::cout << "Shutdown user function timeout." << std::endl;
        return -ETIMEDOUT;
    }

    dev->sysfs_put("", "remove", errmsg, "1\n");
    if (!errmsg.empty()) {
        std::cout << "Stopping user function failed" << std::endl;
        return -EINVAL;
    }

    ret = writeSCImage(flasher, file);

    mgmt_dev->sysfs_put("", "dparent/rescan", errmsg, "1\n");
    if (!errmsg.empty()) {
        std::cout << "ERROR: " << errmsg << std::endl;
    }

    int wait = 0;
    do {
        auto hdl =dev->open("", O_RDWR);
        if (hdl != -1) {
            dev->close(hdl);
            break;
        }
        sleep(1);
    } while (++wait < DEV_TIMEOUT);
    if (wait == DEV_TIMEOUT) {
        std::cout << "ERROR: user function does not back online" << std::endl;
    }

    return ret;
}

// Update shell on the board.
static int updateShell(unsigned index, std::string flashType,
    const char *primary, const char *secondary)
{
    std::shared_ptr<firmwareImage> pri;
    std::shared_ptr<firmwareImage> sec;

    if (!flashType.empty()) {
        std::cout << "CAUTION: Overriding flash mode is not recommended. " <<
            "You may damage your card with this option." << std::endl;
        if(!canProceed())
            return -ECANCELED;
    }

    Flasher flasher(index);
    if(!flasher.isValid())
        return -EINVAL;

    if (primary == nullptr)
        return -EINVAL;

    pri = std::make_shared<firmwareImage>(primary, MCS_FIRMWARE_PRIMARY);
    if (pri->fail())
        return -EINVAL;

    if (secondary != nullptr) {
        sec = std::make_shared<firmwareImage>(secondary,
            MCS_FIRMWARE_SECONDARY);
        if (sec->fail())
            sec = nullptr;
    }

    return flasher.upgradeFirmware(flashType, pri.get(), sec.get());
}

// Reset shell to factory mode.
static int resetShell(unsigned index)
{
    Flasher flasher(index);
    if(!flasher.isValid())
        return -EINVAL;

    std::cout << "CAUTION: Resetting Card [" << flasher.sGetDBDF() <<
        "] back to factory mode." << std::endl;
    if(!canProceed())
        return -ECANCELED;

    return flasher.upgradeFirmware("", nullptr, nullptr);
}

static int updateShellAndSC(unsigned boardIdx, DSAInfo& candidate, bool& reboot)
{
    reboot = false;

    Flasher flasher(boardIdx);
    if(!flasher.isValid()) {
        std::cout << "card not available" << std::endl;
        return -EINVAL;
    }

    bool same_dsa = false;
    bool same_bmc = false;
    DSAInfo current = flasher.getOnBoardDSA();
    if (!current.name.empty()) {
        same_dsa = (candidate.name == current.name &&
            candidate.matchId(current));
        same_bmc = (current.bmcVer.empty() ||
            candidate.bmcVer == current.bmcVer);
    }
    if (same_dsa && same_bmc)
        std::cout << "update not needed" << std::endl;

    if (!same_bmc) {
        std::cout << "Updating SC firmware on card[" << flasher.sGetDBDF() <<
            "]" << std::endl;
        int ret = updateSC(boardIdx, candidate.file.c_str());
        if (ret != 0) {
            std::cout << "WARNING: Failed to update SC firmware on card ["
                << flasher.sGetDBDF() << "]" << std::endl;
        }
    }

    if (!same_dsa) {
        std::cout << "Updating shell on card[" << flasher.sGetDBDF() <<
            "]" << std::endl;
        int ret = updateShell(boardIdx, "", candidate.file.c_str(),
            candidate.file.c_str());
        if (ret != 0) {
            std::cout << "ERROR: Failed to update shell on card["
                << flasher.sGetDBDF() << "]" << std::endl;
        } else {
            reboot = true;
        }
    }

    if (!same_dsa && !reboot)
        return -EINVAL;

    return 0;
}

static DSAInfo selectShell(unsigned idx, std::string& dsa, std::string& id)
{
    unsigned candidateDSAIndex = UINT_MAX;

    Flasher flasher(idx);
    if(!flasher.isValid())
        return DSAInfo("");

    std::vector<DSAInfo> installedDSA = flasher.getInstalledDSA();

    // Find candidate DSA from installed DSA list.
    if (dsa.empty()) {
        std::cout << "Card [" << flasher.sGetDBDF() << "]: " << std::endl;
        if (installedDSA.empty()) {
            std::cout << "\t Status: no shell is installed" << std::endl;
            return DSAInfo("");
        }
        if (installedDSA.size() > 1) {
            std::cout << "\t Status: multiple shells are installed" << std::endl;
            return DSAInfo("");
        }
        candidateDSAIndex = 0;
    } else {
        for (unsigned int i = 0; i < installedDSA.size(); i++) {
            DSAInfo& idsa = installedDSA[i];
            if (dsa != idsa.name)
                continue;
            if (!id.empty() && !idsa.matchId(id))
                continue;
            if (candidateDSAIndex != UINT_MAX) {
                std::cout << "\t Status: multiple shells are installed" << std::endl;
                return DSAInfo("");
            }
            candidateDSAIndex = i;
        }
    }

    if (candidateDSAIndex == UINT_MAX) {
        std::cout << "WARNING: Failed to flash Card["
                  << flasher.sGetDBDF() << "]: Specified shell is not applicable" << std::endl;
        return DSAInfo("");
    }

    DSAInfo& candidate = installedDSA[candidateDSAIndex];

    bool same_dsa = false;
    bool same_bmc = false;
    DSAInfo currentDSA = flasher.getOnBoardDSA();
    if (!currentDSA.name.empty()) {
        same_dsa = (candidate.name == currentDSA.name &&
            candidate.matchId(currentDSA));
        same_bmc = (currentDSA.bmcVer.empty() ||
            candidate.bmcVer == currentDSA.bmcVer);
    }
    if (same_dsa && same_bmc) {
        std::cout << "\t Status: shell is up-to-date" << std::endl;
        return DSAInfo("");
    }
    std::cout << "\t Status: shell needs updating" << std::endl;
    std::cout << "\t Current shell: " << currentDSA.name << std::endl;
    std::cout << "\t Shell to be flashed: " << candidate.name << std::endl;
    return candidate;
}

static int autoFlash(unsigned index, std::string& shell,
    std::string& id, bool force)
{
    std::vector<unsigned int> boardsToCheck;
    std::vector<std::pair<unsigned, DSAInfo>> boardsToUpdate;

    // Sanity check input dsa and timestamp.
    if (!shell.empty()) {
        bool foundDSA = false;
        bool multiDSA = false;
        auto installedDSAs = firmwareImage::getIntalledDSAs();
        for (DSAInfo& dsa : installedDSAs) {
            if (shell == dsa.name &&
                (id.empty() || dsa.matchId(id))) {
                if (!foundDSA)
                    foundDSA = true;
                else
                    multiDSA = true;
            }
        }
        if (!foundDSA) {
            std::cout << "Specified shell not found." << std::endl;
            return -ENOENT;
        }
        if (multiDSA) {
            std::cout << "Specified shell matched multiple installed shells" <<
                std::endl;
            return -ENOTUNIQ;
        }
    }

    // Collect all indexes of boards need checking
    unsigned total = pcidev::get_dev_total(false);
    if (index == UINT_MAX) {
        for(unsigned i = 0; i < total; i++)
            boardsToCheck.push_back(i);
    } else {
        if (index < total)
            boardsToCheck.push_back(index);
    }
    if (boardsToCheck.empty()) {
        std::cout << "Card not found!" << std::endl;
        return -ENOENT;
    }

    // Collect all indexes of boards need updating
    for (unsigned i : boardsToCheck) {
        DSAInfo dsa = selectShell(i, shell, id);
        if (dsa.hasFlashImage)
            boardsToUpdate.push_back(std::make_pair(i, dsa));
    }

    // Continue to flash whatever we have collected in boardsToUpdate.
    unsigned success = 0;
    bool needreboot = false;
    if (!boardsToUpdate.empty()) {

        // Prompt user about what boards will be updated and ask for permission.
        if(!force && !canProceed())
            return -ECANCELED;

        // Perform DSA and BMC updating
        for (auto p : boardsToUpdate) {
            bool reboot;
            std::cout << std::endl;
            if (updateShellAndSC(p.first, p.second, reboot) == 0) {
                std::cout << "Successfully flashed Card[" << getBDF(p.first) << "]"<< std::endl;
                success++;
            }
            needreboot |= reboot;
        }
    }

    std::cout << std::endl;

    if (boardsToUpdate.size() == 0) {
        std::cout << "Card(s) up-to-date and do not need to be flashed." << std::endl;
        return 0;
    }

    if (success != 0) {
        std::cout << success << " Card(s) flashed successfully." << std::endl; 
    } else {
        std::cout << "No cards were flashed." << std::endl; 
    }

    if (needreboot) {
        std::cout << "Cold reboot machine to load the new image on card(s)."
            << std::endl;
    }

    if (success != boardsToUpdate.size()) {
        std::cout << "WARNING:" << boardsToUpdate.size()-success << " Card(s) not flashed. " << std::endl;
        exit(-EINVAL);
    }

    return 0;
}

// For backward compatibility, will be removed later
int flashXbutilFlashHandler(int argc, char *argv[])
{
    if (argc < 2)
        return -EINVAL;

    sudoOrDie();

    if (strcmp(argv[1], "scan") == 0) {
        bool verbose = false;

        if (argc > 3)
            return -EINVAL;

        if (argc == 3) {
            if (strcmp(argv[2], "-v") != 0)
                return -EINVAL;
            verbose = true;
        }

        return scanDevices(verbose, false);
    }

    unsigned devIdx = UINT_MAX;
    char *primary = nullptr;
    char *secondary = nullptr;
    char *bmc = nullptr;
    std::string flashType;
    std::string dsa;
    std::string id;
    bool force = false;
    bool reset = false;

    int opt;
    while ((opt = getopt(argc, argv, "a:d:fm:n:o:p:rt:")) != -1) {
        switch (opt) {
        case 'a':
            dsa = optarg;
            break;
        case 'd':
            if (std::string(optarg).find(":") == std::string::npos) {
                std::cout <<
                    "Please use -d <mgmt-BDF> to specify the device to flash"
                    << std::endl;
                std::cout << "Run xbmgmt scan to find mgmt BDF"
                    << std::endl;
            } else {
                devIdx = bdf2index(optarg);
            }
            if (devIdx == UINT_MAX)
                return -EINVAL;
            break;
        case 'f':
            force = true;
            break;
        case 'm':
            primary = optarg;
            break;
        case 'n':
            secondary = optarg;
            break;
        case 'o':
            flashType = optarg;
            break;
        case 'p':
            bmc = optarg;
            break;
        case 't':
	    id = optarg;
            break;
        case 'r':
            reset = true;
            break;
        default:
            return -EINVAL;
        }
    }

    if (reset) {
        int ret = resetShell(devIdx == UINT_MAX ? 0 : devIdx);
        if (ret)
            return ret;
        std::cout << "Shell is reset successfully" << std::endl;
        std::cout << "Cold reboot machine to load new shell on card" <<
            std::endl;
        return 0;
    }

    if (bmc)
        return updateSC(devIdx == UINT_MAX ? 0 : devIdx, bmc);

    if (primary) {
        int ret = updateShell(devIdx == UINT_MAX ? 0 : devIdx, flashType,
            primary, secondary);
        if (ret)
            return ret;
        std::cout << "Shell is updated successfully" << std::endl;
        std::cout << "Cold reboot machine to load new shell on card" <<
            std::endl;
        return 0;
    }

    if (!dsa.empty()) {
        if (dsa.compare("all") == 0)
            dsa.clear();
        return autoFlash(devIdx, dsa, id, force);
    }

    return -EINVAL;
}

static int scan(int argc, char *argv[])
{
    bool verbose = false;
    bool json = false;
    const option opts[] = {
        { "verbose", no_argument, nullptr, '0' },
        { "json", no_argument, nullptr, '1' },
        { nullptr, 0, nullptr, 0 },
    };

    while (true) {
        const auto opt = getopt_long(argc, argv, "", opts, nullptr);
        if (opt == -1)
            break;

        switch (opt) {
        case '0':
            verbose = true;
            break;
        case '1':
            json = true;
            break;
        default:
            return -EINVAL;
        }
    }
    if (verbose && json)
        return -EINVAL;
    return scanDevices(verbose, json);
}

static int update(int argc, char *argv[])
{
    bool force = false;
    unsigned index = UINT_MAX;
    std::string shell;
    std::string id;
    const option opts[] = {
        { "card", required_argument, nullptr, '0' },
        { "shell", required_argument, nullptr, '1' },
        { "id", required_argument, nullptr, '2' },
        { "force", no_argument, nullptr, '3' },
        { nullptr, 0, nullptr, 0 },
    };

    while (true) {
        const auto opt = getopt_long(argc, argv, "", opts, nullptr);
        if (opt == -1)
            break;

        switch (opt) {
        case '0':
            index = bdf2index(optarg);
            if (index == UINT_MAX)
                return -ENOENT;
            break;
        case '1':
            shell = std::string(optarg);
            break;
        case '2':
	    id = std::string(optarg);
            break;
        case '3':
            force = true;
            break;
        default:
            return -EINVAL;
        }
    }

    if (shell.empty() && !id.empty())
        return -EINVAL;

    return autoFlash(index, shell, id, force);
}

static int shell(int argc, char *argv[])
{
    unsigned index = UINT_MAX;
    std::string file;
    std::string type;
    const option opts[] = {
        { "card", required_argument, nullptr, '0' },
        { "path", required_argument, nullptr, '1' },
        { "flash_type", required_argument, nullptr, '2' },
        { nullptr, 0, nullptr, 0 },
    };

    while (true) {
        const auto opt = getopt_long(argc, argv, "", opts, nullptr);
        if (opt == -1)
            break;

        switch (opt) {
        case '0':
            index = bdf2index(optarg);
            if (index == UINT_MAX)
                return -ENOENT;
            break;
        case '1':
            file = std::string(optarg);
            break;
        case '2':
            type = std::string(optarg);
            break;
        default:
            return -EINVAL;
        }
    }

    if (file.empty() || index == UINT_MAX)
        return -EINVAL;

    int ret = updateShell(index, type, file.c_str(), nullptr);
    if (ret)
        return ret;

    std::cout << "Shell is updated successfully" << std::endl;
    std::cout << "Cold reboot machine to load new shell on card" << std::endl;
    return 0;
}

static int sc(int argc, char *argv[])
{
    unsigned index = UINT_MAX;
    std::string file;
    const option opts[] = {
        { "card", required_argument, nullptr, '0' },
        { "path", required_argument, nullptr, '1' },
        { nullptr, 0, nullptr, 0 },
    };

    while (true) {
        const auto opt = getopt_long(argc, argv, "", opts, nullptr);
        if (opt == -1)
            break;

        switch (opt) {
        case '0':
            index = bdf2index(optarg);
            if (index == UINT_MAX)
                return -ENOENT;
            break;
        case '1':
            file = std::string(optarg);
            break;
        default:
            return -EINVAL;
        }
    }

    if (file.empty() || index == UINT_MAX)
        return -EINVAL;

    int ret = updateSC(index, file.c_str());
    if (ret)
        return ret;

    std::cout << "SC firmware is updated successfully" << std::endl;
    return 0;
}

static int reset(int argc, char *argv[])
{
    unsigned index = UINT_MAX;
    const option opts[] = {
        { "card", required_argument, nullptr, '0' },
        { nullptr, 0, nullptr, 0 },
    };

    while (true) {
        const auto opt = getopt_long(argc, argv, "", opts, nullptr);
        if (opt == -1)
            break;

        switch (opt) {
        case '0':
            index = bdf2index(optarg);
            if (index == UINT_MAX)
                return -ENOENT;
            break;
        default:
            return -EINVAL;
        }
    }

    int ret = resetShell(index == UINT_MAX ? 0 : index);
    if (ret)
        return ret;

    std::cout << "Shell is reset successfully" << std::endl;
    std::cout << "Cold reboot machine to load new shell on card" << std::endl;
    return 0;
}

static const std::map<std::string, std::function<int(int, char **)>> optList = {
    { "--scan", scan },
    { "--update", update },
    { "--shell", shell },
    { "--sc_firmware", sc },
    { "--factory_reset", reset },
};

int flashHandler(int argc, char *argv[])
{
    if (argc < 2)
        return -EINVAL;

    sudoOrDie();

    std::string subcmd(argv[1]);

    auto cmd = optList.find(subcmd);
    if (cmd == optList.end())
        return -EINVAL;

    argc--;
    argv++;
    return cmd->second(argc, argv);
}

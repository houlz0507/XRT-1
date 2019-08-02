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
#include <iostream>
#include <map>
#include <fstream>
#include <climits>
#include <getopt.h>
#include <unistd.h>

#include "flasher.h"
#include "xbmgmt.h"
#include "firmware_image.h"
#include "core/pcie/linux/scan.h"
#include "xclbin.h"
#include "core/pcie/driver/linux/include/mgmt-ioctl.h"

const char *subCmdPartDesc = "Show and download partition onto the device";
const char *subCmdPartUsage =
    "--program --path xclbin [--card bdf] [--force]\n"
    "--scan [--verbose]";

int program_prp(unsigned index, const std::string& xclbin)
{
    std::ifstream stream(xclbin.c_str(), std::ios_base::binary);

    if(!stream.is_open()) {
        std::cout << "ERROR: Cannot open " << xclbin << std::endl;
	return -ENOENT;
    }

    auto dev = pcidev::get_dev(index, false);
    int fd = dev->devfs_open("icap", O_WRONLY);

    if (fd == -1) {
        std::cout << "ERROR: Cannot open icap for writing." << std::endl;
        return -ENODEV;
    }

    stream.seekg(0, stream.end);
    int length = stream.tellg();
    stream.seekg(0, stream.beg);

    char *buffer = new char[length];
    stream.read(buffer, length);
    ssize_t ret = write(fd, buffer, length);
    delete [] buffer;

    if (ret <= 0) {
        std::cout << "ERROR: Write prp to icap subdev failed." << std::endl;
        close(fd);
        return -errno;
    }
    close(fd);

    std::string errmsg;
    dev->sysfs_put("", "rp_program", errmsg, "2");
    if (!errmsg.empty()) {
        std::cout << errmsg << std::endl;
        close(fd);
	return -EINVAL;
    }

    return 0;
}

int program_urp(unsigned index, const std::string& xclbin)
{
    std::ifstream stream(xclbin.c_str());

    if(!stream.is_open()) {
        std::cout << "ERROR: Cannot open " << xclbin << std::endl;
        return -ENOENT;
    }

    stream.seekg(0, stream.end);
    int length = stream.tellg();
    stream.seekg(0, stream.beg);

    char *buffer = new char[length];
    stream.read(buffer, length);
    xclmgmt_ioc_bitstream_axlf obj = { reinterpret_cast<axlf *>(buffer) };
    auto dev = pcidev::get_dev(index, false);
    int ret = dev->ioctl(XCLMGMT_IOCICAPDOWNLOAD_AXLF, &obj);
    delete [] buffer;

    return ret ? -errno : ret;
}

void scanPartitions(int index, std::vector<DSAInfo>& installedDSAs, bool verbose)
{
    Flasher f(index);
    if (!f.isValid())
        return;

    //DSAInfo board = f.getOnBoardDSA();

    std::cout << "Card [" << f.sGetDBDF() << "]" << std::endl;
    std::cout << "\tProgrammable partition running on FPGA:" << std::endl;

    std::vector<std::string> uuids;
    auto dev = pcidev::get_dev(index, false);
    std::string errmsg;

    dev->sysfs_get("", "logic_uuids", errmsg, uuids);
    if (errmsg.empty())
    {
        DSAInfo dsa("", NULL_TIMESTAMP, uuids.back(), "");

        std::cout << "\t\t" << dsa << std::endl;
    }

    std::cout << "\tProgrammable partitions installed in system:" << std::endl;
    if (installedDSAs.empty())
    {
        std::cout << "(None)" << std::endl;
        return;
    }

    for (auto& dsa : installedDSAs)
    {
        if (dsa.hasFlashImage || dsa.uuids.empty())
            continue;
	std::cout << "\t\t" << dsa;
    }
    std::cout << std::endl;
}

int scan(int argc, char *argv[])
{
    unsigned total = pcidev::get_dev_total(false);

    if (total == 0) {
        std::cout << "No card is found!" << std::endl;
	return 0;
    }

    bool verbose;
    const option opts[] = {
        { "verbose", no_argument, nullptr, '0' },
    };

    while (true) {
        const auto opt = getopt_long(argc, argv, "", opts, nullptr);
        if (opt == -1)
            break;

        switch (opt) {
        case '0':
            verbose = true;
            break;
        default:
            return -EINVAL;
        }
    }

    auto installedDSAs = firmwareImage::getIntalledDSAs();
    for (unsigned i = 0; i < total; i++)
    {
        scanPartitions(i, installedDSAs, verbose);
    }

    return 0;
}

int program(int argc, char *argv[])
{
    if (argc < 2)
        return -EINVAL;

    unsigned index = UINT_MAX;
    bool force = false;
    std::string file;
    const option opts[] = {
        { "card", required_argument, nullptr, '0' },
        { "force", no_argument, nullptr, '1' },
        { "path", required_argument, nullptr, '2' },
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
            force = true;
            break;
        case '2':
            file = std::string(optarg);
            break;
        default:
            return -EINVAL;
        }
    }

    if (file.empty())
        return -EINVAL;

    if (index == UINT_MAX)
        index = 0;

    /* Get permission from user. */
    if (!force) {
        std::cout << "CAUTION: Downloading xclbin. " <<
            "Please make sure xocl driver is unloaded." << std::endl;
        if(!canProceed())
            return -ECANCELED;
    }

    DSAInfo dsa(file);
    std::string blp_uuid;
    auto dev = pcidev::get_dev(index, false);
    std::string errmsg;

    dev->sysfs_get("", "interface_uuids", errmsg, blp_uuid);
    if (!errmsg.empty())
    {
        // 1RP platform
        std::cout << "Programming URP..." << std::endl;
        return program_urp(index, file);
    }

    for (std::string uuid : dsa.uuids)
    {
        if (blp_uuid.compare(uuid) == 0)
        {
            std::cout << "Programming PRP..." << std::endl;
            return program_prp(index, file);
        }
    }

    std::cout << "Programming URP..." << std::endl;
    return program_urp(index, file);
}

static const std::map<std::string, std::function<int(int, char **)>> optList = {
    { "--program", program },
    { "--scan", scan },
};

int partHandler(int argc, char *argv[])
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

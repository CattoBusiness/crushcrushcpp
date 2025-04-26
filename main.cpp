#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <map>

// Structure to store patch information for restoration
struct PatchInfo {
    uintptr_t address;
    std::vector<BYTE> originalBytes;
    std::string name;
};

class CrushCrushCheat {
private:
    HANDLE processHandle;
    DWORD processId;
    uintptr_t moduleBase;
    bool connected;
    
    // Store original patches for restoration
    std::map<std::string, PatchInfo> appliedPatches;
    std::map<std::string, LPVOID> allocatedMemory;

    // Find process ID by name
    DWORD GetProcessIdByName(const wchar_t* processName) {
        DWORD pid = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32W);
            
            if (Process32FirstW(snapshot, &processEntry)) {
                do {
                    if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                        pid = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snapshot, &processEntry));
            }
            CloseHandle(snapshot);
        }
        return pid;
    }

    // Get module base address
    uintptr_t GetModuleBaseAddress(DWORD processId, const wchar_t* moduleName) {
        uintptr_t moduleBase = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        
        if (snapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W moduleEntry;
            moduleEntry.dwSize = sizeof(MODULEENTRY32W);
            
            if (Module32FirstW(snapshot, &moduleEntry)) {
                do {
                    if (_wcsicmp(moduleEntry.szModule, moduleName) == 0) {
                        moduleBase = (uintptr_t)moduleEntry.modBaseAddr;
                        break;
                    }
                } while (Module32NextW(snapshot, &moduleEntry));
            }
            CloseHandle(snapshot);
        }
        return moduleBase;
    }

    // Read memory from the game
    template<typename T>
    T ReadMemory(uintptr_t address) {
        T value;
        ReadProcessMemory(processHandle, (LPCVOID)address, &value, sizeof(T), nullptr);
        return value;
    }

    // Write memory to the game
    template<typename T>
    bool WriteMemory(uintptr_t address, T value) {
        return WriteProcessMemory(processHandle, (LPVOID)address, &value, sizeof(T), nullptr);
    }

    // Find memory address using pattern scanning
    uintptr_t FindPatternAddress(const std::vector<BYTE>& pattern, const std::string& mask) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = moduleBase;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_EXECUTE_READ || 
                                            mbi.Protect == PAGE_EXECUTE_READWRITE || 
                                            mbi.Protect == PAGE_READWRITE)) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                
                if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                    for (size_t i = 0; i < bytesRead - pattern.size(); i++) {
                        bool found = true;
                        
                        for (size_t j = 0; j < pattern.size(); j++) {
                            if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                                found = false;
                                break;
                            }
                        }
                        
                        if (found) {
                            return (uintptr_t)mbi.BaseAddress + i;
                        }
                    }
                }
            }
            address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }
        return 0;
    }

    // Apply memory patch with backup for restoration
    bool PatchMemory(uintptr_t address, const std::vector<BYTE>& patch, const std::string& patchName) {
        DWORD oldProtect;
        
        // Backup original bytes if we haven't already
        if (appliedPatches.find(patchName) == appliedPatches.end()) {
            std::vector<BYTE> originalBytes(patch.size());
            if (!ReadProcessMemory(processHandle, (LPCVOID)address, originalBytes.data(), originalBytes.size(), nullptr)) {
                std::cout << "Failed to read original bytes for backup" << std::endl;
                return false;
            }
            
            // Store the backup
            PatchInfo info;
            info.address = address;
            info.originalBytes = originalBytes;
            info.name = patchName;
            appliedPatches[patchName] = info;
        }
        
        // Change memory protection to allow writing
        if (!VirtualProtectEx(processHandle, (LPVOID)address, patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cout << "Failed to change memory protection" << std::endl;
            return false;
        }
        
        // Write the patch
        if (!WriteProcessMemory(processHandle, (LPVOID)address, patch.data(), patch.size(), nullptr)) {
            std::cout << "Failed to write patch" << std::endl;
            VirtualProtectEx(processHandle, (LPVOID)address, patch.size(), oldProtect, &oldProtect);
            return false;
        }
        
        // Restore memory protection
        VirtualProtectEx(processHandle, (LPVOID)address, patch.size(), oldProtect, &oldProtect);
        
        return true;
    }

    // Read bytes from memory
    std::vector<BYTE> ReadBytes(uintptr_t address, size_t size) {
        std::vector<BYTE> buffer(size);
        ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), size, nullptr);
        return buffer;
    }

public:
    CrushCrushCheat() : processHandle(NULL), processId(0), moduleBase(0), connected(false) {}

    ~CrushCrushCheat() {
        Disconnect();
    }

    // Connect to the game process
    bool Connect() {
        processId = GetProcessIdByName(L"CrushCrush.exe");
        if (processId == 0) {
            std::cout << "Process not found. Is the game running?" << std::endl;
            return false;
        }
        
        processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, processId);
        if (processHandle == NULL) {
            std::cout << "Failed to open process. Error code: " << GetLastError() << std::endl;
            return false;
        }
        
        moduleBase = GetModuleBaseAddress(processId, L"CrushCrush.exe");
        if (moduleBase == 0) {
            std::cout << "Failed to get module base address" << std::endl;
            CloseHandle(processHandle);
            processHandle = NULL;
            return false;
        }
        
        connected = true;
        std::cout << "Successfully connected to CrushCrush.exe" << std::endl;
        return true;
    }

    // Disconnect from the game process
    void Disconnect() {
        // Free any allocated memory
        for (auto& mem : allocatedMemory) {
            if (mem.second) {
                VirtualFreeEx(processHandle, mem.second, 0, MEM_RELEASE);
            }
        }
        allocatedMemory.clear();
        
        if (processHandle != NULL) {
            CloseHandle(processHandle);
            processHandle = NULL;
        }
        connected = false;
    }

    // Restore a specific patch
    bool RestorePatch(const std::string& patchName) {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        auto it = appliedPatches.find(patchName);
        if (it == appliedPatches.end()) {
            std::cout << "No patch with name '" << patchName << "' has been applied" << std::endl;
            return false;
        }
        
        PatchInfo& info = it->second;
        DWORD oldProtect;
        
        // Change memory protection to allow writing
        if (!VirtualProtectEx(processHandle, (LPVOID)info.address, info.originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cout << "Failed to change memory protection for restoration" << std::endl;
            return false;
        }
        
        // Restore original bytes
        if (!WriteProcessMemory(processHandle, (LPVOID)info.address, info.originalBytes.data(), info.originalBytes.size(), nullptr)) {
            std::cout << "Failed to restore original bytes" << std::endl;
            VirtualProtectEx(processHandle, (LPVOID)info.address, info.originalBytes.size(), oldProtect, &oldProtect);
            return false;
        }
        
        // Restore memory protection
        VirtualProtectEx(processHandle, (LPVOID)info.address, info.originalBytes.size(), oldProtect, &oldProtect);
        
        std::cout << "Successfully restored '" << patchName << "' to original state" << std::endl;
        
        // Remove from the applied patches map
        appliedPatches.erase(it);
        
        // Free allocated memory if any
        auto memIt = allocatedMemory.find(patchName);
        if (memIt != allocatedMemory.end()) {
            if (memIt->second) {
                VirtualFreeEx(processHandle, memIt->second, 0, MEM_RELEASE);
            }
            allocatedMemory.erase(memIt);
        }
        
        return true;
    }

    // Restore all patches
    bool RestoreAllPatches() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        if (appliedPatches.empty()) {
            std::cout << "No patches have been applied" << std::endl;
            return false;
        }
        
        std::vector<std::string> patchNames;
        for (const auto& patch : appliedPatches) {
            patchNames.push_back(patch.first);
        }
        
        bool success = true;
        for (const auto& name : patchNames) {
            if (!RestorePatch(name)) {
                success = false;
            }
        }
        
        if (success) {
            std::cout << "All patches have been restored to original state" << std::endl;
        } else {
            std::cout << "Some patches could not be restored" << std::endl;
        }
        
        return success;
    }

    // No Messages Cooldown (Smartphone) - Exactly as in Cheat Engine table
    bool NoMessagesCooldown() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "NoMessagesCooldown";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "No messages cooldown is already active" << std::endl;
            return false;
        }
        
        // Pattern from cheat table: 88 87 E5 00 00 00 DD 87 D0
        std::vector<BYTE> pattern = {0x88, 0x87, 0xE5, 0x00, 0x00, 0x00, 0xDD, 0x87, 0xD0};
        std::string mask = "xxxxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find message cooldown pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found message cooldown pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Define noMsgCd as patternAddress+6 like in the cheat table
        uintptr_t noMsgCd = patternAddress + 6;
        
        // Create new memory for our patch code
        LPVOID newmem = VirtualAllocEx(processHandle, NULL, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newmem) {
            std::cout << "Failed to allocate memory for patch" << std::endl;
            return false;
        }
        
        // Store allocated memory for cleanup
        allocatedMemory[patchName] = newmem;
        
        // Create the jump to our new code
        std::vector<BYTE> jumpPatch = {
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp newmem
            0x90                          // nop
        };
        
        // Calculate the jump offset
        int jumpOffset = (int)((uintptr_t)newmem - noMsgCd - 5);
        memcpy(&jumpPatch[1], &jumpOffset, 4);
        
        // Backup original instructions
        std::vector<BYTE> originalInstructions = ReadBytes(noMsgCd, 6);
        
        // Create our new code exactly like in Cheat Engine
        std::vector<BYTE> newCode = {
            0x50,                         // push eax
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x89, 0x87, 0xD0, 0x00, 0x00, 0x00, // mov [edi+D0], eax  // currentTime
            0x89, 0x87, 0xD4, 0x00, 0x00, 0x00, // mov [edi+D4], eax
            0x58,                         // pop eax
        };
        
        // Add original instructions
        newCode.insert(newCode.end(), originalInstructions.begin(), originalInstructions.end());
        
        // Add jump back to original code
        std::vector<BYTE> jumpBack = {
            0xE9, 0x00, 0x00, 0x00, 0x00  // jmp back
        };
        
        int jumpBackOffset = (int)(noMsgCd + 6 - ((uintptr_t)newmem + newCode.size() + 5));
        memcpy(&jumpBack[1], &jumpBackOffset, 4);
        
        newCode.insert(newCode.end(), jumpBack.begin(), jumpBack.end());
        
        // Write our new code
        if (!WriteProcessMemory(processHandle, newmem, newCode.data(), newCode.size(), nullptr)) {
            std::cout << "Failed to write new code" << std::endl;
            VirtualFreeEx(processHandle, newmem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        // Apply jump patch with backup for restoration
        if (!PatchMemory(noMsgCd, jumpPatch, patchName)) {
            std::cout << "Failed to apply jump patch" << std::endl;
            VirtualFreeEx(processHandle, newmem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        std::cout << "No messages cooldown patch applied successfully!" << std::endl;
        return true;
    }

    // Free Store Items - Diamond purchases cost nothing
    bool FreeStoreItems() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "FreeStoreItems";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Free store items is already active" << std::endl;
            return false;
        }
        
        // Pattern from cheat table: 8B 45 0C 89 41 0C 8B 45 10
        std::vector<BYTE> pattern = {0x8B, 0x45, 0x0C, 0x89, 0x41, 0x0C, 0x8B, 0x45, 0x10};
        std::string mask = "xxxxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find store purchase pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found store purchase pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to set cost to 0
        std::vector<BYTE> patch = {
            0x8B, 0x45, 0x0C,                   // mov eax, [ebp+0C]
            0x89, 0x41, 0x0C,                   // mov [ecx+0C], eax
            0xC7, 0x45, 0x10, 0x00, 0x00, 0x00, 0x00  // mov [ebp+10], 0 (cost param)
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch store items" << std::endl;
            return false;
        }
        
        std::cout << "Free store items patch applied successfully!" << std::endl;
        return true;
    }

    // Meet Hearts Requirement
    bool MeetHeartsRequirement() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "MeetHeartsRequirement";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Meet hearts requirement is already active" << std::endl;
            return false;
        }
        
        // Pattern from cheat table: 8B 50 7C 8B 40 78 C9 C3
        std::vector<BYTE> pattern = {0x8B, 0x50, 0x7C, 0x8B, 0x40, 0x78, 0xC9, 0xC3};
        std::string mask = "xxxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find heart requirement pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found heart requirement pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to set hearts to the required amount
        std::vector<BYTE> patch = {
            0x57,                       // push edi
            0x8B, 0xF8,                 // mov edi, eax
            0x8B, 0x50, 0x7C,           // mov edx, [eax+7C]
            0x8B, 0x40, 0x78,           // mov eax, [eax+78]
            0x85, 0xD2,                 // test edx, edx
            0x78, 0x06,                 // js skip (if negative value)
            0x89, 0x97, 0x4C, 0x00, 0x00, 0x00, // mov [edi+48+4], edx (hearts offset+4)
            0x89, 0x87, 0x48, 0x00, 0x00, 0x00, // mov [edi+48], eax (hearts offset)
            0x5F,                       // pop edi
            0xC9,                       // leave
            0xC3                        // ret
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch heart requirements" << std::endl;
            return false;
        }
        
        std::cout << "Meet hearts requirement patch applied successfully!" << std::endl;
        return true;
    }

    // Meet Requirements (general)
    bool MeetRequirements() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "MeetRequirements";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Meet requirements is already active" << std::endl;
            return false;
        }
        
        // Pattern for Girl:MeetsRequirements+10f in the cheat table
        std::vector<BYTE> pattern = {0x8D, 0x65, 0xF4, 0x5E, 0x5F};
        std::string mask = "xxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find requirements pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found requirements pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to always return true (1)
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x8D, 0x65, 0xF4,             // lea esp, [ebp-0C]
            0x5E,                         // pop esi
            0x5F                          // pop edi
        };
        
        if (!PatchMemory(patternAddress - 5, patch, patchName)) {
            std::cout << "Failed to patch general requirements" << std::endl;
            return false;
        }
        
        std::cout << "Meet general requirements patch applied successfully!" << std::endl;
        return true;
    }

    // Unlock All Outfits
    bool UnlockAllOutfits() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "UnlockAllOutfits";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Unlock all outfits is already active" << std::endl;
            return false;
        }
        
        // Pattern from cheat table: 8B 80 94 00 00 00 8B 4E 20
        std::vector<BYTE> pattern = {0x8B, 0x80, 0x94, 0x00, 0x00, 0x00, 0x8B, 0x4E, 0x20};
        std::string mask = "xxxxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find outfit unlock pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found outfit unlock pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to OR outfits instead of AND
        std::vector<BYTE> patch = {
            0x52,                         // push edx
            0x8B, 0xD8,                   // mov ebx, eax
            0x8B, 0x80, 0x94, 0x00, 0x00, 0x00, // mov eax,[eax+00000094]
            0x8B, 0x4E, 0x20,             // mov ecx,[esi+20]
            0x0B, 0xC1,                   // or eax, ecx
            0x89, 0x83, 0x94, 0x00, 0x00, 0x00, // mov [ebx+94], eax
            0x5A                          // pop edx
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch outfit unlock" << std::endl;
            return false;
        }
        
        std::cout << "Unlock all outfits patch applied successfully!" << std::endl;
        return true;
    }

    // Outfits cost 1 Diamond
    bool OutfitsCostOneDiamond() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "OutfitsCostOneDiamond";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Outfits cost 1 diamond is already active" << std::endl;
            return false;
        }
        
        // Pattern for Balance:GetOutfitDiamondCost+da
        std::vector<BYTE> pattern = {0x8D, 0x65, 0xF4, 0x5E, 0x5F, 0x5B, 0xC9, 0xC3};
        std::string mask = "xxxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find outfit cost pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found outfit cost pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to always return 1 diamond
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x8D, 0x65, 0xF4,             // lea esp, [ebp-0C]
            0x5E,                         // pop esi
            0x5F                          // pop edi
        };
        
        if (!PatchMemory(patternAddress - 5, patch, patchName)) {
            std::cout << "Failed to patch outfit cost" << std::endl;
            return false;
        }
        
        std::cout << "Outfits cost 1 diamond patch applied successfully!" << std::endl;
        return true;
    }

    // Gifts cost no Diamonds
    bool GiftsCostNoDiamonds() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "GiftsCostNoDiamonds";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Gifts cost no diamonds is already active" << std::endl;
            return false;
        }
        
        // Pattern for GiftModel:GetGiftDiamondCost+90
        std::vector<BYTE> pattern = {0x8D, 0x65, 0xF8, 0x5E, 0x5B};
        std::string mask = "xxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find gift cost pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found gift cost pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to always return 0 diamonds
        std::vector<BYTE> patch = {
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x8D, 0x65, 0xF8,             // lea esp, [ebp-08]
            0x5E,                         // pop esi
            0x5B                          // pop ebx
        };
        
        if (!PatchMemory(patternAddress - 5, patch, patchName)) {
            std::cout << "Failed to patch gift cost" << std::endl;
            return false;
        }
        
        std::cout << "Gifts cost no diamonds patch applied successfully!" << std::endl;
        return true;
    }

    // No Talk Cooldown
    bool NoTalkCooldown() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "NoTalkCooldown";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "No talk cooldown is already active" << std::endl;
            return false;
        }
        
        // Pattern for talk cooldown in the cheat table
        std::vector<BYTE> pattern = {0xD9, 0x05, 0x00, 0x00, 0x00, 0x00, 0xD9, 0x5D, 0xFC};
        std::string mask = "xx????xxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find talk cooldown pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found talk cooldown pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create new memory for our constant
        LPVOID cooldownMem = VirtualAllocEx(processHandle, NULL, 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!cooldownMem) {
            std::cout << "Failed to allocate memory for cooldown value" << std::endl;
            return false;
        }
        
        // Store allocated memory for cleanup
        allocatedMemory[patchName] = cooldownMem;
        
        // Set cooldown to 0.1
        float cooldownValue = 0.1f;
        if (!WriteProcessMemory(processHandle, cooldownMem, &cooldownValue, sizeof(cooldownValue), nullptr)) {
            std::cout << "Failed to write cooldown value" << std::endl;
            VirtualFreeEx(processHandle, cooldownMem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        // Create patch to load our cooldown value
        std::vector<BYTE> patch = {
            0xD9, 0x05, 0x00, 0x00, 0x00, 0x00  // fld dword ptr [cooldownMem]
        };
        
        // Set the address of our cooldown value
        DWORD cooldownAddr32 = (DWORD)(uintptr_t)cooldownMem;
        memcpy(&patch[2], &cooldownAddr32, sizeof(DWORD));
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch talk cooldown" << std::endl;
            VirtualFreeEx(processHandle, cooldownMem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        std::cout << "No talk cooldown patch applied successfully!" << std::endl;
        return true;
    }

    // Max Hobby Level
    bool MaxHobbyLevel() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "MaxHobbyLevel";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Max hobby level is already active" << std::endl;
            return false;
        }
        
        // Pattern for Hobby2:get_BaseTime+64
        std::vector<BYTE> pattern = {0xDD, 0x00, 0x8D, 0x65, 0xFC};
        std::string mask = "xxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find hobby level pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found hobby level pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create memory for our time value
        LPVOID timeMem = VirtualAllocEx(processHandle, NULL, 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!timeMem) {
            std::cout << "Failed to allocate memory for hobby time value" << std::endl;
            return false;
        }
        
        // Store allocated memory for cleanup
        allocatedMemory[patchName] = timeMem;
        
        // Set time to 0.1 (double)
        double timeValue = 0.1;
        if (!WriteProcessMemory(processHandle, timeMem, &timeValue, sizeof(timeValue), nullptr)) {
            std::cout << "Failed to write hobby time value" << std::endl;
            VirtualFreeEx(processHandle, timeMem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        // Create the patch code
        std::vector<BYTE> patch = {
            0xDD, 0x05, 0x00, 0x00, 0x00, 0x00, // fld qword ptr [timeMem]
            0x8D, 0x65, 0xFC                    // lea esp, [ebp-04]
        };
        
        // Set the address of our time value
        DWORD timeAddr32 = (DWORD)(uintptr_t)timeMem;
        memcpy(&patch[2], &timeAddr32, sizeof(DWORD));
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch hobby level" << std::endl;
            VirtualFreeEx(processHandle, timeMem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        std::cout << "Max hobby level patch applied successfully!" << std::endl;
        return true;
    }

    // No Job Cooldown
    bool NoJobCooldown() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "NoJobCooldown";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "No job cooldown is already active" << std::endl;
            return false;
        }
        
        // Pattern from cheat table: D9 87 ? ? ? 00 D9 ? ? DE C1 D9 ? ? DF F1
        std::vector<BYTE> pattern = {0xD9, 0x87, 0x8C, 0x00, 0x00, 0x00, 0xD9, 0x45, 0x0C};
        std::string mask = "xxxxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find job cooldown pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found job cooldown pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to keep job progress at max
        std::vector<BYTE> patch = {
            0x50,                                   // push eax
            0x8B, 0x45, 0xE4,                       // mov eax, [ebp-1C]
            0x89, 0x87, 0x8C, 0x00, 0x00, 0x00,     // mov [edi+8C], eax
            0x58,                                   // pop eax
            0xD9, 0x87, 0x8C, 0x00, 0x00, 0x00      // fld dword ptr [edi+0000008C]
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch job cooldown" << std::endl;
            return false;
        }
        
        std::cout << "No job cooldown patch applied successfully!" << std::endl;
        return true;
    }

    // Max Job Experience
    bool MaxJobExperience() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "MaxJobExperience";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Max job experience is already active" << std::endl;
            return false;
        }
        
        // Pattern for Job2:get_ExperienceToLevel+22
        std::vector<BYTE> pattern = {0x8B, 0x50, 0x1C, 0x8B, 0x40, 0x18};
        std::string mask = "xxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find job experience pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found job experience pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to set job experience to max
        std::vector<BYTE> patch = {
            0x8B, 0x50, 0x1C,           // mov edx, [eax+1C]
            0x8B, 0x40, 0x18,           // mov eax, [eax+18]
            0x51,                       // push ecx
            0x8B, 0x4D, 0x08,           // mov ecx, [ebp+8]
            0x89, 0x91, 0x84, 0x00, 0x00, 0x00, // mov [ecx+84], edx
            0x89, 0x81, 0x80, 0x00, 0x00, 0x00, // mov [ecx+80], eax
            0x59                        // pop ecx
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch job experience" << std::endl;
            return false;
        }
        
        std::cout << "Max job experience patch applied successfully!" << std::endl;
        return true;
    }

    // Show All Pinups
    bool ShowAllPinups() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "ShowAllPinups";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Show all pinups is already active" << std::endl;
            return false;
        }
        
        // Pattern for Album:IsPinupUnlocked
        std::vector<BYTE> pattern = {0x55, 0x8B, 0xEC, 0x53, 0x57};
        std::string mask = "xxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find pinup unlock pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found pinup unlock pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to always return true (1)
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3                          // ret
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch pinup unlock" << std::endl;
            return false;
        }
        
        std::cout << "Show all pinups patch applied successfully!" << std::endl;
        return true;
    }

    // Unlock All Rewards and Girls
    bool UnlockAllRewardsAndGirls() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "UnlockAllRewardsAndGirls";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Unlock all rewards and girls is already active" << std::endl;
            return false;
        }
        
        // Pattern for AutoResizeBitArray:get_Item+42
        std::vector<BYTE> pattern = {0x8D, 0x44, 0x18, 0x10, 0x0F, 0xB6, 0x00, 0x89, 0x45};
        std::string mask = "xxxxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find rewards array pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found rewards array pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to set all bits to 1 (FF)
        std::vector<BYTE> patch = {
            0x8D, 0x44, 0x18, 0x10,       // lea eax, [eax+ebx+10]
            0xC6, 0x00, 0xFF,             // mov byte ptr [eax], FF
            0x0F, 0xB6, 0x00              // movzx eax, byte ptr [eax]
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch rewards unlock" << std::endl;
            return false;
        }
        
        std::cout << "Unlock all rewards and girls patch applied successfully!" << std::endl;
        return true;
    }

    // Unlock DLCs (NSFW DLC)
    bool UnlockDLCs() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "UnlockDLCs";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Unlock DLCs is already active" << std::endl;
            return false;
        }
        
        // Pattern from cheat table: 83 C4 10 C9 C3
        std::vector<BYTE> pattern = {0x83, 0xC4, 0x10, 0xC9, 0xC3};
        std::string mask = "xxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find DLC check pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found DLC check pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create the patch exactly like in Cheat Engine - force return value to 1 (true)
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xC4, 0x10,             // add esp, 10
            0xC9,                         // leave
            0xC3                          // ret
        };
        
        // Apply the patch exactly at patternAddress-5 like in Cheat Engine
        if (!PatchMemory(patternAddress - 5, patch, patchName)) {
            std::cout << "Failed to apply DLC unlock patch" << std::endl;
            return false;
        }
        
        std::cout << "DLC unlock patch applied successfully!" << std::endl;
        
        // Try to enable NSFW settings
        EnableNSFW();
        
        return true;
    }

    // Enable NSFW Settings
    bool EnableNSFW() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "EnableNSFW";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "NSFW settings are already enabled" << std::endl;
            return false;
        }
        
        // Pattern for GameState.NSFW reference
        std::vector<BYTE> pattern1 = {0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74}; // cmp byte ptr [GameState.NSFW], 0; je
        std::string mask1 = "xx????xx";
        
        uintptr_t reference = FindPatternAddress(pattern1, mask1);
        if (reference != 0) {
            // Found a reference to NSFW flag
            std::cout << "Found NSFW flag reference at: 0x" << std::hex << reference << std::dec << std::endl;
            
            // Read the address from the instruction
            int offset = ReadMemory<int>(reference + 2);
            uintptr_t nsfwAddr = reference + 7 + offset;
            
            // Write 1 to NSFW flag
            if (WriteMemory<BYTE>(nsfwAddr, 1)) {
                std::cout << "NSFW flag enabled at: 0x" << std::hex << nsfwAddr << std::dec << std::endl;
                
                // Assume NSFWAllowed is at nsfwAddr+1
                if (WriteMemory<BYTE>(nsfwAddr + 1, 1)) {
                    std::cout << "NSFWAllowed flag enabled" << std::endl;
                    
                    // Remember patch for restoration
                    PatchInfo info;
                    info.address = nsfwAddr;
                    info.originalBytes = {0x00, 0x00}; // Assume both were 0
                    info.name = patchName;
                    appliedPatches[patchName] = info;
                    
                    return true;
                }
            }
        }
        
        // Alternative approach: patch checks for NSFW flags
        // Scan for comparison checks against NSFW flag
        std::vector<BYTE> pattern2 = {0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84}; // cmp byte ptr [GameState.NSFW], 0; je far
        std::string mask2 = "xx????xxx";
        
        reference = FindPatternAddress(pattern2, mask2);
        if (reference != 0) {
            // Found a check against NSFW flag
            std::cout << "Found NSFW check at: 0x" << std::hex << reference << std::dec << std::endl;
            
            // Create patch to skip the check
            std::vector<BYTE> patch = {
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 // Replace with NOPs
            };
            
            if (PatchMemory(reference, patch, patchName)) {
                std::cout << "NSFW check patched" << std::endl;
                return true;
            }
        }
        
        std::cout << "Could not find or enable NSFW settings" << std::endl;
        std::cout << "Try restarting the game after enabling DLC unlock" << std::endl;
        return false;
    }

    // Disable Analytics
    bool DisableAnalytics() {
        if (!connected) {
            std::cout << "Not connected to the game" << std::endl;
            return false;
        }
        
        std::string patchName = "DisableAnalytics";
        
        // Check if already applied
        if (appliedPatches.find(patchName) != appliedPatches.end()) {
            std::cout << "Analytics are already disabled" << std::endl;
            return false;
        }
        
        // Pattern for analytics manager
        std::vector<BYTE> pattern = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0xE8};
        std::string mask = "xxxxxxx";
        
        uintptr_t patternAddress = FindPatternAddress(pattern, mask);
        if (patternAddress == 0) {
            std::cout << "Failed to find analytics pattern" << std::endl;
            return false;
        }
        
        std::cout << "Found analytics pattern at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Create patch to return immediately
        std::vector<BYTE> patch = {
            0xC3  // ret
        };
        
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch analytics" << std::endl;
            return false;
        }
        
        std::cout << "Analytics disabled successfully!" << std::endl;
        return true;
    }

    // Check if connected to the game
    bool IsConnected() const {
        return connected;
    }
};

// Main function
int main() {
    CrushCrushCheat cheat;
    
    std::cout << "Crush Crush Cheat - Educational Purposes Only\n";
    std::cout << "==============================================\n\n";
    
    std::cout << "This program requires administrator privileges to work correctly.\n";
    
    if (!cheat.Connect()) {
        std::cout << "Failed to connect to the game. Is it running?\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        return 1;
    }
    
    int choice = 0;
    while (true) {
        std::cout << "\nCrush Crush Cheat Menu:\n";
        std::cout << "1. No Messages Cooldown\n";
        std::cout << "2. Free Store Items\n";
        std::cout << "3. Meet Hearts Requirement\n";
        std::cout << "4. Meet All Requirements\n";
        std::cout << "5. Unlock All Outfits\n";
        std::cout << "6. Outfits Cost 1 Diamond\n";
        std::cout << "7. Gifts Cost No Diamonds\n";
        std::cout << "8. No Talk Cooldown\n";
        std::cout << "9. Max Hobby Level\n";
        std::cout << "10. No Job Cooldown\n";
        std::cout << "11. Max Job Experience\n";
        std::cout << "12. Show All Pinups\n";
        std::cout << "13. Unlock All Rewards and Girls\n";
        std::cout << "14. Unlock DLCs\n";
        std::cout << "15. Enable NSFW Settings\n";
        std::cout << "16. Disable Analytics\n";
        std::cout << "17. Restore a Specific Patch\n";
        std::cout << "18. Restore All Patches\n";
        std::cout << "19. Exit\n";
        std::cout << "Enter your choice (1-19): ";
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                cheat.NoMessagesCooldown();
                break;
            case 2:
                cheat.FreeStoreItems();
                break;
            case 3:
                cheat.MeetHeartsRequirement();
                break;
            case 4:
                cheat.MeetRequirements();
                break;
            case 5:
                cheat.UnlockAllOutfits();
                break;
            case 6:
                cheat.OutfitsCostOneDiamond();
                break;
            case 7:
                cheat.GiftsCostNoDiamonds();
                break;
            case 8:
                cheat.NoTalkCooldown();
                break;
            case 9:
                cheat.MaxHobbyLevel();
                break;
            case 10:
                cheat.NoJobCooldown();
                break;
            case 11:
                cheat.MaxJobExperience();
                break;
            case 12:
                cheat.ShowAllPinups();
                break;
            case 13:
                cheat.UnlockAllRewardsAndGirls();
                break;
            case 14:
                cheat.UnlockDLCs();
                break;
            case 15:
                cheat.EnableNSFW();
                break;
            case 16:
                cheat.DisableAnalytics();
                break;
            case 17: {
                // Restore a specific patch
                std::string patchName;
                std::cout << "Enter the name of the patch to restore (e.g. NoMessagesCooldown): ";
                std::cin >> patchName;
                cheat.RestorePatch(patchName);
                break;
            }
            case 18:
                cheat.RestoreAllPatches();
                break;
            case 19:
                std::cout << "Exiting...\n";
                return 0;
            default:
                std::cout << "Invalid choice, please try again.\n";
                break;
        }
    }
    
    return 0;
}
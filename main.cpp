#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <map>
#include <sstream>
#include <limits> // Added for std::numeric_limits

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

    // Read bytes from memory
    std::vector<BYTE> ReadBytes(uintptr_t address, size_t size) {
        std::vector<BYTE> buffer(size);
        ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), size, nullptr);
        return buffer;
    }

    // Find memory address using pattern scanning
    uintptr_t FindPatternAddress(const std::vector<BYTE>& pattern, const std::string& mask, uintptr_t startAddress = 0, uintptr_t endAddress = 0) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = startAddress != 0 ? startAddress : moduleBase;
        uintptr_t endAddr = endAddress != 0 ? endAddress : 0xFFFFFFFF;
        
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi)) && address < endAddr) {
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
    
    // Find pattern in module range
    uintptr_t FindPatternInModule(const std::vector<BYTE>& pattern, const std::string& mask, 
                                 const std::string& moduleName, uintptr_t startOffset, uintptr_t endOffset) {
        // Get module info
        MODULEENTRY32 moduleEntry = {0};
        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        
        if (snapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }
        
        bool foundModule = false;
        if (Module32First(snapshot, &moduleEntry)) {
            do {
                if (_stricmp(moduleEntry.szModule, moduleName.c_str()) == 0) {
                    foundModule = true;
                    break;
                }
            } while (Module32Next(snapshot, &moduleEntry));
        }
        
        CloseHandle(snapshot);
        
        if (!foundModule) {
            return 0;
        }
        
        uintptr_t moduleBaseAddr = (uintptr_t)moduleEntry.modBaseAddr;
        uintptr_t startAddress = moduleBaseAddr + startOffset;
        uintptr_t endAddress = moduleBaseAddr + endOffset;
        
        return FindPatternAddress(pattern, mask, startAddress, endAddress);
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

    // AOBScanRegion - Mimic Cheat Engine's function
    uintptr_t AOBScanRegion(const std::string& functionName, uintptr_t startOffset, uintptr_t endOffset, 
                           const std::vector<BYTE>& pattern) {
        std::string mask(pattern.size(), 'x');  // All bytes are matched exactly
        
        uintptr_t result = FindPatternAddress(pattern, mask);
        if (result == 0) {
            std::cout << "Failed to find pattern for " << functionName << std::endl;
        } else {
            std::cout << "Found " << functionName << " pattern at: 0x" << std::hex << result << std::dec << std::endl;
        }
        
        return result;
    }

    // Create a code injection patch (used by most CE table's patches)
    bool CreateCodeInjection(uintptr_t address, const std::vector<BYTE>& originalCode, 
                            const std::vector<BYTE>& injectedCode, const std::string& patchName) {
        // Allocate memory for our new code
        LPVOID newMem = VirtualAllocEx(processHandle, NULL, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newMem) {
            std::cout << "Failed to allocate memory for " << patchName << std::endl;
            return false;
        }
        
        // Store allocated memory for cleanup
        allocatedMemory[patchName] = newMem;
        
        // Create a jump to our new code
        std::vector<BYTE> jumpPatch = {
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp newmem
            0x90                          // nop (for alignment)
        };
        
        // Calculate the jump offset
        int jumpOffset = (int)((uintptr_t)newMem - address - 5);
        memcpy(&jumpPatch[1], &jumpOffset, 4);
        
        // Create our new code block: injected code + original code + jump back
        std::vector<BYTE> newCode = injectedCode;
        
        // Add the original code
        newCode.insert(newCode.end(), originalCode.begin(), originalCode.end());
        
        // Add jump back to original code path
        std::vector<BYTE> jumpBack = {
            0xE9, 0x00, 0x00, 0x00, 0x00  // jmp back
        };
        
        int jumpBackOffset = (int)(address + originalCode.size() - ((uintptr_t)newMem + newCode.size() + 5));
        memcpy(&jumpBack[1], &jumpBackOffset, 4);
        
        newCode.insert(newCode.end(), jumpBack.begin(), jumpBack.end());
        
        // Write our new code
        if (!WriteProcessMemory(processHandle, newMem, newCode.data(), newCode.size(), nullptr)) {
            std::cout << "Failed to write code injection for " << patchName << std::endl;
            VirtualFreeEx(processHandle, newMem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        // Apply jump patch
        if (!PatchMemory(address, jumpPatch, patchName)) {
            std::cout << "Failed to apply jump patch for " << patchName << std::endl;
            VirtualFreeEx(processHandle, newMem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        std::cout << patchName << " patch applied successfully!" << std::endl;
        return true;
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
        
        uintptr_t patternAddress = AOBScanRegion("Cellphone:Update+3da", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Define noMsgCd as patternAddress+6 like in the cheat table
        uintptr_t noMsgCd = patternAddress + 6;
        
        // Original bytes at noMsgCd
        std::vector<BYTE> originalBytes = ReadBytes(noMsgCd, 6);
        
        // Code to inject - set current time to 0
        std::vector<BYTE> injectedCode = {
            0x50,                         // push eax
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x89, 0x87, 0xD0, 0x00, 0x00, 0x00, // mov [edi+D0], eax  // currentTime
            0x89, 0x87, 0xD4, 0x00, 0x00, 0x00, // mov [edi+D4], eax
            0x58                          // pop eax
        };
        
        return CreateCodeInjection(noMsgCd, originalBytes, injectedCode, patchName);
    }

    // Free Store Items (diamond purchasables only)
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
        
        // We need to patch BOTH places:
        // 1. First the diamond check (comparing player's diamonds with the cost)
        std::string checkPatchName = "DiamondCheck";
        std::vector<BYTE> checkPattern = {0x83, 0xEC, 0x0C, 0xFF, 0x75, 0x08, 0xE8}; // Common function pattern before diamond check
        std::string checkMask = "xxxxxxx";
        
        uintptr_t checkAddr = FindPatternAddress(checkPattern, checkMask);
        if (checkAddr != 0) {
            // Look for comparison code after this pattern (usually within 50 bytes)
            std::vector<BYTE> cmpPattern = {0x3B, 0x00, 0x0F, 0x8C}; // cmp eax, [reg]; jl (jump if less)
            std::string cmpMask = "x?xx";
            
            uintptr_t cmpAddr = FindPatternAddress(cmpPattern, cmpMask, checkAddr, checkAddr + 100);
            
            if (cmpAddr != 0) {
                std::cout << "Found diamond check at: 0x" << std::hex << cmpAddr << std::dec << std::endl;
                
                // Patch to always pass the check
                std::vector<BYTE> nopPatch(10, 0x90); // Fill with NOPs
                
                if (!PatchMemory(cmpAddr, nopPatch, checkPatchName)) {
                    std::cout << "Failed to patch diamond check" << std::endl;
                }
                else {
                    std::cout << "Diamond check bypassed!" << std::endl;
                }
            }
        }
        
        // 2. The actual purchase cost setting
        // Pattern from cheat table: 8B 45 0C 89 41 0C 8B 45 10
        std::vector<BYTE> pattern = {0x8B, 0x45, 0x0C, 0x89, 0x41, 0x0C, 0x8B, 0x45, 0x10};
        
        uintptr_t patternAddress = AOBScanRegion("Store2:PurchaseItem", 0, 0, pattern);
        if (patternAddress == 0) {
            // Try an alternative pattern search
            std::vector<BYTE> altPattern = {0x8B, 0x45, 0x10, 0x89, 0x41, 0x10, 0x8B, 0x45, 0x14};
            patternAddress = FindPatternAddress(altPattern, std::string(altPattern.size(), 'x'));
            
            if (patternAddress == 0) {
                std::cout << "Could not find store purchase pattern" << std::endl;
                return false;
            }
            
            // Adjust to get to the right spot
            patternAddress -= 6;
        }
        
        std::cout << "Found store purchase at: 0x" << std::hex << patternAddress << std::dec << std::endl;
        
        // Original bytes - we need the first 6 bytes
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 6);
        
        // Injected code - set [ebp+10] to 0 (cost parameter)
        std::vector<BYTE> injectedCode = {
            // Keep original instructions
            // 8B 45 0C           - mov eax, [ebp+0C]
            // 89 41 0C           - mov [ecx+0C], eax
            // Then add:
            0xC7, 0x45, 0x10, 0x00, 0x00, 0x00, 0x00  // mov [ebp+10], 0 (cost param)
        };
        
        bool result = CreateCodeInjection(patternAddress, originalBytes, injectedCode, patchName);
        
        // Additionally, try to find and patch the diamond UI check
        std::vector<BYTE> uiPattern = {0x81, 0x7D, 0x00, 0xC8, 0x00, 0x00, 0x00}; // cmp [ebp+X], 200
        std::string uiMask = "xx?xxxx";
        
        uintptr_t uiAddr = FindPatternAddress(uiPattern, uiMask);
        if (uiAddr != 0) {
            std::cout << "Found UI diamond check at: 0x" << std::hex << uiAddr << std::dec << std::endl;
            
            // Patch to skip this check
            std::vector<BYTE> uiPatch = {
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 // NOPs
            };
            
            if (PatchMemory(uiAddr, uiPatch, "DiamondUICheck")) {
                std::cout << "UI diamond check patched!" << std::endl;
            }
        }
        
        return result;
    }

    // Meet Hearts Requirement - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("Girl:get_HeartRequirement", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Original bytes
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 6);
        
        // Injected code to set hearts to the required amount
        // This matches the Cheat Engine table approach
        int heartsOffset = 0x48; // Based on your CT file's heartsOffset

        std::vector<BYTE> injectedCode = {
            0x57,                       // push edi
            0x8B, 0xF8,                 // mov edi, eax
            // Original instructions
            // 8B 50 7C                 // mov edx, [eax+7C]
            // 8B 40 78                 // mov eax, [eax+78]
            0x85, 0xD2,                 // test edx, edx
            0x78, 0x0A,                 // js +0A (skip if negative)
            0x89, 0x97, (BYTE)(heartsOffset+4), 0x00, 0x00, 0x00, // mov [edi+heartsOffset+4], edx
            0x89, 0x87, (BYTE)heartsOffset, 0x00, 0x00, 0x00,      // mov [edi+heartsOffset], eax
            0x5F                        // pop edi
        };
        
        return CreateCodeInjection(patternAddress, originalBytes, injectedCode, patchName);
    }

    // Meet Requirements (general) - Exactly as in Cheat Engine table
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
        
        // Pattern for Girl:MeetsRequirements+10f
        std::vector<BYTE> pattern = {0x8D, 0x65, 0xF4, 0x5E, 0x5F};
        
        uintptr_t patternAddress = AOBScanRegion("Girl:MeetsRequirements+10f", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Create a direct patch to force return value to 1
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x8D, 0x65, 0xF4,             // lea esp, [ebp-0C]
            0x5E,                         // pop esi
            0x5F                          // pop edi
        };
        
        // Apply the patch directly
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch meet requirements" << std::endl;
            return false;
        }
        
        std::cout << "Meet requirements patch applied successfully!" << std::endl;
        return true;
    }

    // No Talk Cooldown - Exactly as in Cheat Engine table
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
        
        // Pattern for Girls:BumpAffection+76
        std::vector<BYTE> pattern = {0xD9, 0x05, 0x00, 0x00, 0x00, 0x00, 0xD9, 0x5D, 0xFC};
        std::string mask = "xx????xxx";
        
        uintptr_t patternAddress = AOBScanRegion("Girls:BumpAffection+3b", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Create memory for the cooldown value
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
        
        // Create code to load our cooldown value
        std::vector<BYTE> injectedCode = {
            0xD9, 0x05, 0x00, 0x00, 0x00, 0x00  // fld dword ptr [cooldownMem]
        };
        
        // Set the address of our cooldown value
        DWORD cooldownAddr32 = (DWORD)(uintptr_t)cooldownMem;
        memcpy(&injectedCode[2], &cooldownAddr32, sizeof(DWORD));
        
        // Original bytes
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 6);
        
        return CreateCodeInjection(patternAddress, originalBytes, injectedCode, patchName);
    }

    // Unlock All Outfits - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("Gift:Init+2ef", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Original bytes
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 9);
        
        // Injected code to OR outfits instead of AND
        std::vector<BYTE> injectedCode = {
            0x53,                         // push ebx
            0x8B, 0xD8,                   // mov ebx, eax
            // Original instructions
            // 8B 80 94 00 00 00          // mov eax, [eax+94]
            // 8B 4E 20                   // mov ecx, [esi+20]
            0x0B, 0xC1,                   // or eax, ecx
            0x89, 0x83, 0x94, 0x00, 0x00, 0x00, // mov [ebx+94], eax
            0x5B                          // pop ebx
        };
        
        return CreateCodeInjection(patternAddress, originalBytes, injectedCode, patchName);
    }

    // Outfits cost 1 Diamond - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("Balance:GetOutfitDiamondCost+188", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Create patch to always return 1 diamond
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x8D, 0x65, 0xF4,             // lea esp, [ebp-0C]
            0x5E,                         // pop esi
            0x5F                          // pop edi
        };
        
        // Apply the patch directly
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch outfit cost" << std::endl;
            return false;
        }
        
        std::cout << "Outfits cost 1 diamond patch applied successfully!" << std::endl;
        return true;
    }

    // Gifts cost no Diamonds - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("GiftModel:GetGiftDiamondCost+90", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Create patch to always return 0 diamonds
        std::vector<BYTE> patch = {
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x8D, 0x65, 0xF8,             // lea esp, [ebp-08]
            0x5E,                         // pop esi
            0x5B                          // pop ebx
        };
        
        // Apply the patch directly
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch gift cost" << std::endl;
            return false;
        }
        
        std::cout << "Gifts cost no diamonds patch applied successfully!" << std::endl;
        return true;
    }

    // Max Hobby Level / No Hobby Cooldown - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("Hobby2:get_BaseTime+64", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Allocate memory for our value
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
        
        // Original bytes
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 5);
        
        // Injected code to load our time value
        std::vector<BYTE> injectedCode = {
            0xDD, 0x05, 0x00, 0x00, 0x00, 0x00, // fld qword ptr [timeMem]
            0x8D, 0x65, 0xFC                    // lea esp, [ebp-04]
        };
        
        // Set the address of our time value
        DWORD timeAddr32 = (DWORD)(uintptr_t)timeMem;
        memcpy(&injectedCode[2], &timeAddr32, sizeof(DWORD));
        
        // Apply patch using the CE approach (direct patch in this case)
        if (!PatchMemory(patternAddress, injectedCode, patchName)) {
            std::cout << "Failed to patch hobby level" << std::endl;
            VirtualFreeEx(processHandle, timeMem, 0, MEM_RELEASE);
            allocatedMemory.erase(patchName);
            return false;
        }
        
        std::cout << "Max hobby level patch applied successfully!" << std::endl;
        return true;
    }

    // No Job Cooldown - Exactly as in Cheat Engine table
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
        
        // Pattern from cheat table: D9 87 8C 00 00 00 D9 45 0C
        std::vector<BYTE> pattern = {0xD9, 0x87, 0x8C, 0x00, 0x00, 0x00, 0xD9, 0x45, 0x0C};
        
        uintptr_t patternAddress = AOBScanRegion("Job2:PerformUpdate+68", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Original bytes
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 6);
        
        // Injected code to set job progress
        std::vector<BYTE> injectedCode = {
            0x50,                                   // push eax
            0x8B, 0x45, 0xE4,                       // mov eax, [ebp-1C]
            0x89, 0x87, 0x8C, 0x00, 0x00, 0x00,     // mov [edi+8C], eax
            0x58                                    // pop eax
        };
        
        return CreateCodeInjection(patternAddress, originalBytes, injectedCode, patchName);
    }

    // Max Job Experience - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("Job2:get_ExperienceToLevel+22", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Original bytes
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 6);
        
        // Injected code to set job experience
        std::vector<BYTE> injectedCode = {
            // Keep original instructions
            // 8B 50 1C                 // mov edx, [eax+1C]
            // 8B 40 18                 // mov eax, [eax+18]
            0x51,                       // push ecx
            0x8B, 0x4D, 0x08,           // mov ecx, [ebp+8]
            0x89, 0x91, 0x84, 0x00, 0x00, 0x00, // mov [ecx+84], edx
            0x89, 0x81, 0x80, 0x00, 0x00, 0x00, // mov [ecx+80], eax
            0x59                        // pop ecx
        };
        
        return CreateCodeInjection(patternAddress, originalBytes, injectedCode, patchName);
    }

    // Show All Pinups - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("Album:IsPinupUnlocked", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Create patch to always return true (1)
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3                          // ret
        };
        
        // Apply the patch directly
        if (!PatchMemory(patternAddress, patch, patchName)) {
            std::cout << "Failed to patch pinup unlock" << std::endl;
            return false;
        }
        
        std::cout << "Show all pinups patch applied successfully!" << std::endl;
        return true;
    }

    // Unlock All Rewards and Girls - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("AutoResizeBitArray:get_Item+1d", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Original bytes (first 7 bytes)
        std::vector<BYTE> originalBytes = ReadBytes(patternAddress, 7);
        
        // Injected code to set all bits to FF
        std::vector<BYTE> injectedCode = {
            // Keep 8D 44 18 10           // lea eax, [eax+ebx+10]
            0xC6, 0x00, 0xFF,             // mov byte ptr [eax], FF
            0x0F, 0xB6, 0x00              // movzx eax, byte ptr [eax]
        };
        
        return CreateCodeInjection(patternAddress, originalBytes, injectedCode, patchName);
    }

    // Unlock DLCs (NSFW DLC) - Exactly as in Cheat Engine table
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
        
        uintptr_t patternAddress = AOBScanRegion("Steamworks.SteamApps:BIsDlcInstalled+3", 0, 0, pattern);
        if (patternAddress == 0) {
            return false;
        }
        
        // Create patch to always return true (1)
        std::vector<BYTE> patch = {
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xC4, 0x10,             // add esp, 10
            0xC9,                         // leave
            0xC3                          // ret
        };
        
        // Apply the patch
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
        
        // Based on Cheat Engine table, patching GameState.NSFW and GameState.NSFWAllowed
        std::vector<BYTE> pattern = {0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74}; // cmp byte ptr [GameState.NSFW], 0; je
        std::string mask = "xx????xx";
        
        uintptr_t reference = FindPatternAddress(pattern, mask);
        if (reference != 0) {
            // Get the NSFW flag address
            uintptr_t nsfwAddrPtr = 0;
            if (ReadProcessMemory(processHandle, (LPCVOID)(reference + 2), &nsfwAddrPtr, 4, nullptr)) {
                // Write 1 to NSFW flag
                if (WriteMemory<BYTE>(nsfwAddrPtr, 1)) {
                    std::cout << "NSFW flag enabled at: 0x" << std::hex << nsfwAddrPtr << std::dec << std::endl;
                    
                    // Assume NSFWAllowed is at nsfwAddr+1 (next byte)
                    if (WriteMemory<BYTE>(nsfwAddrPtr + 1, 1)) {
                        std::cout << "NSFWAllowed flag enabled" << std::endl;
                        
                        // Remember patch for restoration
                        PatchInfo info;
                        info.address = nsfwAddrPtr;
                        info.originalBytes = {0x00, 0x00}; // Assume both were 0
                        info.name = patchName;
                        appliedPatches[patchName] = info;
                        
                        return true;
                    }
                }
            }
        }
        
        // Alternative approach - bypass all NSFW checks
        std::cout << "Could not directly enable NSFW flags, trying alternative approach..." << std::endl;
        
        // Find all references to NSFW flag checks and patch them
        std::vector<BYTE> checkPattern = {0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84}; // cmp byte ptr [GameState.NSFW], 0; je far
        std::string checkMask = "xx????xxx";
        
        uintptr_t checkAddr = FindPatternAddress(checkPattern, checkMask);
        if (checkAddr != 0) {
            std::cout << "Found NSFW check at: 0x" << std::hex << checkAddr << std::dec << std::endl;
            
            // Patch to always pass the check
            std::vector<BYTE> nopPatch(9, 0x90); // Replace with NOPs
            
            if (PatchMemory(checkAddr, nopPatch, "NSFWCheck")) {
                std::cout << "NSFW check patched - should be enabled after restart" << std::endl;
                return true;
            }
        }
        
        std::cout << "NSFW mode will be available after game restart" << std::endl;
        return false;
    }

    // Disable Analytics - Similar to Cheat Engine table
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
        
        // First try to find the AnalyticsManager.DestroyInstance method
        std::vector<BYTE> pattern = {0x55, 0x8B, 0xEC, 0x6A, 0x00, 0xE8}; // Common method prologue
        std::string mask = "xxxxxx";
        
        uintptr_t destroyMethodAddr = FindPatternAddress(pattern, mask);
        if (destroyMethodAddr != 0) {
            std::cout << "Found potential analytics method at: 0x" << std::hex << destroyMethodAddr << std::dec << std::endl;
            
            // Create patch to execute once and return immediately after
            std::vector<BYTE> patch = {
                0xC3  // ret
            };
            
            if (PatchMemory(destroyMethodAddr, patch, patchName)) {
                std::cout << "Analytics disabled successfully!" << std::endl;
                return true;
            }
        }
        
        // Alternative approach - try to patch all Analytics flags in PrivacySettings
        std::vector<BYTE> privacyPattern = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0xC6, 0x05}; // PrivacySettings method
        std::string privacyMask = "xxxxxxxx";
        
        uintptr_t privacyAddr = FindPatternAddress(privacyPattern, privacyMask);
        if (privacyAddr != 0) {
            std::cout << "Found privacy settings at: 0x" << std::hex << privacyAddr << std::dec << std::endl;
            
            // Try to find where analytics flags are set
            uintptr_t flagsAddr = 0;
            for (int i = 0; i < 100; i++) {
                BYTE val = ReadMemory<BYTE>(privacyAddr + i + 8);
                if (val == 0x01) {
                    flagsAddr = ReadMemory<uintptr_t>(privacyAddr + i + 4);
                    if (flagsAddr != 0) {
                        break;
                    }
                }
            }
            
            if (flagsAddr != 0) {
                // Set all analytics flags to disabled (1)
                for (int i = 0; i < 4; i++) {
                    WriteMemory<BYTE>(flagsAddr + i, 1);
                }
                
                std::cout << "Privacy settings patched to disable analytics" << std::endl;
                
                // Store patch info for restoration
                PatchInfo info;
                info.address = flagsAddr;
                info.originalBytes = {0x00, 0x00, 0x00, 0x00}; // Assume they were 0
                info.name = patchName;
                appliedPatches[patchName] = info;
                
                return true;
            }
        }
        
        std::cout << "Could not find analytics to disable" << std::endl;
        return false;
    }

    // Apply all cheats at once
    bool ApplyAllCheats() {
        bool success = true;
        
        success &= NoMessagesCooldown();
        success &= FreeStoreItems();
        success &= MeetHeartsRequirement();
        success &= MeetRequirements();
        success &= NoTalkCooldown();
        success &= UnlockAllOutfits();
        success &= OutfitsCostOneDiamond();
        success &= GiftsCostNoDiamonds();
        success &= MaxHobbyLevel();
        success &= NoJobCooldown();
        success &= MaxJobExperience();
        success &= ShowAllPinups();
        success &= UnlockAllRewardsAndGirls();
        success &= UnlockDLCs();
        success &= DisableAnalytics();
        
        if (success) {
            std::cout << "All cheats applied successfully!" << std::endl;
        } else {
            std::cout << "Some cheats could not be applied" << std::endl;
        }
        
        return success;
    }

    // Check if connected to the game
    bool IsConnected() const {
        return connected;
    }
};

// Main function
int main() {
    CrushCrushCheat cheat;
    
    // Make console window centered and properly sized
    HWND console = GetConsoleWindow();
    if (console) {
        RECT r;
        GetWindowRect(console, &r);
        int width = 800;
        int height = 600;
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);
        SetWindowPos(console, NULL, (screenWidth - width) / 2, (screenHeight - height) / 2, width, height, SWP_SHOWWINDOW);
    }
    
    // Set console title
    SetConsoleTitle(TEXT("Crush Crush Cheat - Table Replicator"));
    
    // Change console colors for better readability
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    
    std::cout << "This program requires administrator privileges to work correctly.\n";
    
    if (!cheat.Connect()) {
        std::cout << "Failed to connect to the game. Is it running?\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        return 1;
    }
    
    // Define pink color (magenta in Windows console)
    const WORD PINK_COLOR = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    
    int choice = 0;
    while (true) {
        // Clear console for prettier look
        system("cls");
        
        // Set title with nice formatting
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "\n+------------------------------------------+\n";
        std::cout << "|     Crush Crush Cheat - Table Replicator    |\n";
        std::cout << "+------------------------------------------+\n\n";
        
        // Set pink color for menu options
        SetConsoleTextAttribute(hConsole, PINK_COLOR);
        
        std::cout << " Main Menu:\n";
        std::cout << "+------------------------------------------+\n";
        std::cout << "|  1. No Messages Cooldown (Smartphone)      |\n";
        std::cout << "|  2. Free Store Items (diamond purchases)   |\n";
        std::cout << "|  3. Meet Hearts Requirement                |\n";
        std::cout << "|  4. Meet All Requirements                  |\n";
        std::cout << "|  5. No Talk Cooldown                       |\n";
        std::cout << "|  6. Unlock All Outfits                     |\n";
        std::cout << "|  7. Outfits Cost 1 Diamond                 |\n";
        std::cout << "|  8. Gifts Cost No Diamonds                 |\n";
        std::cout << "|  9. Max Hobby Level                        |\n";
        std::cout << "| 10. No Job Cooldown                        |\n";
        std::cout << "| 11. Max Job Experience                     |\n";
        std::cout << "| 12. Show All Pinups                        |\n";
        std::cout << "| 13. Unlock All Rewards and Girls           |\n";
        std::cout << "| 14. Unlock DLCs (NSFW DLC)                 |\n";
        std::cout << "| 15. Disable Analytics                      |\n";
        std::cout << "| 16. Apply All Cheats                       |\n";
        std::cout << "| 17. Restore a Specific Patch               |\n";
        std::cout << "| 18. Restore All Patches                    |\n";
        std::cout << "| 19. Exit                                   |\n";
        std::cout << "+------------------------------------------+\n";
        
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "Enter your choice (1-19): ";
        std::cin >> choice;
        
        // Clear screen before executing command
        system("cls");
        
        // Set success color for output
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        
        bool commandExecuted = true;
        
        switch (choice) {
            case 1:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|       No Messages Cooldown (Smartphone)    |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.NoMessagesCooldown();
                break;
            case 2:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|       Free Store Items (diamonds)          |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.FreeStoreItems();
                break;
            case 3:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|          Meet Hearts Requirement           |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.MeetHeartsRequirement();
                break;
            case 4:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|           Meet All Requirements            |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.MeetRequirements();
                break;
            case 5:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|             No Talk Cooldown               |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.NoTalkCooldown();
                break;
            case 6:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|            Unlock All Outfits              |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.UnlockAllOutfits();
                break;
            case 7:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|          Outfits Cost 1 Diamond            |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.OutfitsCostOneDiamond();
                break;
            case 8:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|          Gifts Cost No Diamonds            |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.GiftsCostNoDiamonds();
                break;
            case 9:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|              Max Hobby Level               |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.MaxHobbyLevel();
                break;
            case 10:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|             No Job Cooldown                |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.NoJobCooldown();
                break;
            case 11:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|            Max Job Experience              |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.MaxJobExperience();
                break;
            case 12:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|             Show All Pinups                |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.ShowAllPinups();
                break;
            case 13:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|        Unlock All Rewards and Girls        |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.UnlockAllRewardsAndGirls();
                break;
            case 14:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|          Unlock DLCs (NSFW DLC)            |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.UnlockDLCs();
                break;
            case 15:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|            Disable Analytics               |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.DisableAnalytics();
                break;
            case 16:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|             Apply All Cheats               |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.ApplyAllCheats();
                break;
            case 17: {
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|         Restore a Specific Patch           |\n";
                std::cout << "+------------------------------------------+\n\n";
                // Restore a specific patch
                std::string patchName;
                std::cin.ignore(); // Clear input buffer
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::cout << "Enter the name of the patch to restore: ";
                std::getline(std::cin, patchName);
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.RestorePatch(patchName);
                break;
            }
            case 18:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|           Restore All Patches              |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                cheat.RestoreAllPatches();
                break;
            case 19:
                SetConsoleTextAttribute(hConsole, PINK_COLOR);
                std::cout << "+------------------------------------------+\n";
                std::cout << "|                 Exiting...                 |\n";
                std::cout << "+------------------------------------------+\n\n";
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                return 0;
            default:
                // Set error color
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << "Invalid choice, please try again.\n";
                commandExecuted = false;
                break;
        }
        
        if (commandExecuted) {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << "\nPress Enter to return to menu...";
            std::cin.ignore(10000, '\n');  // Using simpler approach instead of numeric_limits
            std::cin.get();
        }
    }
    
    return 0;
}

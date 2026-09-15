-- valv.yazi
-- Yazi plugin to transparently mount, encrypt, and decrypt files with Valv

local M = {}

local get_targets = ya.sync(function()
	local tab = cx.active
	local paths = {}
	if #tab.selected == 0 then
		if tab.current.hovered then
			table.insert(paths, tostring(tab.current.hovered.url))
		end
	else
		for _, file in pairs(tab.selected) do
			table.insert(paths, tostring(file.url))
		end
	end
	return paths
end)

local get_current_cwd = ya.sync(function()
	return tostring(cx.active.current.cwd)
end)

local function is_valv_path(path)
	local filename = path:match("[^/\\]+$") or path
	return filename:sub(-5) == ".valv" or filename:sub(1, 6) == ".valv."
end

local function file_exists(path)
	local f = io.open(path, "r")
	if f then
		f:close()
		return true
	end
	return false
end

function M:entry(job)
	local cwd = get_current_cwd()

	-- Case 1: Currently inside an active Valv mount session
	if cwd:find("/valv%-") or file_exists(cwd .. "/.valv_session.json") then
		local confirm, event = ya.input {
			pos = { "top-center", y = 3, w = 40 },
			title = "Lock and unmount vault? (Y/n)",
		}
		if event == 1 and (confirm == "" or confirm:lower() == "y") then
			-- Read session to find original vault directory
			local orig_vault = nil
			local f = io.open(cwd .. "/.valv_session.json", "r")
			if f then
				local content = f:read("*a")
				f:close()
				orig_vault = content:match('"vault_dir"%s*:%s*"([^"]+)"')
			end

			local output, err = Command("valv")
				:arg("unmount")
				:arg(cwd)
				:output()

			if orig_vault and file_exists(orig_vault) then
				ya.emit("cd", { orig_vault })
			else
				ya.emit("cd", { ".." })
			end

			ya.notify {
				title = "Valv",
				content = "Vault locked and unmounted",
				timeout = 3.0,
			}
		end
		return
	end

	local targets = get_targets()

	-- Case 2: Target is a directory containing a vault, or we want to mount current directory
	local target_is_dir = false
	local vault_target_dir = cwd
	if #targets == 1 then
		local f = io.open(targets[1] .. "/.", "r")
		if f then
			f:close()
			target_is_dir = true
			vault_target_dir = targets[1]
		end
	end

	-- Check if user wants to mount this directory as a transparent vault
	local is_mount_candidate = target_is_dir
	if not is_mount_candidate and #targets == 0 then
		is_mount_candidate = true
		vault_target_dir = cwd
	end

	if is_mount_candidate then
		local password, event = ya.input {
			pos = { "top-center", y = 3, w = 40 },
			title = "Open Vault Password:",
			obscure = true,
		}

		if event ~= 1 or not password or #password == 0 then
			return
		end

		local child, err = Command("valv")
			:arg("mount")
			:arg(vault_target_dir)
			:arg("--stdin-password")
			:stdin(Command.PIPED)
			:stdout(Command.PIPED)
			:stderr(Command.PIPED)
			:spawn()

		if not child or err then
			ya.notify {
				title = "Valv Error",
				content = "Failed to spawn valv: " .. tostring(err),
				level = "error",
				timeout = 5.0,
			}
			return
		end

		child:write_all(password .. "\n")
		child:flush()

		local output, wait_err = child:wait_with_output()
		if not output or wait_err then
			ya.notify {
				title = "Valv Error",
				content = "Process error: " .. tostring(wait_err),
				level = "error",
				timeout = 5.0,
			}
			return
		end

		if output.status.code == 2 then
			ya.notify {
				title = "Valv",
				content = "Incorrect password for vault",
				level = "error",
				timeout = 5.0,
			}
			return
		elseif not output.status.success then
			local msg = output.stderr:gsub("^%s+", ""):gsub("%s+$", "")
			ya.notify {
				title = "Valv Error",
				content = #msg > 0 and msg or "Mount failed",
				level = "error",
				timeout = 5.0,
			}
			return
		end

		-- Parse mount directory from stdout: "READY /dev/shm/valv-..."
		local mount_path = output.stdout:match("READY%s+([^\r\n]+)")
		if mount_path then
			ya.emit("cd", { mount_path })
			ya.notify {
				title = "Valv",
				content = "Vault transparently mounted. Auto-encryption active.",
				timeout = 4.0,
			}
		end
		return
	end

	-- Case 3: Encrypt or decrypt specific file(s)
	local valv_count = 0
	for _, path in ipairs(targets) do
		if is_valv_path(path) then
			valv_count = valv_count + 1
		end
	end

	local action = valv_count > 0 and "decrypt" or "encrypt"
	local prompt_title = action == "decrypt" and "Valv Decrypt Password:" or "Valv Encrypt Password:"
	local password, event = ya.input {
		pos = { "top-center", y = 3, w = 40 },
		title = prompt_title,
		obscure = true,
	}

	if event ~= 1 or not password or #password == 0 then
		return
	end

	local cmd = Command("valv")
		:arg(action)
		:arg("--stdin-password")

	for _, path in ipairs(targets) do
		cmd = cmd:arg(path)
	end

	local child, err = cmd
		:stdin(Command.PIPED)
		:stdout(Command.PIPED)
		:stderr(Command.PIPED)
		:spawn()

	if not child or err then
		ya.notify {
			title = "Valv Error",
			content = "Failed to run 'valv' command: " .. tostring(err),
			level = "error",
			timeout = 5.0,
		}
		return
	end

	child:write_all(password .. "\n")
	child:flush()

	local output, wait_err = child:wait_with_output()
	if not output or wait_err then
		ya.notify {
			title = "Valv Error",
			content = "Process error: " .. tostring(wait_err),
			level = "error",
			timeout = 5.0,
		}
		return
	end

	if output.status.code == 2 then
		ya.notify {
			title = "Valv",
			content = "Incorrect password",
			level = "error",
			timeout = 5.0,
		}
	elseif not output.status.success then
		local msg = output.stderr:gsub("^%s+", ""):gsub("%s+$", "")
		if #msg == 0 then
			msg = "Failed with exit code " .. tostring(output.status.code)
		end
		ya.notify {
			title = "Valv Error",
			content = msg,
			level = "error",
			timeout = 5.0,
		}
	else
		local verb = action == "decrypt" and "Decrypted" or "Encrypted"
		ya.notify {
			title = "Valv",
			content = string.format("%s %d file(s)", verb, #targets),
			timeout = 3.0,
		}
		ya.emit("escape", {})
	end
end

return M

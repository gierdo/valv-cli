-- valv.yazi
-- Yazi plugin to transparently mount, create, encrypt, and decrypt Age and Valv vaults

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

local function file_exists(path)
	local f = io.open(path, "r")
	if f then
		f:close()
		return true
	end
	return false
end

local function is_vault_file(path)
	local filename = (path:match("[^/\\]+$") or path):lower()
	return filename:sub(-5) == ".valv"
		or filename:sub(-4) == ".age"
		or filename:find("^%.?age_vault%.toml") ~= nil
end

local function dir_has_vault_content(dir)
	local manifest_names = {
		".age_vault.toml.age",
		"age_vault.toml.age",
		".age_vault.toml.valv",
		"age_vault.toml.valv",
		".age_vault.toml",
		"age_vault.toml",
		".valv_session.json",
	}
	for _, name in ipairs(manifest_names) do
		if file_exists(dir .. "/" .. name) then
			return true
		end
	end
	return false
end

local function parse_recipients(input_str)
	local recips = {}
	if not input_str or #input_str:gsub("%s+", "") == 0 then
		return recips
	end

	if input_str:find(",") then
		for r in input_str:gmatch("[^,]+") do
			local trimmed = r:match("^%s*(.-)%s*$")
			if #trimmed > 0 then
				table.insert(recips, trimmed)
			end
		end
	else
		local trimmed = input_str:match("^%s*(.-)%s*$")
		if #trimmed > 0 then
			if trimmed:find(" age1") then
				for r in trimmed:gmatch("%S+") do
					table.insert(recips, r)
				end
			else
				table.insert(recips, trimmed)
			end
		end
	end
	return recips
end

local function run_valv(args, password, quiet)
	local cmd = Command("valv")
	for _, arg in ipairs(args) do
		cmd = cmd:arg(arg)
	end
	if password then
		cmd = cmd:arg("--stdin-password")
	end

	local child, err = cmd
		:stdin(password and Command.PIPED or Command.INHERIT)
		:stdout(Command.PIPED)
		:stderr(Command.PIPED)
		:spawn()

	if not child or err then
		if not quiet then
			ya.notify {
				title = "Valv Error",
				content = "Failed to run 'valv': " .. tostring(err),
				level = "error",
				timeout = 5.0,
			}
		end
		return nil
	end

	if password then
		child:write_all(password .. "\n")
		child:flush()
	end

	local output, wait_err = child:wait_with_output()
	if not output or wait_err then
		if not quiet then
			ya.notify {
				title = "Valv Error",
				content = "Process error: " .. tostring(wait_err),
				level = "error",
				timeout = 5.0,
			}
		end
		return nil
	end

	if output.status.code == 2 then
		if not quiet then
			ya.notify {
				title = "Valv",
				content = "Incorrect password or identity decryption failed",
				level = "error",
				timeout = 5.0,
			}
		end
		return output
	elseif not output.status.success then
		if not quiet then
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
		end
		return output
	end

	return output
end

local function mount_vault(vault_dir)
	-- 1. Try automatic mount with identities (SOPS/config age identities)
	local output = run_valv({ "mount", vault_dir }, nil, true)
	if output and output.status.success then
		local mount_path = output.stdout:match("READY%s+([^\r\n]+)")
		if mount_path then
			ya.emit("cd", { mount_path })
			ya.notify {
				title = "Valv",
				content = "Vault transparently mounted with identity. Auto-encryption active.",
				timeout = 4.0,
			}
			return true
		end
	end

	-- 2. Prompt for password/passphrase if needed
	local password, event = ya.input {
		title = "Open Vault Password/Passphrase:",
		pos = { "top-center", y = 3, w = 40 },
		obscure = true,
	}

	if event ~= 1 or not password or #password == 0 then
		return false
	end

	output = run_valv({ "mount", vault_dir, "--valv" }, password, false)
	if output and output.status.success then
		local mount_path = output.stdout:match("READY%s+([^\r\n]+)")
		if mount_path then
			ya.emit("cd", { mount_path })
			ya.notify {
				title = "Valv",
				content = "Vault transparently mounted. Auto-encryption active.",
				timeout = 4.0,
			}
			return true
		end
	end

	return false
end

local function create_age_vault(vault_dir)
	local recip_input, event = ya.input {
		title = "Age recipient public key (leave empty to use local SOPS/config identity):",
		pos = { "top-center", y = 3, w = 60 },
	}
	if event ~= 1 then
		return false
	end

	local recips = parse_recipients(recip_input)
	local args = { "init", vault_dir }
	for _, r in ipairs(recips) do
		table.insert(args, "-r")
		table.insert(args, r)
	end

	if #recips > 0 then
		local output = run_valv(args, nil, false)
		if output and output.status.success then
			ya.notify {
				title = "Valv",
				content = "Created Age vault with specified recipient(s). Mounting...",
				timeout = 3.0,
			}
			return mount_vault(vault_dir)
		end
	else
		-- Try auto-init with identity from SOPS / config
		local output = run_valv(args, nil, true)
		if output and output.status.success then
			ya.notify {
				title = "Valv",
				content = "Created Age vault with local identity. Mounting...",
				timeout = 3.0,
			}
			return mount_vault(vault_dir)
		else
			-- If no local identity key exists, prompt for passphrase
			local pwd, p_ev = ya.input {
				title = "Set Age Vault Passphrase:",
				pos = { "top-center", y = 3, w = 40 },
				obscure = true,
			}
			if p_ev ~= 1 or not pwd or #pwd == 0 then
				return false
			end
			local out = run_valv({ "init", vault_dir, "--age" }, pwd, false)
			if out and out.status.success then
				ya.notify {
					title = "Valv",
					content = "Created Age vault with passphrase. Mounting...",
					timeout = 3.0,
				}
				return mount_vault(vault_dir)
			end
		end
	end

	return false
end

local function create_valv_vault(vault_dir)
	local pwd, p_ev = ya.input {
		title = "Set Valv Vault Password:",
		pos = { "top-center", y = 3, w = 40 },
		obscure = true,
	}
	if p_ev ~= 1 or not pwd or #pwd == 0 then
		return false
	end

	local out = run_valv({ "init", vault_dir, "--valv" }, pwd, false)
	if out and out.status.success then
		ya.notify {
			title = "Valv",
			content = "Created Valv v2 vault. Mounting...",
			timeout = 3.0,
		}
		return mount_vault(vault_dir)
	end
	return false
end

function M:entry(job)
	local cwd = get_current_cwd()

	-- Case 1: Inside active Valv mount session -> lock/unmount
	if cwd:find("/valv%-") or file_exists(cwd .. "/.valv_session.json") then
		local confirm, event = ya.input {
			title = "Lock and unmount vault? (Y/n)",
			pos = { "top-center", y = 3, w = 40 },
		}
		if event == 1 and (confirm == "" or confirm:lower() == "y") then
			local orig_vault = nil
			local f = io.open(cwd .. "/.valv_session.json", "r")
			if f then
				local content = f:read("*a")
				f:close()
				orig_vault = content:match('"vault_dir"%s*:%s*"([^"]+)"')
			end

			local output = run_valv({ "unmount", cwd }, nil, false)
			if output and output.status.success then
				if orig_vault and file_exists(orig_vault) then
					ya.emit("cd", { orig_vault })
				else
					ya.emit("cd", { ".." })
				end

				ya.notify {
					title = "Valv",
					content = "Vault locked and memory wiped",
					timeout = 3.0,
				}
			end
		end
		return
	end

	local targets = get_targets()

	-- Handle direct CLI subcommand argument
	local subcmd = job and job.args and job.args[1]
	if subcmd == "init" or subcmd == "create" then
		local target_dir = (#targets == 1 and file_exists(targets[1] .. "/.")) and targets[1] or cwd
		create_age_vault(target_dir)
		return
	elseif subcmd == "unmount" or subcmd == "lock" then
		local target = #targets > 0 and targets[1] or cwd
		run_valv({ "unmount", target }, nil, false)
		return
	elseif subcmd == "mount" or subcmd == "open" then
		local target_dir = (#targets == 1 and file_exists(targets[1] .. "/.")) and targets[1] or cwd
		mount_vault(target_dir)
		return
	end

	-- Case 2: Target is a directory or current working directory
	local target_is_dir = false
	local vault_target_dir = cwd
	if #targets == 1 and file_exists(targets[1] .. "/.") then
		target_is_dir = true
		vault_target_dir = targets[1]
	end

	local is_dir_candidate = target_is_dir or #targets == 0
	if is_dir_candidate then
		if dir_has_vault_content(vault_target_dir) then
			mount_vault(vault_target_dir)
			return
		else
			local idx = ya.which {
				cands = {
					{ on = "a", desc = "Create Age vault (encrypted manifest)" },
					{ on = "v", desc = "Create Valv v2 vault (password)" },
					{ on = "m", desc = "Mount directory as vault" },
				},
			}
			if not idx then
				return
			end
			if idx == 1 then
				create_age_vault(vault_target_dir)
			elseif idx == 2 then
				create_valv_vault(vault_target_dir)
			elseif idx == 3 then
				mount_vault(vault_target_dir)
			end
			return
		end
	end

	-- Case 3: Target is one or more files
	local has_vault_files = false
	for _, path in ipairs(targets) do
		if is_vault_file(path) then
			has_vault_files = true
			break
		end
	end

	if has_vault_files then
		-- Decrypt vault files
		local args = { "decrypt", "-o", cwd }
		for _, path in ipairs(targets) do
			table.insert(args, path)
		end

		local output = run_valv(args, nil, true)
		if output and output.status.success then
			ya.notify {
				title = "Valv",
				content = string.format("Decrypted %d file(s)", #targets),
				timeout = 3.0,
			}
			ya.emit("escape", {})
			return
		end

		local password, event = ya.input {
			title = "Valv/Age Decrypt Password/Passphrase:",
			pos = { "top-center", y = 3, w = 40 },
			obscure = true,
		}
		if event ~= 1 or not password or #password == 0 then
			return
		end

		output = run_valv(args, password, false)
		if output and output.status.success then
			ya.notify {
				title = "Valv",
				content = string.format("Decrypted %d file(s)", #targets),
				timeout = 3.0,
			}
			ya.emit("escape", {})
		end
	else
		-- Encrypt plain files
		local idx = ya.which {
			cands = {
				{ on = "a", desc = "Encrypt with Age" },
				{ on = "v", desc = "Encrypt with Valv v2" },
			},
		}
		if not idx then
			return
		end

		local args = { "encrypt" }
		if idx == 1 then
			table.insert(args, "--age")
			for _, path in ipairs(targets) do
				table.insert(args, path)
			end

			local output = run_valv(args, nil, true)
			if output and output.status.success then
				ya.notify {
					title = "Valv",
					content = string.format("Encrypted %d file(s) with Age", #targets),
					timeout = 3.0,
				}
				ya.emit("escape", {})
				return
			end

			local password, event = ya.input {
				title = "Age Encryption Passphrase:",
				pos = { "top-center", y = 3, w = 40 },
				obscure = true,
			}
			if event ~= 1 or not password or #password == 0 then
				return
			end

			output = run_valv(args, password, false)
			if output and output.status.success then
				ya.notify {
					title = "Valv",
					content = string.format("Encrypted %d file(s) with Age", #targets),
					timeout = 3.0,
				}
				ya.emit("escape", {})
			end
		else
			for _, path in ipairs(targets) do
				table.insert(args, path)
			end
			local password, event = ya.input {
				title = "Valv Encrypt Password:",
				pos = { "top-center", y = 3, w = 40 },
				obscure = true,
			}
			if event ~= 1 or not password or #password == 0 then
				return
			end

			local output = run_valv(args, password, false)
			if output and output.status.success then
				ya.notify {
					title = "Valv",
					content = string.format("Encrypted %d file(s) with Valv", #targets),
					timeout = 3.0,
				}
				ya.emit("escape", {})
			end
		end
	end
end

return M

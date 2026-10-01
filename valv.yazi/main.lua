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

local function is_vault_path(path)
	local filename = (path:match("[^/\\]+$") or path):lower()
	return filename:sub(-5) == ".valv"
		or filename:sub(-4) == ".age"
		or filename:find("^%.?age_vault%.toml") ~= nil
end

local function dir_has_vault_manifest(dir)
	local manifest_names = {
		".age_vault.toml.age",
		"age_vault.toml.age",
		".age_vault.toml.valv",
		"age_vault.toml.valv",
		".age_vault.toml",
		"age_vault.toml",
	}
	for _, name in ipairs(manifest_names) do
		if file_exists(dir .. "/" .. name) then
			return true
		end
	end
	return false
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
	-- 1. Try automatic mount with identities first (SOPS/config age identities)
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

	-- 2. Identity not configured or password/passphrase required
	local password, event = ya.input {
		pos = { "top-center", y = 3, w = 40 },
		title = "Open Vault Password/Passphrase:",
		obscure = true,
	}

	if event ~= 1 or not password or #password == 0 then
		return false
	end

	output = run_valv({ "mount", vault_dir }, password, false)
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

local function create_vault(vault_dir)
	local cand = ya.which {
		cands = {
			{ on = "a", desc = "Create Age vault (encrypted manifest)" },
			{ on = "v", desc = "Create Valv v2 vault (password)" },
		},
	}
	if not cand then
		return false
	end

	if cand == 1 then
		-- Age vault
		local recip, event = ya.input {
			pos = { "top-center", y = 3, w = 50 },
			title = "Age recipient(s) (leave blank for SOPS/config identity):",
		}
		if event ~= 1 then
			return false
		end

		local init_args = { "init", vault_dir }
		if recip and #recip:gsub("%s+", "") > 0 then
			for r in recip:gmatch("%S+") do
				table.insert(init_args, "-r")
				table.insert(init_args, r)
			end
			local output = run_valv(init_args, nil, false)
			if output and output.status.success then
				ya.notify {
					title = "Valv",
					content = "Created Age vault. Mounting...",
					timeout = 3.0,
				}
				return mount_vault(vault_dir)
			end
		else
			-- Try init using auto-detected identity
			local output = run_valv(init_args, nil, true)
			if output and output.status.success then
				ya.notify {
					title = "Valv",
					content = "Created Age vault with local identity. Mounting...",
					timeout = 3.0,
				}
				return mount_vault(vault_dir)
			else
				-- Needs passphrase
				local pwd, p_ev = ya.input {
					pos = { "top-center", y = 3, w = 40 },
					title = "Set Age Vault Passphrase:",
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
	elseif cand == 2 then
		-- Valv v2 vault
		local pwd, p_ev = ya.input {
			pos = { "top-center", y = 3, w = 40 },
			title = "Set Valv Vault Password:",
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

	-- Explicit subcommand passed in job args
	local subcmd = job and job.args and job.args[1]
	if subcmd == "init" or subcmd == "create" then
		local target_dir = (#targets == 1 and file_exists(targets[1] .. "/.")) and targets[1] or cwd
		create_vault(target_dir)
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
	if #targets == 1 then
		if file_exists(targets[1] .. "/.") then
			target_is_dir = true
			vault_target_dir = targets[1]
		end
	end

	local is_dir_candidate = target_is_dir or #targets == 0
	if is_dir_candidate then
		if dir_has_vault_manifest(vault_target_dir) then
			-- Recognized vault -> mount automatically
			mount_vault(vault_target_dir)
			return
		else
			-- Not an obvious vault -> offer choice: mount as existing, or initialize new Age/Valv vault
			local cand = ya.which {
				cands = {
					{ on = "m", desc = "Open / Mount as vault" },
					{ on = "a", desc = "Create Age vault (encrypted manifest)" },
					{ on = "v", desc = "Create Valv v2 vault (password)" },
				},
			}
			if not cand then
				return
			end
			if cand == 1 then
				mount_vault(vault_target_dir)
			elseif cand == 2 then
				-- Create Age vault
				local recip, event = ya.input {
					pos = { "top-center", y = 3, w = 50 },
					title = "Age recipient(s) (leave blank for SOPS/config identity):",
				}
				if event == 1 then
					local init_args = { "init", vault_target_dir }
					if recip and #recip:gsub("%s+", "") > 0 then
						for r in recip:gmatch("%S+") do
							table.insert(init_args, "-r")
							table.insert(init_args, r)
						end
						local output = run_valv(init_args, nil, false)
						if output and output.status.success then
							mount_vault(vault_target_dir)
						end
					else
						local output = run_valv(init_args, nil, true)
						if output and output.status.success then
							mount_vault(vault_target_dir)
						else
							local pwd, p_ev = ya.input {
								pos = { "top-center", y = 3, w = 40 },
								title = "Set Age Vault Passphrase:",
								obscure = true,
							}
							if p_ev == 1 and pwd and #pwd > 0 then
								local out = run_valv({ "init", vault_target_dir, "--age" }, pwd, false)
								if out and out.status.success then
									mount_vault(vault_target_dir)
								end
							end
						end
					end
				end
			elseif cand == 3 then
				-- Create Valv vault
				local pwd, p_ev = ya.input {
					pos = { "top-center", y = 3, w = 40 },
					title = "Set Valv Vault Password:",
					obscure = true,
				}
				if p_ev == 1 and pwd and #pwd > 0 then
					local out = run_valv({ "init", vault_target_dir, "--valv" }, pwd, false)
					if out and out.status.success then
						mount_vault(vault_target_dir)
					end
				end
			end
			return
		end
	end

	-- Case 3: Encrypt or decrypt specific file(s)
	local vault_file_count = 0
	for _, path in ipairs(targets) do
		if is_vault_path(path) then
			vault_file_count = vault_file_count + 1
		end
	end

	if vault_file_count > 0 then
		-- Decrypt files
		local args = { "decrypt", "-o", cwd }
		for _, path in ipairs(targets) do
			table.insert(args, path)
		end

		-- Try with configured identities first
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

		-- Prompt password if identity decryption was insufficient
		local password, event = ya.input {
			pos = { "top-center", y = 3, w = 40 },
			title = "Valv/Age Decrypt Password/Passphrase:",
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
		local cand = ya.which {
			cands = {
				{ on = "a", desc = "Encrypt with Age" },
				{ on = "v", desc = "Encrypt with Valv v2" },
			},
		}
		if not cand then
			return
		end

		local args = { "encrypt" }
		if cand == 1 then
			table.insert(args, "--age")
			for _, path in ipairs(targets) do
				table.insert(args, path)
			end

			-- Try with configured recipients first
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

			-- Prompt passphrase if no recipient configured
			local password, event = ya.input {
				pos = { "top-center", y = 3, w = 40 },
				title = "Age Encryption Passphrase:",
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
				pos = { "top-center", y = 3, w = 40 },
				title = "Valv Encrypt Password:",
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

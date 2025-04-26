disable_lua = false

-- Change dji_script_path to point to the directory where you have copied
-- the Lua scripts. Do not place them in the Wireshark Lua directory.
-- Please see the README file for more information.
-- This path should be an absolute path and end with a "/"
--
-- Linux/MacOS example:
--   local dji_script_path = "/path/to/scripts/"
-- Windows example:
--   local dji_script_path = "C:\\path\\to\\scripts\\"

local dji_script_path = ""

-- If you have not changed the line above, Lua will look for the scripts
-- in the current working directory and probably not find them.

dofile(dji_script_path .. 'dji-dumlv1-proto.lua')

dofile(dji_script_path .. 'dji-p3-flyrec-proto.lua')
dofile(dji_script_path .. 'dji-p3-batt-proto.lua')
dofile(dji_script_path .. 'dji-p3.lua')

dofile(dji_script_path .. 'dji-mavic-flyrec-proto.lua')
dofile(dji_script_path .. 'dji-mavic.lua')

dofile(dji_script_path .. 'dji-spark-flyrec-proto.lua')
dofile(dji_script_path .. 'dji-spark.lua')

dofile(dji_script_path .. 'dji-write-kml.lua')

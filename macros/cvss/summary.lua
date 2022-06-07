summary = {}
summary.tmpfilename = status.log_name:sub(1, status.log_name:len() - 4) .. ".bugidx"


function summary.clean()
    io.open(summary.tmpfilename, "w"):close()
end

function summary.add(name)
    local file = io.open(summary.tmpfilename, "a")
    local badge = dofile("macros/cvss/drawbadge.lua")

    if not description then
        tex.print([[\unexpanded{\PackageWarningNoLine{cvss}{Description for summary not set}}]]);
        description = ""
    end

    if not vector_string then
        vector_string = ""
    end

    if score == nil then
        score = "N/A"
    end

    local box = "\\begin{tcolorbox}[fontupper=\\sffamily\\bfseries,beforeafter skip=.15cm]" .. badge .. " \\hyperref[sec:" .. name .. "]{" .. name .."}" 
                .. "\\hfill \\tcbox[on line,boxsep=0pt,left=3pt,right=3pt,top=3pt,bottom=3pt,colback=darkgray]{\\textcolor{white}{" .. score .. "}}"
                .. "\\tcblower"
                .. "\\href{" .. cvss31.get_vector_string_url(vector_string) .. "}{\\texttt{" .. vector_string .. "}} \\\\" .. description .. "\\end{tcolorbox}\n"
    file:write(box)
    file:flush()
end

function summary.print()
    local file = io.open(summary.tmpfilename, "r")
    if not file then
        tex.print([[\unexpanded{\PackageWarningNoLine{cvss}{Vulnerability index not generated yet, please run TeX again}}]]);
        tex.print("\\textbf{\\\\Vulnerability index not generated yet, please run TeX again!\\\\}")
        return
    end

    local contents = file:read("*a")
    file:close()
    tex.print(contents)
end

return summary

if score == nil or score == "N/A" then
    return "\\textbf{N/A}"
elseif score == 0.0 then
    level = "info"
elseif score >= 0.1 and score <= 3.9 then
    level = "low"
elseif score >= 4.0 and score <= 6.9 then
    level = "medium"
elseif score >= 7.0 and score <= 8.9 then
    level = "high"
elseif score >= 9.0 and score <= 10.0 then
    level = "critical"
end

-- decide whether to use the smaller version of badge for toc, or bigger one for titles
dvi_fontsize = font.getfont(font.current()).size
if dvi_fontsize > 800000 then
    size = "big"
else
    size = "small"
end

return "\\cvss" .. level .. "{" .. size .. "}"

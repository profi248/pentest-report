boxes = {
    {
        title = "Attack Vector",
        items = {
            { "globe", "Network", metrics.vector == cvss31.attack_vector.NETWORK },
            { "network-wired", "Adjacent", metrics.vector == cvss31.attack_vector.ADJACENT_NETWORK },
            { "desktop", "Local", metrics.vector == cvss31.attack_vector.LOCAL },
            { "hdd", "Physical", metrics.vector == cvss31.attack_vector.PHYSICAL }
        }
    },
    {
        title = "Attack Complexity",
        items = {
            { "circle", "Low", metrics.complexity == cvss31.attack_complexity.LOW },
            { "dice-d20", "High", metrics.complexity == cvss31.attack_complexity.HIGH }
        }
    },
    {
        title = "Privileges Required",
        items = {
            { "user", "None", metrics.privileges == cvss31.privileges_required.NONE },
            { "user-lock", "Low", metrics.privileges == cvss31.privileges_required.LOW },
            { "user-shield", "High", metrics.privileges == cvss31.privileges_required.HIGH }
        }
    },
    {
        title = "User Interaction",
        items = {
            { "user-slash", "None", metrics.interaction == cvss31.user_interaction.NONE },
            { "user", "Required", metrics.interaction == cvss31.user_interaction.REQUIRED },
        }
    },
    {
        title = "Scope",
        items = {
            { "square", "Unchanged", metrics.scope == cvss31.scope.UNCHANGED },
            { "project-diagram", "Changed", metrics.scope == cvss31.scope.CHANGED },
        }
    },
    {
        title = "Confidentiality Imp.",
        items = {
            { "carrot", "None", metrics.confidentiality == cvss31.confidentiality.NONE },
            { "hammer", "Low", metrics.confidentiality == cvss31.confidentiality.LOW },
            { "bomb", "High", metrics.confidentiality == cvss31.confidentiality.HIGH },
        }
    },
    {
        title = "Integrity Impact",
        items = {
            { "carrot", "None", metrics.integrity == cvss31.integrity.NONE },
            { "hammer", "Low", metrics.integrity == cvss31.integrity.LOW },
            { "bomb", "High", metrics.integrity == cvss31.integrity.HIGH },
        }
    },
    {
        title = "Availability Impact",
        items = {
            { "carrot", "None", metrics.availability == cvss31.availability.NONE },
            { "hammer", "Low", metrics.availability == cvss31.availability.LOW },
            { "bomb", "High", metrics.availability == cvss31.availability.HIGH },
        }
    },
}


for _, box in pairs(boxes) do
    tex.print("\\tcbitem[squeezed title*={\\hfill " .. box.title .. "\\hfill}]{")
    for key, item in pairs(box.items) do
        if item[3] then
            class = "active"
        else
            class = "inactive"
        end
        
        tex.print("\\cvssboxrow[" .. class  .. "]{" .. item[1] .. "}{" .. item[2] .. "}")
        
        -- draw a line after all items except the last one
        if next(box.items, key) ~= nil then
            tex.print("\\tcbline")
        end
    end
    tex.print("}")
end

-- implements https://www.first.org/cvss/specification-document

cvss31 = {}

cvss31.attack_vector = {
    NETWORK = 0.85,
    ADJACENT_NETWORK = 0.62,
    LOCAL = 0.55,
    PHYSICAL = 0.2
}

cvss31.attack_complexity = {
    LOW = 0.77,
    HIGH = 0.44
}

cvss31.privileges_required = {
    NONE = 0.85,
    LOW = 0.62,
    HIGH = 0.27
}

cvss31.user_interaction = {
    NONE = 0.85,
    REQUIRED = 0.62
}

cvss31.scope = {
    CHANGED = 1,
    UNCHANGED = 0
}

cvss31.confidentiality = {
    HIGH = 0.56,
    LOW  = 0.22,
    NONE = 0
}

cvss31.integrity = {
    HIGH = 0.56,
    LOW  = 0.22,
    NONE = 0
}

cvss31.availability = {
    HIGH = 0.56,
    LOW  = 0.22,
    NONE = 0
}

-- https://stackoverflow.com/a/58411671
local function round(num)
    return num + (2^52 + 2^51) - (2^52 + 2^51)
end

local function roundup(num)
    int_num = round(num * 100000)
    if (int_num % 10000) == 0 then
        return int_num / 100000
    else
        return (math.floor(int_num / 10000) + 1) / 10
    end
end

function cvss31.calculate(vector, complexity, privileges, interaction, scope, confidentiality, integrity, availability)
    if not (vector and complexity and privileges and interaction
            and scope and confidentiality and integrity and availability) then
        return nil
    end

    local iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))

    local impact
    if scope == 1 then
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)^15
    else 
        impact = 6.42 * iss
    end

    -- adjust privilege constants for changed scope according to the spec
    if scope == 1 then
        if privileges == 0.62 then privileges = 0.68 end
        if privileges == 0.27 then privileges = 0.5 end
    end

    local exploitability = 8.22 * vector * complexity * privileges * interaction

    local score
    if impact <= 0 then
        score = 0
    elseif scope == 0 then
        score = roundup(math.min((impact + exploitability), 10))
    elseif scope == 1 then
        score = roundup(math.min(1.08 * (impact + exploitability), 10))
    end

    return score
end

function cvss31.vector_string(vector, complexity, privileges, interaction, scope, confidentiality, integrity, availability)
    if not (vector and complexity and privileges and interaction
        and scope and confidentiality and integrity and availability) then
        return nil
    end
    
    local prefix = "CVSS:3.1/"
    
    local parts = { }
    
    if vector == cvss31.attack_vector.NETWORK then
        table.insert(parts, "AV:N")
    elseif vector == cvss31.attack_vector.ADJACENT_NETWORK then
        table.insert(parts, "AV:A")
    elseif vector == cvss31.attack_vector.LOCAL then
        table.insert(parts, "AV:L")
    elseif vector == cvss31.attack_vector.PHYSICAL then
        table.insert(parts, "AV:P")
    end
    
    if complexity == cvss31.attack_complexity.HIGH then
        table.insert(parts, "AC:H")
    elseif complexity == cvss31.attack_complexity.LOW then
        table.insert(parts, "AC:L")
    end
    
    if privileges == cvss31.privileges_required.HIGH then
        table.insert(parts, "PR:H")
    elseif privileges == cvss31.privileges_required.LOW then
        table.insert(parts, "PR:L")
    elseif privileges == cvss31.privileges_required.NONE then
        table.insert(parts, "PR:N")
    end
    
    if interaction == cvss31.user_interaction.NONE then
        table.insert(parts, "UI:N")
    elseif interaction == cvss31.user_interaction.REQUIRED then
        table.insert(parts, "UI:R")
    end
    
    if scope == cvss31.scope.CHANGED then
        table.insert(parts, "S:C")
    elseif scope == cvss31.scope.UNCHANGED then
        table.insert(parts, "S:U")
    end
    
    if confidentiality == cvss31.confidentiality.HIGH then
        table.insert(parts, "C:H")
    elseif confidentiality == cvss31.confidentiality.LOW then
        table.insert(parts, "C:L")
    elseif confidentiality == cvss31.confidentiality.NONE then
        table.insert(parts, "C:N")
    end
    
    if integrity == cvss31.integrity.HIGH then
        table.insert(parts, "I:H")
    elseif integrity == cvss31.integrity.LOW then
        table.insert(parts, "I:L")
    elseif integrity == cvss31.integrity.NONE then
        table.insert(parts, "I:N")
    end
    
    if availability == cvss31.availability.HIGH then
        table.insert(parts, "A:H")
    elseif availability == cvss31.availability.LOW then
        table.insert(parts, "A:L")
    elseif availability == cvss31.availability.NONE then
        table.insert(parts, "A:N")
    end

    return prefix .. table.concat(parts, "/")
    
end

function cvss31.get_vector_string_url(vector_string)
    url_compatible_vector = string.gsub(vector_string, "CVSS:3.1/", "")
    return "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?version=3.1&vector=" .. url_compatible_vector
end

return cvss31

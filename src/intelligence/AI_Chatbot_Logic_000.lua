local responses = {
    greetings = {"Hello!", "Hi there!", "Greetings!", "Nice to see you!", "Welcome back!"},
    farewells = {"Goodbye!", "See you later!", "Farewell!", "Catch you later!", "Have a great day!"},
    thanks = {"You're welcome!", "No problem!", "Happy to help!", "Anytime!", "Glad I could assist!"},
    default = {"I'm not sure I understand.", "Could you rephrase that?", "Interesting, tell me more.", "I see.", "Could you elaborate on that?"},
    maintenance = {"Performing maintenance tasks...", "Cleaning up old logs...", "Optimizing performance...", "Maintenance in progress..."}
}
local function generateResponse(input)
    input = string.lower(input)
    if string.match(input, "hello") or string.match(input, "hi") then
        return responses.greetings[math.random(#responses.greetings)]
    elseif string.match(input, "bye") or string.match(input, "goodbye") then
        return responses.farewells[math.random(#responses.farewells)]
    elseif string.match(input, "thank") then
        return responses.thanks[math.random(#responses.thanks)]
    elseif string.match(input, "maintenance") then
        return responses.maintenance[math.random(#responses.maintenance)]
    else
        return responses.default[math.random(#responses.default)]
    end
end
local function logInteraction(userInput, botResponse)
    local logEntry = os.date("%Y-%m-%d %H:%M:%S") .. " - User: " .. userInput .. " | Bot: " .. botResponse .. "\n"
    local logFile = io.open("chat_log.txt", "a")
    if logFile then
        logFile:write(logEntry)
        logFile:close()
    else
        print("Failed to open log file.")
    end
end
local function performMaintenance()
    print(responses.maintenance[math.random(#responses.maintenance)])
    os.execute("rm -f chat_log_*.txt") -- Unix-like command; adjust for your OS
    os.execute("mv chat_log.txt chat_log_" .. os.date("%Y%m%d%H%M%S") .. ".txt")
    print("Maintenance tasks completed.")
end
local function loadAdditionalResponses(filePath)
    local file = io.open(filePath, "r")
    if not file then
        print("Failed to open responses file.")
        return
    end
    local additionalResponses = file:read("*a")
    file:close()
    local loadedResponses = cjson.decode(additionalResponses)
    for category, messages in pairs(loadedResponses) do
        if responses[category] then
            for _, message in ipairs(messages) do
                table.insert(responses[category], message)
            end
        else
            responses[category] = messages
        end
    end
end
local function main()
    print("Welcome to the Lua Chatbot! Type 'exit' to quit or 'maintenance' to perform maintenance tasks.")
    loadAdditionalResponses("additional_responses.json")

    while true do
        io.write("You: ")
        local userInput = io.read()
        if userInput == "exit" then
            break
        elseif userInput == "maintenance" then
            performMaintenance()
        else
            local botResponse = generateResponse(userInput)
            print("Bot: " .. botResponse)
            logInteraction(userInput, botResponse)
        end
    end
    print("Goodbye! Thanks for chatting.")
end
main()

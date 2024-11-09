// Validation middleware with improved input validation
const validateInput = (req, res, next) => {
    const { text, numRows } = req.body;

    if (!text || typeof text !== 'string' || text.trim().length === 0) {
        return res.status(400).json({
            status: false,
            message: "Text is required and must be a non-empty string"
        });
    }

    // Convert numRows to number and validate
    const rows = parseInt(numRows);
    if (isNaN(rows) || rows < 2 || rows >= text.length) {
        return res.status(400).json({
            status: false,
            message: "Number of rows must be an integer between 2 and text length"
        });
    }

    // Store sanitized values
    req.body.text = text.trim();
    req.body.numRows = rows;

    next();
};

// Improved encryption function
function railFenceEncrypt(text, numRows) {
    // Create rail fence array
    const rails = Array(numRows).fill().map(() => []);
    
    // Variables to track current position
    let currentRail = 0;
    let direction = 1; // 1 for going down, -1 for going up
    
    // Distribute characters into rails
    for (let i = 0; i < text.length; i++) {
        rails[currentRail].push(text[i]);
        
        // Change direction if we hit the top or bottom rail
        if (currentRail === 0) {
            direction = 1;
        } else if (currentRail === numRows - 1) {
            direction = -1;
        }
        
        currentRail += direction;
    }
    
    // Join all rails to get encrypted text
    return rails.reduce((result, rail) => result + rail.join(''), '');
}

// Improved decryption function
function railFenceDecrypt(text, numRows) {
    if (numRows < 2 || numRows >= text.length) return text;
    
    // Create the rail fence pattern with markers
    const pattern = Array(numRows).fill().map(() => Array(text.length).fill(null));
    
    // Mark positions where characters should go
    let currentRail = 0;
    let direction = 1;
    
    for (let i = 0; i < text.length; i++) {
        pattern[currentRail][i] = true;
        
        if (currentRail === 0) {
            direction = 1;
        } else if (currentRail === numRows - 1) {
            direction = -1;
        }
        
        currentRail += direction;
    }
    
    // Fill the pattern with characters from encrypted text
    let textIndex = 0;
    for (let i = 0; i < numRows; i++) {
        for (let j = 0; j < text.length; j++) {
            if (pattern[i][j] === true) {
                pattern[i][j] = text[textIndex++];
            }
        }
    }
    
    // Read off the decrypted text
    let result = '';
    currentRail = 0;
    direction = 1;
    
    for (let i = 0; i < text.length; i++) {
        result += pattern[currentRail][i];
        
        if (currentRail === 0) {
            direction = 1;
        } else if (currentRail === numRows - 1) {
            direction = -1;
        }
        
        currentRail += direction;
    }
    
    return result;
}

// Controller to handle encryption
export const encryptRailFence = async (req, res) => {
    try {
        const { text, numRows } = req.body;
        
        // Ensure numRows is valid for the given text
        if (numRows >= text.length) {
            return res.status(400).json({
                status: false,
                message: "Number of rows must be less than text length"
            });
        }
        
        const encryptedText = railFenceEncrypt(text, numRows);
        
        // Verify that encryption actually changed the text
        if (encryptedText === text) {
            return res.status(400).json({
                status: false,
                message: "Encryption failed to modify the text. Please check parameters."
            });
        }
        
        res.json({
            status: true,
            data: {
                originalText: text,
                encryptedText: encryptedText,
                numRows: numRows
            }
        });
    } catch (error) {
        res.status(500).json({
            status: false,
            message: "Error during encryption",
            error: error.message
        });
    }
};

// Controller to handle decryption
export const decryptRailFence = async (req, res) => {
    try {
        const { text, numRows } = req.body;
        
        // Ensure numRows is valid for the given text
        if (numRows >= text.length) {
            return res.status(400).json({
                status: false,
                message: "Number of rows must be less than text length"
            });
        }
        
        const decryptedText = railFenceDecrypt(text, numRows);
        
        res.json({
            status: true,
            data: {
                encryptedText: text,
                decryptedText: decryptedText,
                numRows: numRows
            }
        });
    } catch (error) {
        res.status(500).json({
            status: false,
            message: "Error during decryption",
            error: error.message
        });
    }
};
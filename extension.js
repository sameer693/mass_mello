// The module 'vscode' contains the VS Code extensibility API

// Import the module and reference it with the alias vscode in your code below
require('dotenv').config()
const vscode = require('vscode');
const {exec} = require('child_process');
const {promisify} = require('util')
const execPromise = promisify(exec);
const { getTestCases,getRecommendations } = require('./chatgpt'); 
const fs = require('fs');
let sessionHistory = [];


// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed

/**
 * @param {vscode.ExtensionContext} context
 */

// Check if a command exists on the system
async function commandExists(command){
    try {
        await execPromise(`which ${command}`);
        return true;
    } catch {
        return false;
    }
}



async function analyzeCode() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showInformationMessage('No editor is active');
        return;
    }

    const selection = editor.selection;
    const code = editor.document.getText(selection);

    if (!code) {
        vscode.window.showInformationMessage('No code selected');
        return;
    }

    
    sessionHistory.push({ role: 'user', content: code });

    try {
        const prompt = `Perform a vulnerability test on this code piece and generate a basic report outlining the vulnerabilities and their solutions according to OWASP or ISI standards. The response should be a JSON object in the following format do not give any statement just the JSON response in answer:

{
  "report": {
    "vulnerabilities": [
      {
        "id": 1,
        "description": "Hardcoded API Key (Sensitive Data Exposure)",
        "severity": "High",
        "details": "The OpenAI API key is hardcoded in the code. If this code is exposed, the API key could be leaked, leading to unauthorized access to your OpenAI account.",
        "recommendation": "Store the API key in environment variables and retrieve it using process.env.OPENAI_API_KEY. This ensures sensitive data is not exposed in the codebase.",
        "owasp_reference": "A3:2017 - Sensitive Data Exposure"
      },
      {
        "id": 2,
        "description": "Template Literal Misuse (Injection Risk)",
        "severity": "High",
        "details": "Using template literals in headers for the Authorization field without proper validation or escaping may allow an injection attack, especially if this value is manipulated.",
        "recommendation": "Ensure that template literals are used carefully and validate inputs, or switch to concatenation if dynamic inputs are required.",
        "owasp_reference": "A1:2017 - Injection"
      },
      {
        "id": 3,
        "description": "Lack of Input Validation for 'prompt' (Potential for Injection Attacks)",
        "severity": "Medium",
        "details": "The prompt variable is passed directly into the OpenAI API without validation or sanitization. Malicious inputs could potentially exploit this to inject harmful content.",
        "recommendation": "Sanitize and validate the prompt input to ensure it doesn't contain any harmful or unexpected characters.",
        "owasp_reference": "A1:2017 - Injection"
      },
      {
        "id": 4,
        "description": "Improper Error Handling (Information Exposure)",
        "severity": "Medium",
        "details": "The error handling section logs the error details to the console. This may expose sensitive information if run in production environments.",
        "recommendation": "Mask sensitive information in error messages and log more detailed information only in secure environments (e.g., development).",
        "owasp_reference": "A9:2017 - Improper Error Handling"
      }
    ],
    "summary": {
      "total_vulnerabilities": 4,
      "severity_high": 2,
      "severity_medium": 2,
      "recommendations": [
        "Store sensitive data like API keys in environment variables.",
        "Avoid misuse of template literals and sanitize dynamic inputs.",
        "Implement proper input validation for user inputs, such as the 'prompt' parameter.",
        "Improve error handling by logging minimal information in production."
      ]
    }
  },
  "correctedCode": {
    "code": "async function getRecommendations(prompt) {\n    try {\n        const sanitizedPrompt = sanitizeInput(prompt); // Add input validation\n        const response = await axios.post(\n            'https://api.openai.com/v1/chat/completions',\n            {\n                model: 'gpt-4',\n                messages: [{ role: 'system', content: 'You are a security expert.' }, { role: 'user', content: sanitizedPrompt }],\n                max_tokens: 1500,\n            },\n            {\n                headers: {\n                    'Content-Type': 'application/json',\n                    'Authorization': Bearer ${process.env.OPENAI_API_KEY} // Use environment variable for API key\n                }\n            }\n        );\n        console.log(response);\n        return response.data.choices[0].message.content;\n    } catch (error) {\n        console.error('Error communicating with ChatGPT:');\n        console.error(maskErrorDetails(error)); // Avoid logging sensitive details in production\n        return 'Error analyzing code';\n    }\n}\n\n// Function to sanitize user inputs\nfunction sanitizeInput(input) {\n    // Basic sanitization to remove unwanted characters\n    return input.replace(/[^a-zA-Z0-9 ]/g, '');\n}\n\n// Function to mask error details in production\nfunction maskErrorDetails(error) {\n    if (process.env.NODE_ENV === 'production') {\n        return 'An error occurred. Please try again later.';\n    }\n    return error;\n}"
  },
  "complianceChecklist": [
    {
      "criterion": "Data Encryption",
      "description": "Ensure sensitive data such as API keys or personal information is encrypted both at rest and in transit.",
      "status": "Failed",
      "recommendation": "The API key is hardcoded in the source code and should be securely stored, such as in environment variables."
    },
    {
      "criterion": "Authentication and Authorization",
      "description": "Ensure that secure authentication mechanisms are used, such as using an API key securely and ensuring it is not exposed.",
      "status": "Needs Improvement",
      "recommendation": "The API key should be protected from exposure. Use a secure method to pass the key (e.g., environment variables)."
    },
    {
      "criterion": "Input Validation",
      "description": "Validate user inputs to prevent security vulnerabilities like SQL injection, XSS, or injection attacks.",
      "status": "Pass",
      "recommendation": "No user inputs are being directly used in this code, but ensure future user inputs are validated."
    },
    {
      "criterion": "Error Handling",
      "description": "Handle errors securely without exposing sensitive information or stack traces to the end user.",
      "status": "Needs Improvement",
      "recommendation": "The error response should be sanitized to avoid exposing internal system details in production."
    },
    {
      "criterion": "Logging and Monitoring",
      "description": "Log significant events such as API usage or failed requests for monitoring, without logging sensitive information.",
      "status": "Not Implemented",
      "recommendation": "No logging mechanism is implemented. Add secure logging for monitoring API interactions."
    },
    {
      "criterion": "Patch and Update Management",
      "description": "Ensure that dependencies such as 'axios' are up-to-date to mitigate known vulnerabilities.",
      "status": "Needs Review",
      "recommendation": "Verify that the 'axios' library and other dependencies are up-to-date."
    }
  ]
}

`;

        vscode.window.showInformationMessage('Sending code for analysis...');

        
        const recommendations = await getRecommendations({
            model: 'gpt-4',
            messages: [...sessionHistory, { role: 'user', content: prompt }],
            max_tokens: 1500
        });

        
        sessionHistory.push({ role: 'assistant', content: recommendations });

        // Create and show the webview with recommendations
        const panel = vscode.window.createWebviewPanel(
            'aiSecurityAssistant',
            'AI Security Assistant',
            vscode.ViewColumn.One,
            {}
        );

        panel.webview.html = getWebviewContent(recommendations);
    } catch (error) {
        console.error('Error communicating with ChatGPT:', error.response ? error.response.data : error.message);
        vscode.window.showErrorMessage('Error analyzing code');
    }
}

// Function to generate test cases
async function generateTestCases() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showInformationMessage('No editor is active');
        return;
    }

    const selection = editor.selection;
    const code = editor.document.getText(selection);

    if (!code) {
        vscode.window.showInformationMessage('No code selected');
        return;
    }

    // Define the prompt for generating test cases
    const prompt = `${code} ######## Analyze the above function and generate the most relevant test cases that might lead to errors. Focus on:
- Invalid inputs: cases which don't follow constraints.
- Performance test case: cases which may lead to long execution times.
- Security Test Case: encryption and authentication.
Generate only JavaScript test cases in Jest format. Do not include any explanations, comments, or additional text. Return only the JavaScript test code.
`;

    vscode.window.showInformationMessage('Generating test cases...');

    try {
        // Send the entire session history along with the new prompt
        const testCases = await getTestCases({
            model: 'gpt-4',
            messages: [...sessionHistory, { role: 'user', content: prompt }],
            max_tokens: 1500
        });

        // Save the test cases to a new file
        /*const fileName = `test_${Date.now()}.js`;
        const filePath = vscode.Uri.file(`${vscode.Uri}/${fileName}`);
        const edit = new vscode.WorkspaceEdit();
        edit.createFile(filePath, { ignoreIfExists: true });
        edit.insert(filePath, new vscode.Position(0, 0), testCases);
        await vscode.workspace.applyEdit(edit);
        await vscode.window.showTextDocument(filePath);
        */
        //
        // Construct the file name
        const fileName = `test_${Date.now()}.js`;

        // Use workspace.fs to handle path and file creation
        const workspaceFolde = vscode.workspace.workspaceFolders;
        
        
        if (!workspaceFolde) {
            vscode.window.showErrorMessage('No workspace folder is open');
            return;
        }
        const workspaceFolder=workspaceFolde[0];


        // Ensure the file path is valid for WSL2
        const fileUri = vscode.Uri.joinPath(workspaceFolder.uri, fileName);

        
        console.log(fileUri);

        // Write the file using workspace.fs
        // Convert the test cases string to a Uint8Array (required by writeFile)
        const encoder = new TextEncoder();
        const testCasesData = encoder.encode(testCases);
        console.log(testCasesData);
        await vscode.workspace.fs.writeFile(fileUri, testCasesData);


        // Open the newly created file in the editor
        const document = await vscode.workspace.openTextDocument(fileUri);
        await vscode.window.showTextDocument(document);


    } catch (error) {
        console.error('Error generating test cases:', error.response ? error.response.data : error.message);
        vscode.window.showErrorMessage('Error generating test cases');
    }
}

// Function to generate webview content for the analysis report
function getWebviewContent(recommendations) {
    // Sanitize the input JSON string to remove invalid control characters
    console.log(recommendations);
    const sanitizedRecommendations = sanitizeJSONString(recommendations);

    let parsedRecommendations;

    try {
        parsedRecommendations = JSON.parse(sanitizedRecommendations); // Parse sanitized JSON
    } catch (error) {
        console.error("Invalid JSON", error);
        return `
            <p>There was an error parsing the recommendations.</p>
        `;
    }

    // Access the nested vulnerabilities, summary, corrected code, and compliance checklist within 'report'
    const vulnerabilities = parsedRecommendations.report?.vulnerabilities || [];
    const summary = parsedRecommendations.report?.summary || {};
    const correctedCode = parsedRecommendations.correctedCode?.code || '';
    const complianceChecklist = parsedRecommendations.complianceChecklist || [];

    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Security Assistant</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    padding: 20px;
                    background-color: #f0f4f8;
                }
                h1 {
                    color: #333;
                    text-align: center;
                }
                h2 {
                    color: #555;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                }
                .section {
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    padding: 20px;
                    margin-bottom: 20px;
                }
                .section h3 {
                    margin-top: 0;
                }
                .list-item {
                    margin-bottom: 10px;
                }
                .solutions {
                    background-color: #e8f5e9;
                    border: 1px solid #c8e6c9;
                }
                .checklist {
                    background-color: #fff3e0;
                    border: 1px solid #ffcc80;
                }
                pre {
                    background-color: #f5f5f5;
                    padding: 15px;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>AI Security Assistant - Analysis Report</h1>

                <!-- Vulnerabilities Section -->
                <div class="section">
                    <h2>Vulnerabilities Detected</h2>
                    ${vulnerabilities.length > 0 ? vulnerabilities.map(vul => `
                        <div class="list-item">
                            <h3>${vul.description}</h3>
                            <p><strong>Impact:</strong> ${vul.severity}</p>
                            <p><strong>Details:</strong> ${vul.details}</p>
                            <p><strong>Recommendation:</strong> ${vul.recommendation}</p>
                            <p><strong>OWASP Reference:</strong> ${vul.owasp_reference}</p>
                        </div>
                    `).join('') : '<p>No vulnerabilities found.</p>'}
                </div>

                <!-- Summary Section -->
                <div class="section">
                    <h2>Summary</h2>
                    <p><strong>Total Vulnerabilities:</strong> ${summary.total_vulnerabilities || 0}</p>
                    <p><strong>High Severity:</strong> ${summary.severity_high || 0}</p>
                    <p><strong>Medium Severity:</strong> ${summary.severity_medium || 0}</p>
                    <p><strong>Recommendations:</strong></p>
                    <ul>
                        ${summary.recommendations ? summary.recommendations.map(rec => `<li>${rec}</li>`).join('') : '<li>No recommendations available</li>'}
                    </ul>
                </div>

                <!-- Corrected Code Section -->
                <div class="section">
                    <h2>Corrected Code</h2>
                    <pre>${correctedCode}</pre>
                </div>

                <!-- Compliance Checklist Section -->
                <div class="section checklist">
                    <h2>Compliance Checklist</h2>
                    ${complianceChecklist.length > 0 ? complianceChecklist.map(item => `
                        <div class="list-item">
                            <h3>${item.criterion}</h3>
                            <p><strong>Description:</strong> ${item.description}</p>
                            <p><strong>Status:</strong> ${item.status}</p>
                            <p><strong>Recommendation:</strong> ${item.recommendation}</p>
                        </div>
                    `).join('') : '<p>No compliance issues found.</p>'}
                </div>
            </div>
        </body>
        </html>
    `;
}


// Function to sanitize JSON string
function sanitizeJSONString(jsonString) {
    // Replace invalid control characters with safe spaces
    return jsonString.replace(/[\u0000-\u001F\u007F]/g, ''); 
}






function activate(context) {

	console.log('Congratulations, your extension "hackasol" is now active!');


    // Command to analyze selected code
    const analyzeCodeDisposable = vscode.commands.registerCommand('hackasol.analyzeCode', analyzeCode);
    context.subscriptions.push(analyzeCodeDisposable);

    // Command to generate test cases
    const generateTestCasesDisposable = vscode.commands.registerCommand('hackasol.generateTestCases', generateTestCases);
    context.subscriptions.push(generateTestCasesDisposable);

	const disposable = vscode.commands.registerCommand('hackasol.helloWorld', function () {
		// The code you place here will be executed every time your command is executed

		// Display a message box to the user
		vscode.window.showInformationMessage('Hello World from hackasol!');
	});
    

	const disposable2 = vscode.commands.registerCommand('hackasol.testrun', async () => {
        // Prompt for URL input
		console.log('ran');
        const targetUrl = await vscode.window.showInputBox({ 
            prompt: 'Enter the target URL for security testing', 
            placeHolder: 'http://example.com'
        });
        
        if (targetUrl) {
            const requiredTools = ['ffuf','nikto'];
            const missingTools = [];

            // Check for required tools
            for (const tool of requiredTools) {
                if (!(await commandExists(tool))) {
                    missingTools.push(tool);
                }
            }

            if (missingTools.length > 0) {
                vscode.window.showErrorMessage(`Missing tools: ${missingTools.join(', ')}. Please install them.`);
                return;
            }

            // Run security tests
            const tests = [
                { name: 'Fuzz Testing', command: `ffuf -u ${targetUrl}/FUZZ -w /usr/share/wordlists/small.txt` },
                //{ name: 'Web Vulnerability Scan (OWASP ZAP)', command: `zap-cli quick-scan --self-contained --spider ${targetUrl}` },
                {name:'YOYO',command:"\n echo helloo \n"},
                { name: 'Web Technology Fingerprinting', command: `whatweb -v -a 3 ${targetUrl}` },
                {name:'YOYO',command:"\n echo helloo \n"},
                {
                    name: 'Directory Enumeration (DNS) gobuster',
                    command: `gobuster dns -d google.com -w /usr/share/wordlists/small.txt`
                },
                //{ name: 'SQL Injection Testing', command: `sqlmap -u ${targetUrl} --batch` },
                {name:'YOYO',command:"\n echo helloo \n"},
                //{ name: 'Web Server Vulnerability Scan', command: `curl ${targetUrl} ` },
                { name: 'Port and Service Enumeration', command: `nmap -sV -T4 -O ${targetUrl}` }
                
            ];

            // Show results in the VSCode terminal
            const terminal = vscode.window.createTerminal('Security Tests');
            terminal.show();

            for (const test of tests) {
                //terminal.sendText(`Running ${test.name}...`);
                try {
                    console.log(test.name);
                    const { stdout, stderr } = await execPromise(test.command);
                    if (stdout) terminal.sendText(stdout);
                    if (stderr) terminal.sendText(stderr);
                    console.log('next');
                } catch (error) {
                    terminal.sendText(`Error running ${test.name}: ${error.message}`);
                }
            }

            vscode.window.showInformationMessage('Security tests completed. Check the terminal for results.');
        } else {
            vscode.window.showWarningMessage('No URL provided. Aborting security tests.');
        }
    });

	context.subscriptions.push(disposable);
	context.subscriptions.push(disposable2);
    // New Code Audit Command (graudit on user code base)
    const disposable3 = vscode.commands.registerCommand('hackasol.codeAudit', async () => {
        console.log('Running source code audit...');

        // Prompt user to select a folder for code audit
        const folders = await vscode.window.showOpenDialog({
            canSelectFiles: false,
            canSelectFolders: true,
            canSelectMany: false,
            openLabel: 'Select Code Base Folder'
        });

        if (!folders || folders.length === 0) {
            vscode.window.showWarningMessage('No folder selected for code audit.');
            return;
        }

        const selectedFolder = folders[0].fsPath;

        // Check if graudit is installed
        if (!(await commandExists('graudit'))) {
            vscode.window.showErrorMessage('graudit is not installed. Please install it to run the code audit.');
            return;
        }

        // Run graudit on the selected folder
        const terminal = vscode.window.createTerminal('Code Audit');
        terminal.show();

        try {
            const { stdout, stderr } = await execPromise(`graudit ${selectedFolder}`,);            
            if (stdout) terminal.sendText(stdout);
            if (stderr) terminal.sendText(stderr);
        } catch (error) {
            terminal.sendText(`Error running graudit: ${error.message}`);
        }

        vscode.window.showInformationMessage('Code audit completed. Check the terminal for results.');
    });
    context
}

// This method is called when your extension is deactivated
function deactivate() {}

module.exports = {
	activate,
	deactivate
}

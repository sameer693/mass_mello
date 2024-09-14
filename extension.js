// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
const vscode = require('vscode');
const {exec} = require('child_process');
const {promisify} = require('util')
const execPromise = promisify(exec);
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


function activate(context) {

	console.log('Congratulations, your extension "hackasol" is now active!');

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
                //{ name: 'SQL Injection Testing', command: `sqlmap -u ${targetUrl} --batch` },
                //{name:'YOYO',command:"\n echo helloo \n"},
                //{ name: 'Web Server Vulnerability Scan', command: `curl ${targetUrl} ` },
                { name: 'Port and Service Enumeration', command: `sudo nmap -sV -T4 -O ${targetUrl}` }
                
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
	context.subscriptions.push(disposable2)
}

// This method is called when your extension is deactivated
function deactivate() {}

module.exports = {
	activate,
	deactivate
}

import { execSync } from "child_process";

// Based on https://stackoverflow.com/questions/26090995/detect-if-executable-exists-on-system-path-with-node
function isForgeInPathPosix() {
	try {
		// `command -v` is more portable than `which`
		// https://stackoverflow.com/questions/592620/how-can-i-check-if-a-program-exists-from-a-bash-script
		execSync(`command -v forge`, { encoding: "utf-8" });
		return true;
	} catch {
		return false;
	}
}

function main() {
	console.log("Checking if `forge` is installed...");

	// https://nodejs.org/api/process.html#processplatform
	switch (process.platform) {
		case "linux":
		case "darwin": {
			if (isForgeInPathPosix()) {
				console.log("`forge` is installed!");
				return;
			}

			console.log("Installing `forge` with `foundryup`...");
			execSync("curl -L https://foundry.paradigm.xyz | bash", {
				// Show command output in console
				stdio: "inherit",
			});
			execSync("source /vercel/.bashrc && foundryup", {
				// Show command output in console
				stdio: "inherit",
			});
			break;
		}
		default: {
			console.error(
				"This script only supports Linux and macOS. Please install `forge` manually for your platform: https://book.getfoundry.sh/getting-started/installation",
			);
			break;
		}
	}
}

main();

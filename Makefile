build:
	mkdir -p ./dist
	swiftc -O -o ./dist/VGuard main.swift -framework Cocoa -framework SystemConfiguration

bundle: build
	rm -rf ./dist/VGuard.app
	mkdir -p ./dist/VGuard.app/Contents/MacOS ./dist/VGuard.app/Contents/Resources
	cp ./dist/VGuard ./dist/VGuard.app/Contents/MacOS/VGuard
	cp Info.plist ./dist/VGuard.app/Contents/Info.plist
	cp media/AppIcon.icns ./dist/VGuard.app/Contents/Resources/AppIcon.icns
	cp com.vguard.daemon.plist ./dist/VGuard.app/Contents/Resources/com.vguard.daemon.plist
	codesign --force --deep -s - ./dist/VGuard.app

install: bundle
	rm -rf /Applications/VGuard.app
	cp -R ./dist/VGuard.app /Applications/VGuard.app

# Root firewall daemon (asks for sudo). Re-run after every rebuild so the daemon matches the app.
install-daemon: build
	sudo install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools "/Library/Application Support/VGuard"
	sudo install -o root -g wheel -m 755 ./dist/VGuard /Library/PrivilegedHelperTools/com.vguard.daemon
	sudo install -o root -g wheel -m 644 com.vguard.daemon.plist /Library/LaunchDaemons/com.vguard.daemon.plist
	-sudo launchctl bootout system/com.vguard.daemon 2>/dev/null; sleep 1
	sudo launchctl bootstrap system /Library/LaunchDaemons/com.vguard.daemon.plist

# Stops the daemon (it removes its pf rules on exit) and deletes it.
uninstall-daemon:
	-sudo launchctl bootout system/com.vguard.daemon
	sudo rm -f /Library/PrivilegedHelperTools/com.vguard.daemon /Library/LaunchDaemons/com.vguard.daemon.plist
	-sudo /sbin/pfctl -a com.apple/vguard -F all

check: build
	./dist/VGuard --check

.PHONY: build bundle install install-daemon uninstall-daemon check

package infrastructure

import "path/filepath"

// layout is where one program keeps its stores on a system: the folders that
// hold a profiles.ini (Firefox and its forks), or the one folder of a store
// that every profile of the home shares (Chromium's ~/.pki/nssdb).
type layout struct {
	browser   string
	packaging string
	profiles  []string
	shared    string
}

// layouts lists the places to look, in the order a person would use them: the
// native installs, then Snap, then Flatpak. Windows and macOS keep the
// Firefox family in their application-data folders; Chromium uses the
// system's own store there, so it is not listed.
func layouts(env Environment) []layout {
	switch env.System {
	case "windows":
		return []layout{
			{browser: "Firefox", profiles: []string{filepath.Join(env.AppData, "Mozilla", "Firefox")}},
			{browser: "LibreWolf", profiles: []string{filepath.Join(env.AppData, "librewolf")}},
			{browser: "Thunderbird", profiles: []string{filepath.Join(env.AppData, "Thunderbird")}},
		}
	case "darwin":
		support := filepath.Join(env.Home, "Library", "Application Support")
		return []layout{
			{browser: "Firefox", profiles: []string{filepath.Join(support, "Firefox")}},
			{browser: "LibreWolf", profiles: []string{filepath.Join(support, "librewolf")}},
			{browser: "Thunderbird", profiles: []string{filepath.Join(support, "Thunderbird")}},
		}
	}
	return linuxLayouts(env)
}

// linuxLayouts are the Linux packages. A Flatpak keeps its own home folder,
// ~/.var/app/<id>, which holds the app's ".mozilla", ".librewolf" and
// "config" folders as the app sees them.
func linuxLayouts(env Environment) []layout {
	home := env.Home
	sandbox := func(id string, parts ...string) string {
		return filepath.Join(append([]string{home, ".var", "app", id}, parts...)...)
	}
	return []layout{
		{browser: "Firefox", profiles: []string{
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(env.ConfigHome, "mozilla", "firefox"),
		}},
		{browser: "Firefox Nightly", profiles: []string{filepath.Join(home, ".mozilla", "firefox-trunk")}},
		{browser: "LibreWolf", profiles: []string{
			filepath.Join(home, ".librewolf"),
			filepath.Join(env.ConfigHome, "librewolf", "librewolf"),
		}},
		{browser: "Waterfox", profiles: []string{filepath.Join(home, ".waterfox")}},
		{browser: "Floorp", profiles: []string{filepath.Join(home, ".floorp")}},
		{browser: "Zen", profiles: []string{filepath.Join(home, ".zen")}},
		{browser: "Thunderbird", profiles: []string{filepath.Join(home, ".thunderbird")}},
		{browser: "Chromium", shared: filepath.Join(home, ".pki", "nssdb")},

		{browser: "Firefox", packaging: "snap", profiles: []string{
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
		}},
		{browser: "Thunderbird", packaging: "snap", profiles: []string{
			filepath.Join(home, "snap", "thunderbird", "common", ".thunderbird"),
		}},
		{browser: "Chromium", packaging: "snap", shared: filepath.Join(home, "snap", "chromium", "current", ".pki", "nssdb")},

		{browser: "Firefox", packaging: "flatpak org.mozilla.firefox", profiles: []string{
			sandbox("org.mozilla.firefox", ".mozilla", "firefox"),
			sandbox("org.mozilla.firefox", "config", "mozilla", "firefox"),
		}},
		{browser: "LibreWolf", packaging: "flatpak io.gitlab.librewolf-community", profiles: []string{
			sandbox("io.gitlab.librewolf-community", ".librewolf"),
			sandbox("io.gitlab.librewolf-community", "config", "librewolf", "librewolf"),
		}},
		{browser: "Waterfox", packaging: "flatpak net.waterfox.waterfox", profiles: []string{
			sandbox("net.waterfox.waterfox", ".waterfox"),
		}},
		{browser: "Thunderbird", packaging: "flatpak org.mozilla.Thunderbird", profiles: []string{
			sandbox("org.mozilla.Thunderbird", ".thunderbird"),
		}},
		{browser: "Chromium", packaging: "flatpak org.chromium.Chromium", shared: sandbox("org.chromium.Chromium", ".pki", "nssdb")},
		{browser: "ungoogled-chromium", packaging: "flatpak io.github.ungoogled_software.ungoogled_chromium",
			shared: sandbox("io.github.ungoogled_software.ungoogled_chromium", ".pki", "nssdb")},
		{browser: "Google Chrome", packaging: "flatpak com.google.Chrome", shared: sandbox("com.google.Chrome", ".pki", "nssdb")},
		{browser: "Brave", packaging: "flatpak com.brave.Browser", shared: sandbox("com.brave.Browser", ".pki", "nssdb")},
		{browser: "Microsoft Edge", packaging: "flatpak com.microsoft.Edge", shared: sandbox("com.microsoft.Edge", ".pki", "nssdb")},
		{browser: "Vivaldi", packaging: "flatpak com.vivaldi.Vivaldi", shared: sandbox("com.vivaldi.Vivaldi", ".pki", "nssdb")},
	}
}

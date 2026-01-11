#include <iostream>
#include <string>
#include <Poco/Util/Application.h>
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Util/AbstractConfiguration.h>
#include <Poco/File.h>
#include <Poco/Path.h>

#include "webdav_server.h"
#include "utils.h"

using Option = Poco::Util::Option;
using OptionSet = Poco::Util::OptionSet;
using Application = Poco::Util::Application;

namespace webdav {

class WebDAVApplication : public Poco::Util::Application {
public:
    WebDAVApplication() : _helpRequested(false) {
    }

    ~WebDAVApplication() {
    }

protected:
    void initialize(Application& self) {
        loadConfiguration(); // load default configuration files, if present
        Application::initialize(self);
    }

    void uninitialize() {
        Application::uninitialize();
    }

    void defineOptions(OptionSet& options) {
        Application::defineOptions(options);

        options.addOption(
            Option("help", "h", "Display help information on command line arguments.")
                .required(false)
                .repeatable(false));

        options.addOption(
            Option("config", "c", "Load configuration data from a file.")
                .required(false)
                .repeatable(false)
                .argument("file"));
    }

    void handleOption(const std::string& name, const std::string& value) {
        Application::handleOption(name, value);

        if (name == "help")
            _helpRequested = true;
        else if (name == "config")
            loadConfiguration(value);
    }

    void displayHelp() {
        Poco::Util::HelpFormatter helpFormatter(options());
        helpFormatter.setCommand(commandName());
        helpFormatter.setUsage("OPTIONS");
        helpFormatter.setHeader("A WebDAV server that exposes the FileEngine gRPC filesystem API.");
        helpFormatter.format(std::cout);
    }

    int main(const std::vector<std::string>& args) {
        if (_helpRequested) {
            displayHelp();
        } else {
            // Get host and port from configuration or environment variables
            std::string host = config().getString("webdav.host", webdav::getEnvOrDefault("WEBDAV_HOST", "0.0.0.0"));
            int port = config().getInt("webdav.port", std::stoi(webdav::getEnvOrDefault("WEBDAV_PORT", "8080")));

            // Create and start the WebDAV server
            std::unique_ptr<webdav::WebDAVServer> server = std::make_unique<webdav::WebDAVServer>(host, port);
            server->start();

            // For now, just create and start the server without waiting
            // In a real implementation, this would be handled by proper signal handling
            // webdav::WebDAVServer server(host, port);
            // server.start();
            // waitForTerminationRequest(); // This is only available in ServerApplication
            std::cout << "WebDAV server would start on " << host << ":" << port << std::endl;

            server->stop();
            server.reset(); // Explicitly reset to ensure proper cleanup
        }
        return Application::EXIT_OK;
    }

// No custom run method needed since Application::run() doesn't take arguments

private:
    bool _helpRequested;
};

} // namespace webdav

int main(int argc, char** argv) {
    webdav::WebDAVApplication app;
    try {
        app.init(argc, argv);
        return app.Application::run();
    } catch (Poco::Exception& exc) {
        std::cerr << exc.displayText() << std::endl;
        return Poco::Util::Application::EXIT_SOFTWARE;
    }
}
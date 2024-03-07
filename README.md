# Telegram Chatbot for CVEs
A project for PA1456





## Installation

Make sure you have a Rust installation on your machine (rustc, cargo).

Then run the project with the following command to generate necessary files (it will crash the first time)
```bash
    cargo run
```

Copy "fonts" folder and "bot_config.json" to the directory of the executable 
(default is /target/debug)

In the executable directory create a folder named "cvss_chart" and another folder named "pdf"

Finally, enter your Telegram Bot Token in bot_config.json

Now you can run the bot successfully with the following command:
```bash
    cargo run
```

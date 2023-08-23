# Vectra Triage Report

## Requirements

1. Python3
2. The URL of a Brain and the corresponding API Token
    1. The token can be found after logging in to the brain. On the Left, Click on
        1. My Profile > API Token
        2. Click on **Copy**
3. Access to the brain for the duration of the script

## Obtaining the source

1. Obtain the latest source code from
    [GitHub](https://github.com/vectranetworks/triage-report)

## Installation

### Mac / Linux

1. If you downloaded a zip file, extract the contents
2. Change to the directory where the source is located
3. (Optional recommended step): Setup a Virtual Environment
    1. Create the Virtual Environemnt `python3 -m venv .env`
    2. Activate the Virtual Environment (note the prompt change in the second line
    when this is done properly)

        ```bash
        user@mbp19:triage-report $ source .env/bin/activate
        (.env) user@mbp19:triage-report $
        ```

4. Install the prerequities `pip3 install -r requirements.txt`
5. If you created a Virtual Environment in Step 3, you do not need to create
    a new environment each time, though you do need to ensure it is active via
    `source .env/bin/activate`
6. Run the script as in [Usage](#Usage)

### Windows

1. Obtain Python3 from Python.org
2. Extract the contents of the zip file
3. Change to the directory where the source is located
4. (Optional recommended step): Setup a Virtual Environment
    1. Create the Virtual Environment `python3 -m venv .env`
    2. Activate the Virtual Environment (note the prompt change in the second
    line when this is done properly)
5. Install the prerequisites `pip3 install -r requirements.txt`
6. If you created a Virtual Environment in Step 3, you do not need to create a
    new environment each time, though you do need to ensure it is active via
    `/.env/Scripts/activate`
7. Run the script as in [Usage](#Usage)

## Usage

```shell
python3 triage_report.py --cognito_url https://brain.vectra.ai --cognito_token xxxxxx
```

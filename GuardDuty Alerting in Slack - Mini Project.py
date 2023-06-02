import json
import urllib3
import os

http = urllib3.PoolManager()

def lambda_handler(event, context):
    # Extract the desired information from the event
    records = event.get('Records', [])
    sns_message = records[0].get('Sns', {})
    message = sns_message.get('Message', '{}')
    parsed_message = json.loads(message)
    
    aws_account = parsed_message.get('account', '')
    region = parsed_message.get('region', '')
    title = parsed_message.get('detail', {}).get('title', '')
    severity = parsed_message.get('detail', {}).get('severity', '')
    event_type = parsed_message.get('detail', {}).get('type', '')
    
    event_first_seen = parsed_message.get('detail', {}).get('service', {}).get('eventFirstSeen', '')
    event_last_seen = parsed_message.get('detail', {}).get('service', {}).get('eventLastSeen', '')
    
    remote_ip = parsed_message.get('detail', {}).get('service', {}).get('action', {}).get('networkConnectionAction', {}).get('remoteIpDetails', {}).get('ipAddressV4', '')
    instance_id = parsed_message.get('detail', {}).get('resource', {}).get('instanceDetails', {}).get('instanceId', '')


    
    description = parsed_message.get('detail', {}).get('description', '')
    title = parsed_message.get('detail', {}).get('title', '')
    accountId = parsed_message.get('detail', {}).get('accountId', '')
    action = parsed_message.get('detail', {}).get('service', {}).get('action', {})
    
    # Extract relevant information from the event
    severity_num = int(parsed_message.get('detail', {}).get('severity', 0))
    
    # Determine severity label and color based on the severity number
    severity_label = ""
    severity_color = ""
    if severity_num >= 0 and severity_num < 5:
        severity_label = "LOW"
        severity_color = "#29C5F6"  # Blue color
    elif severity_num >= 5 and severity_num < 8:
        severity_label = "MEDIUM"
        severity_color = "#FFA500"  # Yellow color
    elif severity_num >= 8:
        severity_label = "HIGH"
        severity_color = "#FF0000"  # Red color


    # Construct the Slack message payload
    slack_message = {
        "attachments": [
            {
                "color": severity_color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*AWS GuardDuty*\n*A {severity_label} severity threat has been detected: {title}*"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*AWS Account*\n{aws_account}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Region*\n{region}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Severity*\n{severity_label} - {severity_num}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Type*\n{event_type}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*First Seen*\n{event_first_seen}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Last Seen*\n{event_last_seen}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Description*\n{description}"
                        }
                    },
                    
                    {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": ":key: Sign-in to AWS",
                                "emoji": True
                            },
                            "url": "https://signin.aws.amazon.com/signin?redirect_uri=https%3A%2F%2Faws.amazon.com%2Fmarketplace%2Fmanagement%2Fsignin%3Fstate%3DhashArgs%2523%26isauthcode%3Dtrue&client_id=arn%3Aaws%3Aiam%3A%3A015428540659%3Auser%2Faws-mp-seller-management-portal&forceMobileApp=0&code_challenge=FrHw_yv4WY73oBKfXgZmsIxQvdtZ6JVw358S6ifqTeo&code_challenge_method=SHA-256"
                        },
                        {
                            "type": "button",
                            "text": {
                            "type": "plain_text",
                            "text": ":mag: Open in GuardDuty",
                            "emoji": True
                        },
                        "url": "https://us-west-2.console.aws.amazon.com/guardduty/home?region=us-west-2#/findings?macros=current"
                        }
                      ]
                    }

                ]
            }
        ]
    }
    
    # Send the event parsed content to the Slack us-west-2 Channel
    slack_webhook_url = os.environ['SLACK_WEBHOOK_URL']
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = http.request('POST', slack_webhook_url, headers=headers, body=json.dumps(slack_message))
        print("Status code:", response.status)
    except Exception as e:
        print("Failed to send event to Slack. Error:", str(e))

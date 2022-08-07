import feedparser
import webbrowser
import requests


def news():
    """
    Gather user input to determine what website they would like to gather
    information from. User can select number of articles to view in terminal
    and open in their browser.
    """

    websites = {
        "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
        "ThreatPost": "https://threatpost.com/feed",
        "NakedSecurity": "https://nakedsecurity.sophos.com/feed",
        "PortSwigger": "https://portswigger.net/daily-swig/us",
    }

    print('-----Security News Websites-----')
    for k in websites.keys():
        print(f'- {k}')

    try:
        web_input = str(input('Enter website name to view articles: '))
        news_feed = feedparser.parse(websites[web_input])
        article_list = []
        article_link = []
        num = int(input('Please enter amount of articles to view from the selected website: '))
        for i in range(num):
            article = news_feed.entries[i]
            titles = article.title
            link = article.link
            article_link.append(link)
            article_list.append(titles)

        article_num = 1
        for article in article_list:
            print('[{}] {}'.format(str(article_num), article))
            article_num += 1

        article_link_click = False
        while not article_link_click:
            if num > 1:
                selected_links = list(map(int, input(f'What links do you want to open? ').split()))
                valid_links = 0
                try:
                    for i in selected_links:
                        if 0 <= i < len(article_link) + 1:
                            valid_links += 1
                except IndexError as i_err:
                    print(f'Err: {i_err}')
                finally:
                    if valid_links == len(article_link):
                        for i in selected_links:
                            webbrowser.open(article_link[i - 1])
            else:
                single_link = int(input(f'Enter ({num}) again to open link: '))
                webbrowser.open(article_link[single_link - 1])

            article_link_click = True

    except KeyError as k_err:
        print(f'Err: {k_err} is not a valid website')
        return
    except IndexError as i_err:
        print(f'Err: {i_err}')
        return

def cve_30(num):
    """
    Display up to the last 30 CVEs on the terminal.
    :param num: Number of CVES to display.
    """

    content = requests.get("https://cve.circl.lu/api/last")
    json_elements = content.json()
    cve_list = list(json_elements[0:num])

    for item in cve_list:
        print("{} {}".format("Vuln Num:", item['id']))
        print("{} {}\n".format("Desc:", item['summary']))


def owasp_10():
    """
    Opens link on user's browser to the selected OWASP Top 10 vulnerability.
    """

    websites = {
        "Broken Access Control": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "Cryptographic Failures": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "Injection": "https://owasp.org/Top10/A03_2021-Injection/",
        "Insecure Design": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "Security Misconfiguration": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "Vulnerable and Outdated Components": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "Identification and Authentication Failures":
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "Software and Data Integrity Failures": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "Security Logging and Monitoring Failures":
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "Server-Side Request Forgery": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    }

    print('OWASP Top 10')
    for k in websites.keys():
        print(k)

    link_click = False
    while not link_click:
        user_click = str(input("Type the security risk you would like to read more on.\n"))
        webbrowser.open(websites[user_click])
        link_click = True


if __name__ == '__main__':

    print('Hello! Here are your options to select:\n- news: See latest cybersecurity news.\n'
          '- cve30: See up to 30 of the last.'
          'CVEs\n- owasp10: Links to OWASP Top 10 risks.')

    while True:
        user_input = input('-----Please enter your command-----\n')
        if user_input == 'news':
            news()
        elif user_input == 'cve30':
            cve_num = int(input('Please enter amount of CVEs (up to 30) you want to see.\n'))
            cve_30(cve_num)
        elif user_input == 'owasp10':
            owasp_10()
        elif user_input == 'end':
            break
        else:
            print('Invalid command.')

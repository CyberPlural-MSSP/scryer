<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/mukhy/scryer">
    <img src="images/logo.png" alt="Logo" height="100">
  </a>

  <h3 align="center">Scryer IDS</h3>

  <p align="center">
    An awesome configurable IDS made by <a href="#contact">us</a>
    <br />
    <a href="https://docs.google.com/document/d/1wF2qryPLDN5uwAlxvbAIxNTm62B8KeLeW5EXssNi-fE/edit?usp=sharing"><strong>Read Documentation</strong></a>
    <br />
    <br />
    <a href="https://github.com/mukhy/scryer">View Demo</a>
    ·
    <a href="https://github.com/mukhy/scryer/issues">Report Bug</a>
    ·
    <a href="https://github.com/mukhy/scryer/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://github.com/muhky/scryer)

Scryer is a network-based intrusion detection system (IDS) designed to protect your network from external threats. Using advanced algorithms and machine learning techniques, Scryer is able to continuously monitor your network traffic and detect potential security breaches in real-time. With Scryer, you can stay one step ahead of attackers and ensure that your network remains secure and protected.

Scryer is easy to use and requires no specialized knowledge or expertise. Simply install Scryer on your network, and let it do the work for you. Scryer is continuously updated with the latest security signatures and algorithms, so you can trust that your network is always protected. Try Scryer today, and take the first step towards securing your network.

Scryer uses advanced algorithms to detect suspicious traffic on your network. By continuously monitoring network traffic and analyzing it for unusual patterns or anomalies, Scryer is able to identify potential security breaches and alert you in real-time. With Scryer, you can stay one step ahead of attackers and protect your network from potential threats.

Scryer also includes features to detect and prevent unauthorised users from accessing your network. By continuously monitoring user activity, Scryer is able to identify suspicious login attempts and block them before they can gain access to your network. In addition, Scryer can be configured to require two-factor authentication for all users, adding an extra layer of security to protect your network from unauthorised access. With Scryer, you can be confident that only authorised users have access to your network.


<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

[![Python][Python.logo]][Python.url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

To get started, you need to install python3, from [here](Python.url)

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/muhky/scryer.git
   ```
2. Prerequisites are in the _requirements.txt_ file. Install them as follows
    * pip
    ```sh
    pip install -r requirements.txt
    ```
3. Review and edit `conf.yml` to describe your instance's parameters
   ```yml
   scryer:
    interface: wlo1
    traffic:
        UDP:
            max_count: 150
            max_len: 0 # Don't check for packet lengths
            scan_interval: 1000 # scan interval in milliseconds
        TCP:
            max_count: 10000
            max_len: 0 # Don't check
            scan_interval: 1000
        ICMP:
            max_count: 100
            max_len: 0
            scan_interval: 1000
        HTTP:
            max_count: 200_000
            max_len: 0
            scan_interval: 1000
        SYN:
            max_count: 100
            max_len: 0
            scan_interval: 1000
        ACK:
            max_count: 100
            max_len: 0
            scan_interval: 1000
        FIN:
            max_count: 100

    data_transfer:
        limit: 1MB # Computers only allowed to transfer 1MB of data a second
        interval: 1000

    network_resources:
        network: 192.168.*.* # Define the bounds of your network
        internal: 192.168.3.* # Define protected resources that even internal computers can't access
        external: !192.168.4.2 # Define protected resources that external computers can't access
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

To use this program, change directory to the root of this project and run

```sh
sudo python3 index.py
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [x] Detect unusual data transfer
- [x] Detect suspicious packets
- [x] Detect access to restricted resources
- [X] Detect spike in network traffic
- [X] Basic example config file
- [ ] Isolation of suspicious IP addresses from the network 
- [ ] Booting out suspicious ip out of the network.
- [ ] Implementation of the IDS on the event manager making it easy for admins to carryout possible investigation


See the [open issues](https://github.com/othneildrew/Best-README-Template/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact Us

- Muktar Suleiman - [@Abtwithmoha](https://twitter.com/Abtwithmoha) - muktarsuleiman62@gmail.com 
- Mainasara Tsowa - [@neutrino2211](https://twitter.com/neutrino221) - tsowamainasara@gmail.com - neutrino221.github.io
- Birma Markus Yakubu - [@ThaBlackBoy__](https://twitter.com/ThaBlackBoy__) - birma4markus@gmail.com
- Sylvester Ushie - [@]() - 
- Rufai Ahmed Salihu - [@]() - 
- Abdulhafeez Abdulfatai Olaitan - [@]() - 


Project Link: [https://github.com/mukhy/scryer](https://github.com/mukhy/scryer)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [Choose an Open Source License](https://choosealicense.com)
* [Best Readme Template](https://github.com/othneildrew/Best-README-Template)
* [IPsum](https://github.com/stamparm/ipsum)
* [Scapy](https://github.com/secdev/scapy)
* [Pyyaml](https://github.com/yaml/pyyaml)
* [Yaspin](https://github.com/pavdmyt/yaspin)
* [Img Shields](https://shields.io)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/muhky/scryer?style=for-the-badge
[contributors-url]: https://github.com/muhky/scryer/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/muhky/scryer?style=for-the-badge
[forks-url]: https://github.com/muhky/scryer/network/members
[stars-shield]: https://img.shields.io/github/stars/muhky/scryer?style=for-the-badge
[stars-url]: https://github.com/muhky/scryer/stargazers
[issues-shield]: https://img.shields.io/github/issues/muhky/scryer?style=for-the-badge
[issues-url]: https://github.com/muhky/scryer/issues
[license-shield]: https://img.shields.io/github/license/muhky/scryer?style=for-the-badge
[license-url]: https://github.com/muhky/scryer/blob/master/LICENSE.txt
[product-screenshot]: images/app.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com 
[Python.logo]: https://www.python.org/static/community_logos/python-logo-generic.svg
[Python.url]: https://www.python.org/
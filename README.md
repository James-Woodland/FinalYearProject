<div id="top"></div>
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
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/James-Woodland/FinalYearProject">
    <img src="Images/Logo.png" alt="Logo" width="500" height="200">
  </a>

  <p align="center">
    A Novel Machine Learning based IDS for IoT enabled homes
  </p>
</div>



<!-- ABOUT THE PROJECT -->
## About The Project

![Product Name Screen Shot][product-screenshot1]
![Product Name Screen Shot][product-screenshot2]

<p align="right">(<a href="#top">back to top</a>)</p>
The IoT, internet of things, market is growing and currently thoughts of security and secure implementation are being left behind, causing some unwillingness in consumers to bring these devices into their homes. Whilst no one likely needs an IoT toaster there are much more helpful devices out there, from smart smoke alarms notifying you of a fire even if you’re not home, smart cameras helping to catch a burglar or smart thermostats lowering your bills.
<p> </p>
Just because the IoT industry has left security behind, people with genuine security concerns shouldn’t have to miss out on the boons that IoT devices can offer. This report covers the process that has been undergone to develop a novel machine learning based intrusion detection system for IoT enabled homes. It has been made the intention of giving homeowners the ability to better monitor their IoT devices and be made aware of when potential infections or intrusions occur, hopefully dissuading some of the security concerns around IoT devices. 



### Built With

* [Python](https://www.python.org/)
* [Jupyter Notebooks](https://jupyter.org/)
* [Grafana](https://grafana.com/)
* [Scikit-Learn](https://scikit-learn.org/stable/)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- GETTING STARTED -->
# Installation Guide

## Database

### Installation

To be installed on the same system as the network collector is to be run and the host that’s running the Wi-Fi hotspot.

1.  Install PostgreSQL, follow instructions found at <https://www.postgresqltutorial.com/postgresql-getting-started/install-postgresql/>
    1.  If you wish to use the host data collection, you’ll need to open port 5432 in the windows firewall to allow inbound connection. Instructions to do this can be found here.
    2.  [https://manifold.net/doc/mfd9/open_a_firewall_port_for_postgresql.htm\#:\~:text=Enter%205432%20and%20click%20Next,in%20the%20Install%20PostgreSQL%20topic](https://manifold.net/doc/mfd9/open_a_firewall_port_for_postgresql.htm#:~:text=Enter%205432%20and%20click%20Next,in%20the%20Install%20PostgreSQL%20topic)
2.  You will also have to edit the pg_hba and postgresql config file, instruction to do this can be found here.
    1.  <https://www.netiq.com/documentation/identity-manager-47/setup_windows/data/connecting-to-a-remote-postgresql-database.html>
3.  Now that Postgres is installed open the SQL shell that can be found via the windows search bar.
4.  You should be able to just press enter until it asks for a password, at this point enter the password you set when setting up PostgreSQL
5.  Now that you’re logged in type:
```
Create Database Pulse;
```
6.  This should complete successfully, and you should be able to do: \\c Pulse
7.  Now open another terminal and navigate to the directory where PostgreSQL is installed.
8.  In the terminal type, replacing \<Git Download Directory\> to wherever you downloaded the git repository:
```
Psql.exe -U postgres -d pulse -f '<Git Download Director>\FinalYearProject\Final Product\Database\pulse_20220427.sql'
```
9.  Make sure that the database uses the UTC time zone
10. The database should now be fully setup

## Host Collection Script – Additional Installation

### Prerequisites

All this must be installed on the raspberry pi device. This instillation only applies to Ubuntu.

-   Python 3.9
-   Pip
-   Relevant Libraries
    -   Vcgencmd (https://pypi.org/project/vcgencmd/)
    -   Psycopg2 (https://pypi.org/project/psycopg2/)
    -   Joblib (https://pypi.org/project/joblib/)
    -   Getmac (https://pypi.org/project/getmac/)
    -   Sklearn Version 1.0.1 (<https://pypi.org/project/scikit-learn/>)
    -   To install specific version of packages use == after the package name followed by the version number
        -   Pip install scikit-learn==1.0.1
        -   Alternatively, the requirements.txt can be used to install all the relevant libraries
        ```
        Pip install -r requirements.txt
        ```
1.  Installation
2.  Copy all the files in the host collector folder onto the raspberry pi and into the raspberry pi user’s home directory
3.  Change the values in the config files to display the correct database IP and the password for PostgreSQL
4.  Copy the .service file into /etc/systemd/system
5.  Edit this file and replace \<UserName\> with whatever the users name is
6.  Reload the service files to include the new service.
```
sudo systemctl daemon-reload
```
7.  Start the service
```
sudo systemctl start pulse.service
```
8.  Check the service is running
```
sudo systemctl status pulse.service
```
9.  Enable the service so that it restarts if the device reboots
```
sudo systemctl enable pulse.service
```

## Network Collection Script

### Prerequisites

All this must be installed on the same device as the database.

-   Database installed
-   Grafana Installed
-   NSSM downloaded and set up in paths
-   NetworkInterfacesView downloaded (<https://www.nirsoft.net/utils/network_interfaces.html>)
-   NMAP installed in default location (C:\\Program Files (x86)\\)

### Installation

1.  make sure all the settings in the config file are setup correctly
    1.  A Grafana API key can be made in the API Key tab in the configuration menu, copy this API key into the config file. Access Grafana by going to localhost:8080, the default username and password should be admin, admin
    2.  All the other settings should correspond to things that have already been setup
        1.  Under scan settings it is advised to set Enabled to true so that a full scan is performed on startup, otherwise only the IPs under DeviceIPs
        2.  The OUIs list can be added to if searching for specific devices, check the first 3 sections of the mac address of the device you wish to detect before adding new values here
    3.  The network interface should be whichever interface GUID is being used by the Wi-Fi hotspot. The easiest way to check your interfaces is using NetworkInterfacesView. It is most likely to be the only enabled Wi-FI Virtual Adapter
2.  With the config file setup open a terminal as an administrator
3.  Run the following command whilst in the same directory as to where NetworkMonitor.exe was downloaded to
```
nssm install PulseNetworkCollector
```
4.  When the UI opens select the NetworkMonitor.exe and click OK
5.  Run the following command to start the service
```
nssm add PulseNetworkCollector
```
6.  Run the following command to make sure the service restarts on boot
```
nssm set PulseNetworkCollector start SERVICE_AUTO_START
```
7.  Everything should now be setup go, your dashboards for any discovered devices should be there, keep in mind that it may take a while to startup if the script is having to scan the whole network





<!-- CONTACT -->
## Contact

James Woodland - [@ThatStatGuyZero](https://twitter.com/thatstatguyzero) - jameswoodland1712@hotmail.co.uk

Project Link: [https://github.com/James-Woodland/FinalYearProject](https://github.com/James-Woodland/FinalYearProject)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/james-woodland-0a03991967
[product-screenshot1]: Images/NetDataDash.png
[product-screenshot2]: Images/HostDataDash.png

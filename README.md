# Application Workspace Packaging Solution
This repo is to store my Application Workspace Inventory and Packaging Solution

This poject is a combination way to inventory existing software on machines and then use the Utility to enable those applications in your Application Workspace environment.

The first part of it is a script that gets deployed through Intune that will inventory the devices.
The second script will reach out and retrieve the data collected from above and then search your Application Workspace connector for potential matches within our catalog and then provide you the list of potential matches that you can then select and then it will add in those packages to your Application Workspace zone so that you can deliver to your end users.
![AWPackagingMainPage](https://github.com/user-attachments/assets/f4eceff9-0990-4057-bace-73c9b671619d)

![AWPackagingChoices](https://github.com/user-attachments/assets/3746afbc-4862-4b80-9d36-9a15815d91ad)

Here are screenshots of the Workbook that you can create.
![AWInstalledApplications1](https://github.com/user-attachments/assets/e5b9c53d-3a46-4884-a255-9c8162f6255f)
![AWInstalledApplications2](https://github.com/user-attachments/assets/446c9d01-e31e-4903-9abb-93c6428b3943)
![AWInstalledApplications3](https://github.com/user-attachments/assets/75713619-1c36-4e8f-94b3-5121adb1beec)
![AWInstalledApplications4](https://github.com/user-attachments/assets/871aea33-8c65-4a99-9600-6e15d4ab0685)

And here is an example of the Log Analytics table data and a sample KQL query.
![AWLogAnalytics](https://github.com/user-attachments/assets/59f2042c-7910-4f0e-a0fd-bafc12bf4cf5)

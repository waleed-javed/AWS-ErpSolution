# AWS-ErpSolution
<p align="center">
  <a href="https://github.com/waleed-javed/AWS-ErpSolution">
    <img src="https://imgix.datadoghq.com/img/solutions/aws-hero.png?ch=Width&fit=max&auto=compress&auto=format" alt="Logo">
  </a>
</p>

## PreReqs
- You will first require a S3 Bucket that has to be configures accordingly
- You will then be required to change the serverless template configurations as per your own needs
- The code will be deployed using the Cloud formation templating methodology
- Make sure you hook the _**PreTrafficHook**_ Rules and execution policies properly

# For Deploying the code

Use the following command in order to start the deployment protocol from your command line / console
> _Make sure your AWS toolkit is configured properly with your credentials_
``` 
dotnet lambda deploy-serverless -cfg aws-lambda-tools-{YOUR_REGION_HERE}.Json
```
> -CFG Flag indicates config file, which is in most cases your ```aws-lambda-tools-{YOUR_REGION_HERE}.Json``` file

# NOTE:

_*For Any Assistance Feel free to contact me !*_

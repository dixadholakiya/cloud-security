# Deploying the Antigravity Website to AWS EC2

This guide walks you through deploying your static website to your AWS EC2 instance at **13.51.44.23** using your keypair **mykeypair.pem**.

---

## Step 1: Set Private Key Permissions
On your local terminal, navigate to the folder where `mykeypair.pem` is stored and run:
```bash
chmod 400 mykeypair.pem
```

---

## Step 2: Upload Files to the EC2 Instance
Run this command from your local machine (where `mykeypair.pem` is located) to transfer the site assets folder:

### For Ubuntu Instances (Default):
```bash
scp -i "mykeypair.pem" -r /Users/user/antigravity-cloud ubuntu@13.51.44.23:/home/ubuntu/
```

### For Amazon Linux Instances (Alternative):
```bash
scp -i "mykeypair.pem" -r /Users/user/antigravity-cloud ec2-user@13.51.44.23:/home/ec2-user/
```

---

## Step 3: Install Nginx on the EC2 Instance
Connect to your EC2 instance via SSH:

### For Ubuntu:
```bash
ssh -i "mykeypair.pem" ubuntu@13.51.44.23
```
Then, install Nginx:
```bash
sudo apt update && sudo apt install nginx -y
sudo systemctl start nginx
sudo systemctl enable nginx
```

### For Amazon Linux:
```bash
ssh -i "mykeypair.pem" ec2-user@13.51.44.23
```
Then, install Nginx:
```bash
sudo dnf update -y
sudo dnf install nginx -y
sudo systemctl start nginx
sudo systemctl enable nginx
```

---

## Step 4: Move Uploaded Files to the Web Server Root
Once inside your SSH session, clean up the default web page and move the uploaded assets:

### For Ubuntu:
```bash
# Clean default page and copy your files to the web server directory
sudo rm -rf /var/www/html/*
sudo cp -r /home/ubuntu/antigravity-cloud/* /var/www/html/

# Set correct read permissions for Nginx
sudo chown -R www-data:www-data /var/www/html/
sudo chmod -R 755 /var/www/html/
```

### For Amazon Linux:
```bash
# Clean default page and copy your files to the web server directory
sudo rm -rf /var/www/html/*
sudo cp -r /home/ec2-user/antigravity-cloud/* /var/www/html/

# Set correct read permissions for Nginx
sudo chown -R nginx:nginx /var/www/html/
sudo chmod -R 755 /var/www/html/
```

---

## Step 5: Configure AWS Security Group
In your AWS EC2 Console, ensure that the **Security Group** attached to your instance allows inbound traffic:
1. **HTTP** on Port 80 from anywhere (`0.0.0.0/0`).
2. **SSH** on Port 22 from your IP address.

Once done, open a browser and go to `http://13.51.44.23` to view the live site!

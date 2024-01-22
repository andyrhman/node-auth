# Node Auth with Express server

<p align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d9/Node.js_logo.svg/300px-Node.js_logo.svg.png" />
</p>

## Introduction

Use the project for studying how authorization logic works, it will be useful in the future

### First Time Set Up & Configuration

Create the directory:

```bash
mkdir node-admin
npm init -y
```

Install some dependencies:

```bash
npm i -D typescript ts-node nodemon

### Ignore this if you have installed typescript globally

npm i -g typescript
```

Typescript configuration:

```bash
tsc --init
```

Create a file called `nodemon.json` and copy this code

```json
{
    "ignore": [
      ".git",
      "node_modules/",
      "dist/",
      "coverage/"
    ],
    "watch": [
      "src/*"
    ],
    "ext": "js,json,ts"
  }
```

## Features

List the main features of your autth server. For example:
- User authentication and authorization
- Auth Token
- 2FA Authentication

## Requirements

Outline the prerequisites and dependencies needed to run your admin server. For example:
- Node.js (version)
- npm or yarn
- Database (if applicable)

## Installation

Provide step-by-step instructions for installing and setting up the project locally. Include commands and any additional configurations. For example:

```bash
git clone https://github.com/andyrhman/node-auth.git
cd node-admin
npm install
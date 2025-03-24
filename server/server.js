const express = require('express');
const cors = require('cors');
const fs = require('fs');
const { exec } = require('child_process');
const path = require('path');
const multer = require('multer');
const { spawn } = require('child_process');
const bodyParser = require('body-parser');
const mongoose = require('./database');
const Protocol = require('./Protocol');
const { ConnectionPoolMonitoringEvent } = require('mongodb');


const app = express();
const port = 8383;

// Middleware
app.use(cors());
app.use(express.text());
app.use(express.json());
app.use(bodyParser.json());

const runPythonScript = (args = [], timeout = 30000*1000) => {
  return new Promise((resolve, reject) => {
      const python = spawn('python3', ['/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/predict_dpi.py', ...args]);
      // const python = spawn('python3', ['/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML4/try.py', ...args]);
      let output = '';
      let errorOutput = '';
      let isResolved = false;

      // const timer = setTimeout(() => {
      //     python.kill(); // Kill the process after the timeout
      //     if (!isResolved) {
      //         isResolved = true;
      //         reject('Process timed out');
      //     }
      // }, timeout);

      python.stdout.on('data', (data) => {
          output += data.toString();
      });

      python.stderr.on('data', (data) => {
          errorOutput += data.toString();
      });

      python.on('close', (code) => {
          //clearTimeout(timer);
          console.log(`Python script exited with code ${code}`);
          //code=code-1;
          if (!isResolved) {
              isResolved = true;
              if (code === 0) {
                  resolve(output);
              } else {
                  reject(errorOutput || `Process exited with code ${code}`);
              }
          }
      });
  });
};



// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Directory where files will be stored
  },
  filename: (req, file, cb) => {
    // Keep the original filename or modify as you see fit
    cb(null, file.originalname);
  },
});

// This will allow multiple files to be uploaded under the same field name "pcapFile"
const upload = multer({ storage: storage });

// Routes
// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the Node.js server!\n');
});

// Upload route for PCAP files (multiple files)
app.post('/upload', upload.array('pcapFile'), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ message: 'No files uploaded' });
  }

  req.files.forEach((file) => {
    console.log(`Received file: ${file.originalname}, saved to: ${file.path}`);
  });

  // You can perform additional processing here if needed

  res.status(200).json({
    message: 'Files uploaded successfully',
    files: req.files,
  });

  
});

// Route for receiving and processing text data
let serverOutput = 'X';

app.post('/data', async (req, res) => {
  try {
    const allData = (req.body).split(/\r?\n/);
    console.log(allData);
    const Protocolname = allData[0];
    const data = allData.slice(1).join('\n');
    console.log('Received text data:\n', data);

    // Write file using promisified version
    await fs.promises.writeFile('received_data.txt', data);
    console.log('Data saved to received_data.txt');

    // Combine PCAP files
    await new Promise((resolve, reject) => {
      exec('../runOfiles/combine_pcapng runfile.pcapng ../server/uploads',
        (error, stdout) => {
          if (error) reject(error);
          else {
            console.log('Combined the pcap files:', stdout);
            resolve();
          }
        }
      );
    });

    // Run main C file
    await new Promise((resolve, reject) => {
      exec('../runOfiles/main received_data.txt', (error) => {
        if (error) reject(error);
        else {
          console.log('Ran the C file');
          resolve();
        }
      });
    });

    // Run Python script
    console.log('Running ML Python script');
    const pythonArgs = ['/mnt/c/Users/aviv/Desktop/newProject/server/runfile.pcapng',Protocolname];
    //try{
    await runPythonScript(pythonArgs);
    // }catch(err){

    // }
    console.log('Python ML script finished');

    await new Promise((resolve, reject) => {
      exec('/usr/bin/python3 /mnt/c/Users/aviv/Desktop/newProject/pythonscripts/gen_diss.py', (error) => {
        if (error) reject(error);
        else {
          console.log('generated dissector files');
          resolve();
        }
      });
    });

    await new Promise((resolve, reject) => {
      exec('../runOfiles/clearTableAndUploads', (error) => {
        if (!error) reject(error);
        else {
          console.log('Cleared the table and uploads directory');
          resolve();
        }
      });
    });

    const dpiData = JSON.parse(fs.readFileSync('/mnt/c/Users/aviv/Desktop/newProject/server/dpi_output.json', 'utf8'));
    serverOutput = dpiData;

    

    return res.status(200).json({
      success: true,
      message: 'All processing completed successfully',
      //output: result
    });

  } catch (error) {
    console.error('Processing error:', error);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Route to fetch output
app.get('/output', (req, res) => {
  //func for read from txt file
    //console.log(serverOutput);
  //if (serverOutput !== 'X') {
   res.send(serverOutput.dpi);
 // }
  
});

// Route to download the dissector file
app.get('/download-dissector', (req, res) => {
  console.log(req.query);
  console.log('Downloading dissector file');
  if(req.query.ip == undefined){
    const filePath =
    '/mnt/c/Users/aviv/Desktop/newProject/server/my_protocol_dissector.lua';
  res.download(filePath, 'dissector.lua', (err) => {
    if (err) {
      console.error('Error downloading file:', err);
      res.status(500).send('Error downloading the file.');
    }
  });
  }
  else{
    // const ip = req.query['ip']
    // console.log(ip);
    if(req.query['ip']==='Global'){
      console.log('Global');
      const protocol = req.query['protocol'];
      let filePath = '/mnt/c/Users/aviv/Desktop/newProject/data/'+protocol+ '.lua';
      console.log(filePath);
      res.download(filePath, protocol+ '.lua', (err) => {
        if (err) {
          console.error('Error downloading file:', err);
          res.status(500).send('Error downloading the file.');
    }
    });
  }
  else{
    const ip = req.query['ip'].replace(/\./g, "_");
    const protocol = req.query['protocol'];
    let filePath = '/mnt/c/Users/aviv/Desktop/newProject/data/'+protocol+'_for_'+ip+ '.lua';
    console.log(filePath);
    res.download(filePath, protocol+'_for_'+ip+ '.lua', (err) => {
      if (err) {
        console.error('Error downloading file:', err);
        res.status(500).send('Error downloading the file.');
  }
}
  );}
  }

  
});

app.post('/save-protocol', async (req, res) => {
    try {
        const { name, fields, files, dpi } = req.body;
        //console.log('Saving protocol:', name, fields, files, dpi);

        // המרת מבנה ה-DPI למערך של אובייקטים
        const dpiArray = Object.entries(dpi).map(([ip, data]) => ({
            ip,
            fields: data
        }));

        const newProtocol = new Protocol({
            name,
            fields,
            files,
            dpi: dpiArray
        });

        // console.log('Saving protocol:', newProtocol);

        await newProtocol.save();

        res.status(201).json({
            message: 'Protocol saved successfully',
            data: newProtocol
        });

    } catch (error) {
        console.error('Error saving protocol:', error);
        res.status(500).json({ message: 'Error saving protocol', error });
    }
});

app.get('/get-protocols', async (req, res) => {
    try {
        const protocols = await Protocol.find();
        res.status(200).json(protocols);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving protocols', error });
    }
});

app.get('/get-names', async (req, res) => {
    try {
        const protocols = await Protocol.find({}, 'name');
        res.status(200).json(protocols.map(p => p.name));
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving protocol names', error });
    }
});

app.get('/get-protocol', async (req, res) => {
    console.log('get-protocol');
    try {
        //console.log(req.query);
        let name = req.query.name;
        // let tmp = JSON.stringify(name.name);
       
        console.log(name);
       
        const protocol = await Protocol.findOne({
            name
        });
        res.status(200).json(protocol);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving protocol', error });
    }
});
app.delete('/delete-protocol', async (req, res) => {
  console.log('delete-protocol');
    try {
      console.log(req.query);
        const name = req.query.name;
        await Protocol.deleteOne({ name });

        res.status(200).json({ message: 'Protocol deleted successfully ' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting protocol', error });
    }
});
app.get('/test', (_, res) => {
  console.log('test');
   //new Promise((resolve, reject) => {
    exec('../runOfiles/clearTableAndUploads', (error) => {
      if (error) {console.log(error);}
      else {
        console.log('Cleared the table and uploads directory');
        //resolve();
      }
    });
  //});
  console.log('test finished');
  res.send('test');
});
// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
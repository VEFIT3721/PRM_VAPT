const OracleDB = require("oracledb");
const express = require("express");
require("dotenv").config();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const cors = require("cors");
const exceljs = require("exceljs");
const nodemailer = require("nodemailer");
const jwtSecret = "2ye7inClD1";
const jwt = require("jsonwebtoken");
const moment = require("moment-timezone");
const multer = require("multer");
const crypto = require("crypto");

const app = express();
const port = 3000;
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  connectString: process.env.DB_CONNECT_STRING,
  poolMin: 10, // Minimum number of connections
  poolMax: 200, // Maximum number of connections
  poolTimeout: 120, // Maximum time in seconds to wait for a connection
  queueTimeout: 600000, // Increase timeout to 120 seconds
};


// Connect to Oracle database using connection pool
OracleDB.createPool(dbConfig, (err, pool) => {
  if (err) {
    console.error("Error connecting to Oracle database:", err);
    process.exit(1); // Exit on error
  }

  console.log("Connected to Oracle database");

  app.use(bodyParser.json());
  app.use(cors({ origin: "*" }));

  app.post("/api/register", async (req, res) => {
    const user = req.body;
    console.log("received data from frontend",user)
    let connection;

    try {
      connection = await pool.getConnection();
      if (!connection)
        throw new Error("Failed to acquire connection from pool");

      const saltRounds = 10;
      const salt = await bcrypt.genSalt(saltRounds);
      const hashedPassword = await bcrypt.hash(user.hashedPassword, salt);

      const sql = `
        INSERT INTO USER_MASTER (
          EmpCode, username, useremail, hashedPassword, user_roles,CREATEDBY
        ) VALUES (
          :EmpCode, :username, :useremail, :hashedPassword, :user_roles,:CREATEDBY
        )
      `;
      const binds = {
        EmpCode: user.EmpCode,
        username: user.username,
        hashedPassword,
        useremail: user.useremail,
        user_roles: user.user_roles,
        CREATEDBY: user.CREATED_BY // Use the exact field name from frontend (CREATED_BY)
      };
      console.log('Binds object:', binds);  // Debugging step

      const result = await connection.execute(sql, binds);
      await connection.commit();

      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      console.error("Error saving user:", error);
      res.status(500).json({ message: "Error saving user" });
    } finally {
      if (connection) {
        try {
          await connection.close();
        } catch (error) {
          console.error("Error closing connection", error);
        }
      }
    }
  });

    // Reset password API
    app.post("/api/reset-password", async (req, res) => {
      const { token, newPassword, Changed_By } = req.body;
      
      let connection;
      
      try {
        connection = await pool.getConnection();
        if (!connection) {
          throw new Error("Failed to acquire connection from pool");
        }
    
        // Step 1: Check if the reset token is valid and not expired
        const sql = `SELECT * FROM USER_MASTER WHERE reset_token = :resetToken`;
        const binds = { resetToken: token };
        const result = await connection.execute(sql, binds);
        
        if (result.rows.length === 0) {
          return res.status(400).json({ message: "Invalid or expired reset token" });
        }
    
        const user = result.rows[0];
        const empCode = user[0]; // Assuming EmpCode is the first column
        const currentPasswordHash = user[3]; // Assuming hashed password is at index 7
        let tokenExpiryDate = user[10]; // Assuming reset_token_expiry is at index 10
        if (!(tokenExpiryDate instanceof Date)) {
          tokenExpiryDate = new Date(tokenExpiryDate); // Convert to Date if necessary
        }
    
        if (isNaN(tokenExpiryDate.getTime())) {
          return res.status(400).json({ message: "Invalid token expiry date" });
        }
    
        if (tokenExpiryDate <= new Date()) {
          return res.status(400).json({ message: "Reset token has expired" });
        }
       
        // Step 2: Compare the new password with the current password
        const isSamePassword = await bcrypt.compare(newPassword, currentPasswordHash);
        if (isSamePassword) {
          return res.status(400).json({ message: "New password cannot be the same as the old password" });
        }
    
        // Step 3: Hash the new password
        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
    
        // Step 4: Update the password and clear reset token
        const updateSql = `
          UPDATE USER_MASTER
          SET HASHEDPASSWORD = :hashedPassword,
              reset_token = NULL,
              reset_token_expiry = NULL,
              MODIFIEDTIME = CURRENT_TIMESTAMP,
              MODIFIEDBY = :Changed_By
          WHERE reset_token = :resetToken
        `;
        const updateBinds = { hashedPassword, resetToken: token, Changed_By: empCode }; // EmpCode as Changed_By
        const updateResult = await connection.execute(updateSql, updateBinds);
    
        if (updateResult.rowsAffected === 0) {
          return res.status(400).json({ message: "User not found or no changes made" });
        }
    
        await connection.commit(); // Commit the changes
        res.status(200).json({ message: "Password reset successful" });
      } catch (error) {
        console.error("Error resetting password:", error);
        res.status(500).json({ message: "Internal Server Error" });
      } finally {
        if (connection) {
          try {
            await connection.close();
          } catch (error) {
            console.error("Error closing connection", error);
          }
        }
      }
    });
  
    // API route to handle forgot password request
    app.post("/api/forgot-password", async (req, res) => {
      const { email } = req.body;
  
      let connection;
      try {
        connection = await pool.getConnection();
        if (!connection) {
          throw new Error("Failed to acquire connection from pool");
        }
  
        // Step 1: Check if the email exists in the database
        const sql = `SELECT * FROM USER_MASTER WHERE USEREMAIL = :useremail`;
        const binds = { useremail: email };
        const result = await connection.execute(sql, binds);
  
        if (result.rows.length === 0) {
          return res.status(404).json({ message: "Email not found" });
        }
  
        const user = result.rows[0];
        const empCode = user[0];
  
        // Step 2: Generate the reset token and its expiry time
        const resetToken = crypto.randomBytes(32).toString("hex");
        const resetTokenExpiry = new Date(Date.now() + 3600000); // Token expires in 2 minutes
  
        // Step 3: Store the reset token and expiry time in the database
        const updateSql = `UPDATE USER_MASTER SET reset_token = :resetToken, reset_token_expiry = :resetTokenExpiry WHERE USEREMAIL = :useremail`;
        const updateBinds = { resetToken, resetTokenExpiry, useremail: email };
        await connection.execute(updateSql, updateBinds);
        await connection.commit();
  
        // Step 4: Create the reset password link
        const resetLink = `https://vef.manappuram.com/reset-password?token=${resetToken}`;
  
        // Step 5: Compose the reset password email contentclear
        const emailContent = `
        Hi,
  
        You requested a password reset. Please click the link below to reset your password:
  
        ${resetLink}
  
        This link will expire in 1 hour. If you did not request a password reset, please ignore this email.
  
        If you have any questions, feel free to contact our support team.
  
        Thanks & Regards,
        [Your VEF IT Team]
  
        *** This email was auto-generated. Please do not reply to this email. ***
      `;
  
        // Step 6: Send the reset password email
        await transporter.sendMail({
          from: "vefitrpa@manappuram.com", // Your email address
          to: email,
          subject: "Password Reset Request",
          text: emailContent,
        });
  
        // Step 7: Send response to the client
        res.json({ message: "Password reset link has been sent to your email." });
      } catch (error) {
        console.error("Error sending password reset email:", error);
        res.status(500).json({ message: "Error sending password reset email" });
      } finally {
        if (connection) {
          try {
            await connection.close();
          } catch (error) {
            console.error("Error closing connection", error);
          }
        }
      }
    });

    
  app.post("/api/login", async (req, res) => {
    const { EmpCode, password } = req.body;
    let connection;

    try {
      connection = await pool.getConnection();
      const sql = `SELECT * FROM USER_MASTER WHERE EMPCODE = :EmpCode`;
      const result = await connection.execute(sql, { EmpCode });

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const EmpCode = user[0];
        const hashedPassword = user[3];
        const role = user[4];
        const username = user[1];

        const isMatch = await bcrypt.compare(password, hashedPassword);
        if (isMatch) {
          const payload = { EmpCode, role, username };
          const token = await jwt.sign(payload, jwtSecret, { expiresIn: "1h" });
          res.json({ message: "Login successful", token });
        } else {
          res.status(401).json({ message: "Invalid username or password" });
        }
      } else {
        res.status(404).json({ message: "User not found" });
      }
    } catch (error) {
      console.error("Error processing login:", error);
      res.status(500).json({ message: "Internal server error" });
    } finally {
      if (connection) {
        try {
          await connection.close();
        } catch (error) {
          console.error("Error closing connection", error);
        }
      }
    }
  });

  app.post("/api/save-meeting", async (req, res) => {
    const meetingData = req.body;
    let connection;

    try {
      connection = await pool.getConnection();
      const sql = `
        INSERT INTO MEETING_MASTER (
          MEETINGID, EMAIL_ID, ConductedDate, VerticalName, ConductedPerson,
          department, DeptHod, EmpCode, ActionPoint, TargetDate, MisCordinator,
          User_Remark,MIS_STATUS,MIS_EMAIL,createdBy
        ) VALUES (
          meeting_id_seq.NEXTVAL, :EMAIL_ID, TO_DATE(:ConductedDate, 'YYYY-MM-DD'),
          :VerticalName, :ConductedPerson, :department, :DeptHod, :EmpCode,
          :ActionPoint, TO_DATE(:TargetDate, 'YYYY-MM-DD'), :MisCordinator,
          :User_Remark, :MIS_STATUS, :MIS_EMAIL,:createdBy
        ) RETURNING MEETINGID INTO :meetingId
      `;
      const binds = {
        EMAIL_ID: meetingData.EMAIL_ID,
        ConductedDate: meetingData.ConductedDate,
        VerticalName: meetingData.VerticalName,
        ConductedPerson: meetingData.ConductedPerson,
        department: meetingData.department,
        DeptHod: meetingData.DeptHod,
        EmpCode: meetingData.EmpCode,
        ActionPoint: meetingData.ActionPoint,
        TargetDate: meetingData.TargetDate,
        MisCordinator: meetingData.MisCordinator,
        User_Remark: meetingData.User_Remark,
        MIS_STATUS:meetingData.MIS_STATUS,
        MIS_EMAIL:meetingData.MIS_EMAIL,
        createdBy: meetingData.CREATED_BY,
        meetingId: { type: OracleDB.OUT, dir: OracleDB.BIND_OUT },
      };

      const result = await connection.execute(sql, binds);
      await connection.commit();

      const meetingId = result.outBinds.meetingId[0];
      res
        .status(201)
        .json({ message: "Meeting data saved successfully", meetingId });
    } catch (error) {
      console.error("Error saving meeting data:", error);
      res.status(500).json({ message: "Error saving meeting data" });
    } finally {
      if (connection) {
        try {
          await connection.close();
        } catch (error) {
          console.error("Error closing connection", error);
        }
      }
    }
  });

  app.get("/api/get-meeting-by-id/:MeetingId", async (req, res) => {
    const meetingId = req.params.MeetingId;
    const decodedToken = jwt.verify(
      req.headers.authorization.split(" ")[1],
      jwtSecret
    );
    let connection;
    try {
      const connection = await pool.getConnection();
      const sql = `SELECT * FROM MEETING_MASTER WHERE MEETINGID = :meetingID`;
      const binds = {
        MeetingID: meetingId,
      };
      const result = await connection.execute(sql, { meetingID: meetingId });

      if (result.rows.length > 0) {
        const meeting = result.rows[0];
        if (decodedToken.role === "USER" || decodedToken.role === "CHECKER")
         {
          res.status(200).json(meeting);
        } else {
          res.status(401).json({ message: "Unauthorized access" });
        }
      
      } else {
        res.status(404).json({ message: "Meeting not found" });
      }
    } catch (error) {
      console.error("Error fetching meeting data:", error);
      res.status(500).json({ message: "Error fetching meeting data" });
    } finally {
      if (connection) {
        try {
          await connection.close();
        } catch (error) {
          console.error("Error closing connection", error);
        }
      }
    }
  });

  const roleMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized access" });
    }

    const token = authHeader.split(" ")[1];
    try {
      const decodedToken = jwt.verify(token, jwtSecret);
      if (decodedToken.role !== "USER" && decodedToken.role !== "CHECKER") {
        return res
          .status(403)
          .json({ message: "Forbidden: Insufficient permissions" });
      }
      req.user = decodedToken;
      next();
    } catch (error) {
      console.error("Error verifying token:", error);
      res.status(401).json({ message: "Unauthorized access" });
    }
  };
  
// UPDATE USER REMARK INCLUDING MAILALERT TO MIS ENDPOINT
 app.put(
  "/api/meetings/:meetingId/remark",
  roleMiddleware,
  upload.single("file"),
  async (req, res) => {
    const meetingId = req.params.meetingId;
    const { remark } = req.body;
    const file = req.file;
    let connection;

    try {
      connection = await pool.getConnection();

      // Update meeting remark
      const updateQuery = `
        UPDATE MEETING_MASTER
        SET User_Remark = :remark
        WHERE MEETINGID = :meetingId
      `;
      const binds = { remark, meetingId };
      const result = await connection.execute(updateQuery, binds);

      // Handle file upload
      if (file) {
        const fileBuffer = file.buffer; // Buffer from memory storage
        const fileType = file.mimetype;
        const fileName = file.originalname;

        const insertFileQuery = `
          INSERT INTO MEETING_FILES (MEETINGID, FILE_NAME, FILE_TYPE, FILE_DATA)
          VALUES (:meetingId, :fileName, :fileType, :fileData)
        `;
        const fileBinds = {
          meetingId,
          fileName,
          fileType,
          fileData: fileBuffer,
        };
        await connection.execute(insertFileQuery, fileBinds);
      }

      await connection.commit();

      // Check if the remark is "Resolved"
      if (remark.toLowerCase() === "resolved") {
        // Query to get the MIS user's email
        const misEmailResult = await connection.execute(
          `SELECT "MIS_EMAIL" FROM MEETING_MASTER WHERE MEETINGID = :meetingId`,
          { meetingId }
          
        );
        console.log("Received meeting id:", meetingId);
        console.log("MIS_EMAIL query result:", misEmailResult.rows);

        if (misEmailResult.rows && misEmailResult.rows.length > 0) {
          const misEmail = misEmailResult.rows[0][0];
          console.log("Received MIS email:", misEmail);

          // If a valid MIS email is found, send an email to the MIS user
          if (misEmail && misEmail.trim() !== "") {
            // Nodemailer configuration
            const transporter = nodemailer.createTransport({
              host: "smtp.office365.com",
              port: 587,
              secure: false,
              auth: {
                user: "vefitrpa@manappuram.com", // Your email
                pass: "WSXasd@1234", // Your email password
              },
            });

            const mailOptions = {
              from: '"Meeting Manager" <vefitrpa@manappuram.com>',
              to: misEmail, // MIS Coordinator's email
              subject: `Meeting ID ${meetingId} Status Updated to Resolved`,
              text: `The status for Meeting ID ${meetingId} has been updated to "Resolved" by the user. Kindly check it from your end and also update your remark to avoid any delay.`,
              html: `<p>The status for <strong>Meeting ID ${meetingId}</strong> has been updated to <strong>"Resolved"</strong> by the user.</p>
                     <p>Kindly check it from your end and also update your remark to avoid any delay.</p>

                      Thanks & Regards,
                      [ VEF IT Team]
                     <p>
                     <strong style="color:#FF0000:>*** This email was auto-generated. Please do not reply to this email. ***
                     </p>`,
            };

            transporter.sendMail(mailOptions, (err, info) => {
              if (err) {
                console.error("Error sending email:", err);
              } else {
                console.log("Email sent:", info.response);
              }
            });
          } else {
            console.log("No valid recipient email address found.");
          }
        } else {
          console.log("No MIS email found for the given meeting ID");
        }
      }

      if (result.rowsAffected === 1) {
        res.status(200).json({ message: "Meeting status updated successfully" });
      } else {
        res.status(400).json({ message: "Meeting update failed (no rows affected)" });
      }
    } catch (error) {
      console.error("Error updating meeting:", error);
      res.status(500).json({ message: "Error updating meeting" });
    } finally {
      if (connection) {
        try {
          await connection.close();
        } catch (error) {
          console.error("Error closing connection", error);
        }
      }
    }
  }
);
 // updated end pont for user reamrk avoid duplicate files upload
//  app.put(
//   "/api/meetings/:meetingId/remark",
//   roleMiddleware,
//   upload.single("file"),
//   async (req, res) => {
//     const meetingId = req.params.meetingId;
//     const { remark } = req.body;
//     const file = req.file;
//     let connection;

//     try {
//       connection = await pool.getConnection();

//       // Prevent file upload if status is Resolved or Rejected
//       const statusQuery = `
//         SELECT User_Remark FROM MEETING_MASTER WHERE MEETINGID = :meetingId
//       `;
//       const [statusResult] = await connection.execute(statusQuery, { meetingId });
//       const currentRemark = statusResult?.User_Remark;

//       if (currentRemark === 'Resolved' || currentRemark === 'Rejected') {
//         return res.status(400).send('Cannot upload files. Status is Resolved or Rejected.');
//       }

//       // Prevent multiple files for the same meeting ID
//       const fileCheckQuery = `
//         SELECT COUNT(*) AS fileCount FROM MEETING_FILES WHERE MEETINGID = :meetingId
//       `;
//       const [fileCheckResult] = await connection.execute(fileCheckQuery, { meetingId });

//       if (fileCheckResult.fileCount > 0) {
//         return res.status(400).send('A file already exists for this meeting ID.');
//       }

//       // Update meeting remark
//       const updateQuery = `
//         UPDATE MEETING_MASTER
//         SET User_Remark = :remark
//         WHERE MEETINGID = :meetingId
//       `;
//       await connection.execute(updateQuery, { remark, meetingId });

//       // Handle file upload
//       if (file) {
//         const fileBuffer = file.buffer; // Buffer from memory storage
//         const fileType = file.mimetype;
//         const fileName = file.originalname;

//         const insertFileQuery = `
//           INSERT INTO MEETING_FILES (MEETINGID, FILE_NAME, FILE_TYPE, FILE_DATA)
//           VALUES (:meetingId, :fileName, :fileType, :fileData)
//         `;
//         await connection.execute(insertFileQuery, {
//           meetingId,
//           fileName,
//           fileType,
//           fileData: fileBuffer,
//         });
//       }

//       await connection.commit();
//       res.status(200).send('Remark and file updated successfully.');
//     } catch (err) {
//       console.error('Error updating meeting remark:', err);
//       res.status(500).send('Internal server error.');
//     } finally {
//       if (connection) connection.release();
//     }
//   }
// );


  //fetche file api
  
  app.get('/api/get-files-by-meeting-id/:meetingId', async (req, res) => {
    const meetingId = req.params.meetingId;
  let connection;

  try {
    connection = await pool.getConnection();

    const query = `
    SELECT FILE_ID, FILE_NAME, FILE_TYPE, FILE_DATA 
    FROM MEETING_FILES 
    WHERE MEETINGID = :meetingId
    `;
    const result = await connection.execute(query, { meetingId }, {
      outFormat: OracleDB.OUT_FORMAT_OBJECT,
      fetchInfo: {
        "FILE_DATA": { type: OracleDB.BUFFER }
      }
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No files found for this meeting ID.' });
    }
    const baseUrl = 'https://vef.manappuram.com'; 
    const files = result.rows.map(file => ({
      fileId: file.FILE_ID,
      fileName: file.FILE_NAME,
      fileType: file.FILE_TYPE,
      fileUrl: `/api/file/${file.FILE_ID}`  // A separate URL for the file download/preview
    }));

    res.json(files);  // Return file metadata as JSON
  } catch (error) {
    console.error('Error fetching files:', error);
    res.status(500).send('Error fetching files');
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error('Error closing connection', error);
      }
    }
  }
});

// preview fetched files
app.get('/api/file/:fileId', async (req, res) => {
  const fileId = req.params.fileId;
  let connection;

  try {
    connection = await pool.getConnection();

    const query = `
    SELECT FILE_NAME, FILE_TYPE, FILE_DATA 
    FROM MEETING_FILES 
    WHERE FILE_ID = :fileId
    `;
    const result = await connection.execute(query, { fileId }, {
      outFormat: OracleDB.OUT_FORMAT_OBJECT,
      fetchInfo: {
        "FILE_DATA": { type: OracleDB.BUFFER }
      }
    });

    if (result.rows.length === 0) {
      return res.status(404).send('File not found');
    }

    const file = result.rows[0];
    const fileData = file.FILE_DATA;

    // Set headers for the file
    res.setHeader('Content-Type', file.FILE_TYPE);
    res.setHeader('Content-Disposition', `inline; filename="${file.FILE_NAME}"`);

    // Send the file data as a Blob
    res.send(fileData);
  } catch (error) {
    console.error('Error fetching file:', error);
    res.status(500).send('Error fetching file');
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error('Error closing connection', error);
      }
    }
  }
});

  //Fetch Employee Details API
  app.get("/api/employees/:empCode", async (req, res) => {
    const empCode = req.params.empCode;
    let connection;

    try {
      connection = await pool.getConnection();

      const sql = `SELECT DeptHod, department,VerticalName,MisCordinator,ConductedPerson,EMAIL_ID ,MIS_EMAIL FROM prm_master WHERE emp_code = :empCode`;
      const binds = { empCode };

      const result = await connection.execute(sql, binds);

      if (result.rows.length === 0) {
        res.status(404).send({ message: "Employee not found" });
      } else {
        const employee = result.rows[0];
        res.json(employee);
      }

      await connection.close();
    } catch (error) {
      console.error("Error fetching employee details:", error);
      res.status(500).send({ message: "Internal Server Error" });
    }
  });

  const transporter = nodemailer.createTransport({
    host: "smtp.office365.com", // Replace with your email provider's SMTP host
    port: 587, // Replace with your email provider's SMTP port
    secure: false, // Adjust based on your SMTP server configuration
    auth: {
      user: "vefitrpa@manappuram.com", // Replace with your email address
      pass: "WSXasd@1234", // Replace with your email password
    },
  });
  // API endpoint to handle meeting details and send email
  app.post("/api/send-meeting-email", async (req, res) => {
    try {
      const { meetingId, recipientEmail, DeptHod } = req.body;
      console.log(
        "received meeting_id:",
        meetingId,
        "received mail:",
        recipientEmail
      );

      // Validate required fields
      if (!meetingId || !recipientEmail) {
        return res.status(400).json({
          message: "Missing required fields: meetingId and employeeCode",
        });
      }

      // Validate email address

      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

      if (!emailRegex.test(recipientEmail)) {
        return res
          .status(400)
          .json({ message: "Invalid recipient email address" });
      }

      // Compose the email content
      const emailContent = `
      Hi ${DeptHod},

      This email confirms that your meeting actionable points have been saved successfully.

      Meeting ID: ${meetingId}

       You can access the meeting details through your meeting management system.
     
      Internal Meeting System link to access - https://vef.manappuram.com

      If you are the first time user, kindly collect the credentails from MIS Team.

    
      Thanks & Regards,
      [VEF - IT Team]

    *** This email has been auto-generated. Kindly don't reply on this. If you need assistance or have any query, please reach out to MIS Team.
    `;

      // Send the email
      await transporter.sendMail({
        from: "vefitrpa@manappuram.com", // Replace with your email address
        to: recipientEmail,
        subject: "Actionable Point-ID: " + meetingId,
        text: emailContent,
      });

      res.json({ message: "Meeting email sent successfully!" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error sending meeting email" });
    }
  });

  // Get pending ATR details API route
  app.get("/api/pending-atr-details", async (req, res) => {
    const searchTerm = req.query.searchTerm;

    let connection;
    try {
      connection = await pool.getConnection();

      const sql = `
         
select "VERTICALNAME","EMPCODE",SUM(EXTRACT(DAY FROM TARGETDATE - CONDUCTEDDATE)) AS "DELAY_DAYS" FROM MEETING_MASTER
where REMARK = 'in-progress'
AND EMPCODE= :searchTerm
GROUP BY "VERTICALNAME","EMPCODE"
`;

      const binds = {
        searchTerm,
      };

      const result = await connection.execute(sql, binds);
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching pending ATR details:", error);
      res.status(500).json({ message: "Error fetching pending ATR details" });
    } finally {
      if (connection) {
        try {
          await connection.close();
        } catch (error) {
          console.error("Error closing connection", error);
        }
      }
    }
  });

  // NEW EXPORT EXCEL API ENDPOINT
  app.get("/api/export-excel", async (req, res) => {
    const { fromDate, toDate } = req.query;
    console.log("received date:", fromDate, "to date:", toDate);

    let connection;

    try {
      const connection = await pool.getConnection();
      const sql = `SELECT * FROM MEETING_MASTER WHERE CONDUCTEDDATE BETWEEN TO_DATE(:fromDate, 'YYYY-MM-DD') AND TO_DATE(:toDate, 'YYYY-MM-DD')`;
      const result = await connection.execute(sql, {
        fromDate,
        toDate,
      });
      const meetingData = result.rows;
      console.log("meeting data:", result.rows);

      // Convert dates to the desired format

      meetingData.forEach((row) => {
        row[1] = moment(row[1]).tz("Asia/Kolkata").format("YYYY-MM-DD");

        row[8] = moment(row[8]).tz("Asia/Kolkata").format("YYYY-MM-DD");
      });

      // Generate Excel file using exceljs
      const workbook = new exceljs.Workbook();
      const worksheet = workbook.addWorksheet("Meetings");

      // Add headers
      worksheet.addRow([
        "MEETINGID",
        "ConductedDate",
        "VerticalName",
        "ConductedPerson",
        "department",
        "DeptHod",
        "EmpCode",
        "ActionPoint",
        "TargetDate",
        "MisCordinator",
        "User_Remark",
        "CREATEDDATE",
        "UPDATEDTIME",
        "EMAIL_ID",
        "CREATEDBY",
        "UPDATEDBY",
        "MIS_STATUS",
        "MIS_EMAIL"
      ]);

      // Add meeting data to rows

      meetingData.forEach((row) => {
        worksheet.addRow(row);
      });
      //  Create a buffer to hold the Excel file
      const buffer = await workbook.xlsx.writeBuffer();

      // Send the exported Excel file as a response
      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        "attachment; filename=meetings.xlsx"
      );
      res.send(buffer);
    } catch (error) {
      console.error("Error exporting data:", error);
      res.status(500).json({ message: "Error exporting data" });
    } finally {
      if (connection) {
        try {
          await connection.close();
        } catch (error) {
          console.error("Error closing connection", error);
        }
      }
    }
  });
//MIS REMARK UPDATE
  app.put("/api/meetings/:meetingId/misRemark", async (req, res) => {
    const meetingId = req.params.meetingId;
    const updatedRemark = req.body.MIS_STATUS;
    const updatedBy = req.body.updatedBy;
    let connection;
  try {
    connection = await pool.getConnection();
    const updateQuery = `
        UPDATE MEETING_MASTER
        SET MIS_STATUS = :updatedRemark , UPDATEDBY = :updatedBy
        WHERE MEETINGID = :meetingId
      `;
    const binds = {
      meetingId: { val: meetingId },
      updatedRemark: { val: updatedRemark },
      updatedBy: { val: updatedBy },
      
    };
    console.log('Received Binds:',binds)

    const result = await connection.execute(updateQuery, binds);
    await connection.commit();

    if (result.rowsAffected === 1) {
      res.status(200).json({
        message: "Meeting status updated successfully",
        updatedBy: updatedBy,
      });
    } else {
      res
        .status(400)
        .json({ message: "Meeting update failed (no rows affected)" });
    }
  } catch (error) {
    console.error("Error updating meeting status:", error);
    res.status(500).json({ message: "Error updating meeting status" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection", error);
      }
    }
  }
});

  // Endpoint to fetch delay data
app.get('/api/delays', async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const query = (`
      SELECT 
        "DEPTHOD" AS USER_NAME,
        "DEPARTMENT" AS DEPARTMENT,
        SUM(CASE WHEN "USER_REMARK" = 'in-progress' THEN 1 ELSE 0 END) AS Inprogress,
        COUNT("USER_REMARK") AS TOTAL_DELAYS,
        ROUND(MAX(SYSDATE - TO_DATE("TARGETDATE"))) AS DELAY_DAYS
      FROM MEETING_MASTER
      WHERE "TARGETDATE" IS NOT NULL
        AND "USER_REMARK" = 'in-progress'
      GROUP BY "DEPTHOD", "DEPARTMENT"
    `);
    const result = await connection.execute(query)

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error fetching data');
  }
});
app.post("/api/user-master",async(req,res) => {
const userData = req.body;
let connection;
try{
  connection =await pool.getConnection();
  const sql =`
  INSERT INTO PRM_MASTER(
  EMP_CODE,DEPTHOD,DEPARTMENT,VERTICALNAME,CONDUCTEDPERSON,MISCORDINATOR,EMAIL_ID,MIS_EMAIL
  )VALUES(
  :EMP_CODE,:DEPTHOD,:DEPARTMENT,:VERTICALNAME,:CONDUCTEDPERSON,:MISCORDINATOR,:EMAIL_ID,:MIS_EMAIL
  )
  `;
  const binds = {
    EMP_CODE:  userData.EMP_CODE,
    DEPTHOD: userData.DEPTHOD,
    DEPARTMENT: userData.DEPARTMENT,
    VERTICALNAME:userData.VERTICALNAME,
    CONDUCTEDPERSON:userData.CONDUCTEDPERSON,
    MISCORDINATOR:userData.MISCORDINATOR,
    EMAIL_ID:userData.EMAIL_ID,
    MIS_EMAIL:userData.MIS_EMAIL


  };
  const result = await connection.execute(sql,binds);
  await connection.commit();
  res.status(201).json({message:"User data saved successfully"});
} catch(error){
  console.error("Error saving meeting data:",error);
  res.status(500).json({message:"Error saving Meeting data"});
}finally{
  if(connection){
    try{
      await connection.close();
    }catch(error){
      console.error("Error closing the connection",error);
    }
  }
}
});

  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});
